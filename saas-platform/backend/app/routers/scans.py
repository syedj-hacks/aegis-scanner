from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from .. import aegis_bridge, models, schemas, tiers
from ..database import SessionLocal, get_db
from ..deps import ensure_period_reset, get_current_user

router = APIRouter(prefix="/scans", tags=["scans"])


@router.get("/profiles", response_model=list[schemas.ProfileInfo])
def list_profiles(user: models.User = Depends(get_current_user)):
    """
    Every profile is always returned to every account (per the brief: never
    hide feature existence). `locked` tells the frontend whether to show a
    lock icon + upgrade tooltip instead of a Scan button.
    """
    tier = user.subscription.tier
    allowed = tiers.profiles_for_tier(tier)
    out = []
    for name in aegis_bridge.ALL_AEGIS_PROFILES:
        out.append(
            schemas.ProfileInfo(
                name=name,
                description=aegis_bridge.PROFILE_DESCRIPTIONS.get(name, ""),
                locked=name not in allowed,
                requires_authorization=name in tiers.CONDITIONAL_TOOLS_REQUIRE_AUTHORIZATION,
            )
        )
    return out


def _run_scan_job(job_id: int, auth_header: str, auth_cookie: str):
    """
    Executed in Starlette's threadpool (BackgroundTasks runs sync callables
    off the event loop automatically), so this blocking call into Aegis never
    stalls other requests. A dedicated Celery worker is the production-grade
    version of this queue; BackgroundTasks is used here to keep the student
    project's setup to one process — see docs/ARCHITECTURE.md for the tradeoff.

    Opens its own DB session because the request-scoped session used to
    create the job is already closed by the time this runs.
    """
    db = SessionLocal()
    try:
        job = db.query(models.ScanJob).get(job_id)
        if job is None:
            return
        job.status = models.JobStatus.running
        job.started_at = datetime.utcnow()
        db.commit()

        try:
            auth = aegis_bridge.build_auth_config(cookie=auth_cookie, header=auth_header)
            scan_id, txt_path, pdf_path, html_path, _stats = aegis_bridge.run_profile_sync(
                job.profile, job.target, auth=auth
            )
            job.aegis_scan_id = scan_id
            job.txt_report_path = txt_path
            job.pdf_report_path = pdf_path
            job.html_report_path = html_path
            job.status = models.JobStatus.done
        except Exception as exc:  # Aegis itself never raises, but stay defensive
            job.status = models.JobStatus.failed
            job.error = str(exc)
        job.finished_at = datetime.utcnow()
        db.commit()
    finally:
        db.close()


@router.post("/submit", response_model=schemas.ScanJobOut)
def submit_scan(
    body: schemas.ScanSubmitRequest,
    background_tasks: BackgroundTasks,
    request: Request,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    sub = user.subscription
    ensure_period_reset(sub, db)
    tier = sub.tier

    # 1. Profile gate — re-checked server-side regardless of what the UI showed.
    if not tiers.can_run_profile(tier, body.profile):
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"Profile '{body.profile}' is not available on your tier")

    # 2. Quota gate.
    limit = tiers.scan_limit_for_tier(tier)
    if limit is not None and sub.scans_used_this_period >= limit:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Monthly scan quota exhausted for your tier")

    # 3. Parallel-scan gate.
    active = (
        db.query(models.ScanJob)
        .filter(
            models.ScanJob.user_id == user.id,
            models.ScanJob.status.in_([models.JobStatus.queued, models.JobStatus.running]),
        )
        .count()
    )
    if active >= tiers.max_parallel_for_tier(tier):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Too many scans already in progress for your tier")

    # 4. Custom-config gate: Free gets no auth customization, Pro gets
    # header/cookie only, Enterprise gets full (still just header/cookie here
    # since that's all Aegis's AuthConfig models today).
    custom_level = tiers.CUSTOM_CONFIG_ALLOWED[tier]
    if custom_level == "none" and (body.auth_header or body.auth_cookie):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Custom auth config requires Pro or Enterprise")

    # 5. Conditional/intrusive-tools hard gate. deepscan is the only profile
    # that can dispatch wpscan/sqlmap/hydra/enum4linux (see aegis_bridge /
    # CONDITIONAL_TOOLS), and it must never run without the explicit,
    # logged authorization checkbox — this is enforced here, in the service
    # layer, not only hidden behind a UI condition.
    if body.profile in tiers.CONDITIONAL_TOOLS_REQUIRE_AUTHORIZATION:
        if tier != models.Tier.enterprise:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "This profile requires an Enterprise subscription")
        if not body.authorized_intrusive:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "This profile can run intrusive tools (wpscan/sqlmap/hydra/enum4linux) against the "
                "target. You must confirm you own or are authorized to test it.",
            )

    # 6. Target validation — reuse Aegis's own validator, never trust raw input.
    try:
        clean_target = aegis_bridge.validate_and_normalize_target(body.target)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))

    job = models.ScanJob(
        user_id=user.id,
        target=clean_target,
        profile=body.profile,
        status=models.JobStatus.queued,
    )
    if body.profile in tiers.CONDITIONAL_TOOLS_REQUIRE_AUTHORIZATION and body.authorized_intrusive:
        # Logged with timestamp + IP per the brief, since this authorization
        # gates running intrusive tools (wpscan/sqlmap/hydra/enum4linux)
        # against a third-party target.
        job.authorized_intrusive = True
        job.authorized_at = datetime.utcnow()
        job.authorized_ip = request.client.host if request.client else None

    db.add(job)
    sub.scans_used_this_period += 1
    db.add(sub)
    db.commit()
    db.refresh(job)

    background_tasks.add_task(_run_scan_job, job.id, body.auth_header, body.auth_cookie)
    return job


@router.get("/jobs", response_model=list[schemas.ScanJobOut])
def list_jobs(user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    return (
        db.query(models.ScanJob)
        .filter(models.ScanJob.user_id == user.id)
        .order_by(models.ScanJob.created_at.desc())
        .all()
    )


@router.get("/jobs/{job_id}", response_model=schemas.ScanJobOut)
def get_job(job_id: int, user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    job = db.query(models.ScanJob).get(job_id)
    if job is None or job.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan job not found")
    return job


@router.get("/jobs/{job_id}/findings")
def get_job_findings(job_id: int, user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    job = db.query(models.ScanJob).get(job_id)
    if job is None or job.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan job not found")
    if job.status != models.JobStatus.done or job.aegis_scan_id is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Scan is not finished yet")
    return aegis_bridge.get_findings(job.aegis_scan_id)


@router.get("/jobs/{job_id}/report")
def download_report(
    job_id: int,
    fmt: str = "html",
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    job = db.query(models.ScanJob).get(job_id)
    if job is None or job.user_id != user.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan job not found")

    allowed_formats = tiers.report_formats_for_tier(user.subscription.tier)
    if fmt not in allowed_formats:
        raise HTTPException(status.HTTP_403_FORBIDDEN, f"'{fmt}' reports require a higher tier")

    path = {"html": job.html_report_path, "pdf": job.pdf_report_path}.get(fmt)
    if fmt == "json":
        if job.aegis_scan_id is None:
            raise HTTPException(status.HTTP_409_CONFLICT, "Scan is not finished yet")
        return aegis_bridge.get_findings(job.aegis_scan_id)
    if not path:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Report not available (scan still running or failed)")
    return FileResponse(path)


@router.get("/history")
def target_history(target: str, user: models.User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Scan history for one target, restricted to jobs this user submitted."""
    jobs = (
        db.query(models.ScanJob)
        .filter(models.ScanJob.user_id == user.id, models.ScanJob.target == target)
        .order_by(models.ScanJob.created_at.desc())
        .all()
    )
    return [schemas.ScanJobOut.model_validate(j) for j in jobs]


@router.post("/diff")
def diff_scans(
    body: schemas.DiffRequest,
    user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    tier = user.subscription.tier
    if not tiers.diff_allowed_for_tier(tier):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Scan comparison requires Pro or Enterprise")

    # Both scans must belong to jobs owned by this user, so a diff can't leak
    # another user's findings via a guessed aegis_scan_id.
    owned_ids = {
        j.aegis_scan_id
        for j in db.query(models.ScanJob).filter(models.ScanJob.user_id == user.id).all()
        if j.aegis_scan_id
    }
    if body.scan_id_a not in owned_ids or body.scan_id_b not in owned_ids:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Scan not found")

    # Preserves Aegis's own new/fixed/unverified/unchanged/changed shape —
    # the frontend must render "unverified" distinctly from "fixed" rather
    # than collapsing them into a naive diff (per the brief).
    return aegis_bridge.diff(body.scan_id_a, body.scan_id_b)
