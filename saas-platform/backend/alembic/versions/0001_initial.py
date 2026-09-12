"""initial schema: users, subscriptions, payments, scan_jobs, admin_actions

Revision ID: 0001
Revises:
Create Date: 2026-09-13

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

# postgresql.ENUM (not generic sa.Enum) so create_type=False is honored: the
# types are created once, explicitly, in upgrade() below via .create(checkfirst
# =True). With generic sa.Enum the flag is ignored and op.create_table re-emits
# CREATE TYPE for every enum column, failing with "type already exists" on a
# fresh database (and emitting it repeatedly for types shared across tables).
role_enum = postgresql.ENUM("user", "admin", name="role", create_type=False)
tier_enum = postgresql.ENUM("free", "pro", "enterprise", name="tier", create_type=False)
substatus_enum = postgresql.ENUM("active", "cancelled", "expired", name="substatus", create_type=False)
paymentstatus_enum = postgresql.ENUM("paid", "pending", "failed", name="paymentstatus", create_type=False)
jobstatus_enum = postgresql.ENUM("queued", "running", "done", "failed", name="jobstatus", create_type=False)


def upgrade():
    bind = op.get_bind()
    role_enum.create(bind, checkfirst=True)
    tier_enum.create(bind, checkfirst=True)
    substatus_enum.create(bind, checkfirst=True)
    paymentstatus_enum.create(bind, checkfirst=True)
    jobstatus_enum.create(bind, checkfirst=True)

    op.create_table(
        "users",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("email", sa.String(255), unique=True, index=True, nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("role", role_enum, nullable=False, server_default="user"),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default=sa.true()),
        sa.Column("created_at", sa.DateTime, nullable=True),
        sa.Column("last_login_at", sa.DateTime, nullable=True),
    )

    op.create_table(
        "subscriptions",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id"), unique=True, nullable=False),
        sa.Column("tier", tier_enum, nullable=False, server_default="free"),
        sa.Column("status", substatus_enum, nullable=False, server_default="active"),
        sa.Column("started_at", sa.DateTime, nullable=True),
        sa.Column("renews_at", sa.DateTime, nullable=True),
        sa.Column("scans_used_this_period", sa.Integer, nullable=False, server_default="0"),
        sa.Column("period_start_date", sa.DateTime, nullable=False),
    )

    op.create_table(
        "payments",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("amount", sa.Integer, nullable=False),
        sa.Column("tier", tier_enum, nullable=False),
        sa.Column("simulated_method", sa.String(64), server_default="manual/demo"),
        sa.Column("status", paymentstatus_enum, nullable=False, server_default="paid"),
        sa.Column("created_at", sa.DateTime, nullable=True),
        sa.Column("note", sa.String(255), nullable=True),
    )

    op.create_table(
        "scan_jobs",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("target", sa.String(255), nullable=False),
        sa.Column("profile", sa.String(64), nullable=False),
        sa.Column("status", jobstatus_enum, nullable=False, server_default="queued"),
        sa.Column("aegis_scan_id", sa.Integer, nullable=True),
        sa.Column("txt_report_path", sa.String(512), nullable=True),
        sa.Column("pdf_report_path", sa.String(512), nullable=True),
        sa.Column("html_report_path", sa.String(512), nullable=True),
        sa.Column("error", sa.Text, nullable=True),
        sa.Column("authorized_intrusive", sa.Boolean, server_default=sa.false()),
        sa.Column("authorized_ip", sa.String(64), nullable=True),
        sa.Column("authorized_at", sa.DateTime, nullable=True),
        sa.Column("created_at", sa.DateTime, nullable=True),
        sa.Column("started_at", sa.DateTime, nullable=True),
        sa.Column("finished_at", sa.DateTime, nullable=True),
    )

    op.create_table(
        "admin_actions",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("admin_id", sa.Integer, sa.ForeignKey("users.id"), nullable=False),
        sa.Column("action", sa.String(64), nullable=False),
        sa.Column("target_user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("timestamp", sa.DateTime, nullable=True),
        sa.Column("detail", sa.Text, nullable=True),
    )


def downgrade():
    op.drop_table("admin_actions")
    op.drop_table("scan_jobs")
    op.drop_table("payments")
    op.drop_table("subscriptions")
    op.drop_table("users")

    bind = op.get_bind()
    jobstatus_enum.drop(bind, checkfirst=True)
    paymentstatus_enum.drop(bind, checkfirst=True)
    substatus_enum.drop(bind, checkfirst=True)
    tier_enum.drop(bind, checkfirst=True)
    role_enum.drop(bind, checkfirst=True)
