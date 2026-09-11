#!/usr/bin/env bash
# Phase 6 smoke test driver. Writes all artefacts under smoke_test/phase6/.
set -u
cd /home/jafar/aegis-scanner
PY=venv/bin/python3
OUT=smoke_test/phase6
mkdir -p $OUT
DVWA=172.28.0.20
ALL_TARGETS="$OUT/targets.txt"
printf '172.28.0.20\n172.28.0.10\n172.28.0.30\n172.28.0.40\n172.17.0.2\n172.17.0.3\n' > "$ALL_TARGETS"

echo "### Pre-scan liveness" > $OUT/liveness_before.txt
for pair in "172.28.0.20:80" "172.28.0.10:80" "172.28.0.30:2222" "172.28.0.40:445" "172.17.0.2:3000" "172.17.0.3:8080"; do
  h=${pair%%:*}; p=${pair##*:}
  if [ "$p" = "2222" ] || [ "$p" = "445" ]; then
    (nc -zv -w3 "$h" "$p" >/dev/null 2>&1 && echo "$pair: OPEN" || echo "$pair: DOWN") >> $OUT/liveness_before.txt
  else
    curl -s -o /dev/null -w "$pair: %{http_code} %{time_total}s\n" --max-time 8 "http://$pair/" >> $OUT/liveness_before.txt 2>&1 || echo "$pair: DOWN" >> $OUT/liveness_before.txt
  fi
done

# --- 1) Legacy deepscan baseline on DVWA (timed) ---
echo "[phase6] legacy deepscan baseline on $DVWA ..."
START=$(date +%s)
$PY aegis.py $DVWA --profile deepscan --non-interactive --no-live > $OUT/legacy_dvwa.log 2>&1
LEGACY_RC=$?
LEGACY_SECS=$(( $(date +%s) - START ))
echo "LEGACY: rc=$LEGACY_RC secs=$LEGACY_SECS" | tee $OUT/legacy_time.txt

# --- 2) Engine full scan on DVWA (timed, head-to-head) ---
echo "[phase6] engine full scan on $DVWA ..."
START=$(date +%s)
$PY aegis.py $DVWA --engine --scan-profile full --criticality high --non-interactive --no-live > $OUT/engine_dvwa.log 2>&1
ENGINE_RC=$?
ENGINE_SECS=$(( $(date +%s) - START ))
echo "ENGINE: rc=$ENGINE_RC secs=$ENGINE_SECS" | tee $OUT/engine_time.txt

# --- 3) Engine full scan across all reachable targets ---
echo "[phase6] engine full scan across all targets ..."
START=$(date +%s)
$PY aegis.py --targets "$ALL_TARGETS" --engine --scan-profile full --non-interactive --no-live --max-concurrent-targets 3 > $OUT/engine_all.log 2>&1
ALL_RC=$?
ALL_SECS=$(( $(date +%s) - START ))
echo "ENGINE_ALL: rc=$ALL_RC secs=$ALL_SECS" | tee $OUT/engine_all_time.txt

# --- 4) Post-scan liveness (throttling safety: nothing knocked offline) ---
echo "### Post-scan liveness" > $OUT/liveness_after.txt
for pair in "172.28.0.20:80" "172.28.0.10:80" "172.28.0.30:2222" "172.28.0.40:445" "172.17.0.2:3000" "172.17.0.3:8080"; do
  h=${pair%%:*}; p=${pair##*:}
  if [ "$p" = "2222" ] || [ "$p" = "445" ]; then
    (nc -zv -w3 "$h" "$p" >/dev/null 2>&1 && echo "$pair: OPEN" || echo "$pair: DOWN") >> $OUT/liveness_after.txt
  else
    curl -s -o /dev/null -w "$pair: %{http_code} %{time_total}s\n" --max-time 8 "http://$pair/" >> $OUT/liveness_after.txt 2>&1 || echo "$pair: DOWN" >> $OUT/liveness_after.txt
  fi
done

echo "[phase6] DONE legacy=${LEGACY_SECS}s engine=${ENGINE_SECS}s all=${ALL_SECS}s" | tee $OUT/DONE.txt
