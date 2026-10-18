#!/usr/bin/env bash
# End-to-end check of a RUNNING server using curl (start it first: scripts/start.sh).
# Generates simulated demo data as a side effect.
source "$(dirname "$0")/common.sh"
TOKEN="$(env_value SOC_ANALYST_TOKEN)"; BASE="http://${CHECK_HOST}:${PORT}"; pass=0; failn=0
[ -n "$TOKEN" ] || { echo "SOC_ANALYST_TOKEN not found in .env"; exit 1; }
check() { if [ "$2" = "0" ]; then echo "PASS  $1"; pass=$((pass+1)); else echo "FAIL  $1"; failn=$((failn+1)); fi; }
AUTH=(-H "Authorization: Bearer $TOKEN"); JSON=(-H "Content-Type: application/json")
jget() { "$PY" -c "import sys,json; d=json.load(sys.stdin); print(eval(sys.argv[1]))" "$1"; }

curl -fsS -m 5 "$BASE/api/health" >/dev/null;                                                  check "health endpoint answers" $?
[ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/alerts")" = "401" ];                     check "data endpoints reject a missing token" $?
[ "$(curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer wrong' "$BASE/api/alerts")" = "401" ]; check "wrong token rejected" $?
[ "$(curl -s -o /dev/null -w '%{http_code}' "$BASE/")" = "200" ];                               check "dashboard page served" $?
SIM="$(curl -fsS -m 60 "${AUTH[@]}" "${JSON[@]}" -X POST -d '{"seed":42}' "$BASE/api/simulate")"; check "simulate demo data" $?
[ "$(echo "$SIM" | jget "d['alerts_total']")" -ge 15 ];                                          check "detection produced alerts" $?
AID="$(curl -fsS "${AUTH[@]}" "$BASE/api/alerts?limit=1" | jget "d['items'][0]['id']")"
curl -fsS "${AUTH[@]}" "$BASE/api/alerts/$AID" | grep -q '"breakdown"';                         check "alert detail has score breakdown" $?
curl -fsS "${AUTH[@]}" "${JSON[@]}" -X POST -d '{"status":"investigating"}' "$BASE/api/alerts/$AID/status" >/dev/null; check "status update" $?
curl -fsS "${AUTH[@]}" "${JSON[@]}" -X POST -d '{"text":"smoke test note"}' "$BASE/api/alerts/$AID/notes" >/dev/null;  check "add analyst note" $?
curl -fsS "${AUTH[@]}" "$BASE/api/export/logs.csv?limit=5" 2>/dev/null | head -n1 | grep -q "log_id";        check "CSV export" $?
[ "$(curl -s -o /dev/null -w '%{http_code}' "${AUTH[@]}" "${JSON[@]}" -X POST -d '{"status":"bogus"}' "$BASE/api/alerts/$AID/status")" = "422" ]; check "invalid input is rejected (422)" $?
echo; echo "SMOKE TEST: $pass passed, $failn failed"; [ "$failn" = 0 ]
