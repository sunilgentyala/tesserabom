#!/usr/bin/env bash
# Verify the decoders and rules against a real manager using its offline logtest tool.
#
# Usage: MANAGER_IMAGE=<manager container image> scripts/logtest_docker.sh
#        (needs Docker; the image is pulled on first use; no default is baked in)
#
# Each line of siem/samples/logtest.txt must raise the rule id listed in EXPECTED, in order.
set -euo pipefail
export MSYS_NO_PATHCONV=1

IMAGE="${MANAGER_IMAGE:?set MANAGER_IMAGE to a manager container image}"
NAME="tesserabom-logtest-$$"
EXPECTED=(100903 100910 100913 100902)
ROOT="$(cd "$(dirname "$0")/.." && (pwd -W 2>/dev/null || pwd))"

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker run -d --name "$NAME" "$IMAGE" >/dev/null
tool() { docker exec "$NAME" bash -c "ls /var/ossec/bin/*-$1 2>/dev/null | head -1"; }
CONTROL="$(tool control)"; ANALYSISD="$(tool analysisd)"; LOGTEST="$(tool logtest)"
for _ in $(seq 1 40); do
  docker exec "$NAME" "$CONTROL" status 2>/dev/null | grep -q "analysisd is running" && break
  sleep 3
done

docker cp "$ROOT/siem/decoders/tesserabom_decoders.xml" "$NAME:/var/ossec/etc/decoders/tesserabom_decoders.xml"
docker cp "$ROOT/siem/rules/tesserabom_rules.xml" "$NAME:/var/ossec/etc/rules/tesserabom_rules.xml"
docker exec "$NAME" bash -c "chown --reference=/var/ossec/etc/ossec.conf /var/ossec/etc/decoders/tesserabom_decoders.xml /var/ossec/etc/rules/tesserabom_rules.xml"

if docker exec "$NAME" "$ANALYSISD" -t 2>&1 | grep -E "ERROR|CRITICAL"; then
  echo "FAIL: manager rejected the configuration" >&2
  exit 1
fi
docker exec "$NAME" "$CONTROL" restart >/dev/null 2>&1
sleep 12

status=0
i=0
while IFS= read -r line; do
  out="$(printf '%s\n' "$line" | docker exec -i "$NAME" "$LOGTEST" 2>&1)"
  got="$(printf '%s\n' "$out" | sed -n "s/^[[:space:]]*id: '\([0-9]*\)'.*/\1/p" | head -1)"
  if [ "$got" = "${EXPECTED[$i]}" ] && printf '%s' "$out" | grep -q "Alert to be generated"; then
    echo "ok   sample $((i + 1)): rule $got"
  else
    echo "FAIL sample $((i + 1)): expected ${EXPECTED[$i]}, got '${got:-none}'" >&2
    status=1
  fi
  i=$((i + 1))
done < "$ROOT/siem/samples/logtest.txt"
exit $status
