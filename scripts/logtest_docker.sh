#!/usr/bin/env bash
# Verify the decoders and rules against a real Wazuh manager using wazuh-logtest.
#
# Usage: scripts/logtest_docker.sh            (needs Docker; pulls the image on first use)
#        WAZUH_IMAGE=wazuh/wazuh-manager:4.14.10 scripts/logtest_docker.sh
#
# Each line of wazuh/samples/logtest.txt must raise the rule id listed in EXPECTED, in order.
set -euo pipefail
export MSYS_NO_PATHCONV=1

IMAGE="${WAZUH_IMAGE:-wazuh/wazuh-manager:4.14.10}"
NAME="tesserabom-logtest-$$"
EXPECTED=(100903 100910 100913 100902)
ROOT="$(cd "$(dirname "$0")/.." && (pwd -W 2>/dev/null || pwd))"

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker run -d --name "$NAME" "$IMAGE" >/dev/null
for _ in $(seq 1 40); do
  docker exec "$NAME" /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "wazuh-analysisd is running" && break
  sleep 3
done

docker cp "$ROOT/wazuh/decoders/tesserabom_decoders.xml" "$NAME:/var/ossec/etc/decoders/tesserabom_decoders.xml"
docker cp "$ROOT/wazuh/rules/tesserabom_rules.xml" "$NAME:/var/ossec/etc/rules/tesserabom_rules.xml"
docker exec "$NAME" bash -c "chown wazuh:wazuh /var/ossec/etc/decoders/tesserabom_decoders.xml /var/ossec/etc/rules/tesserabom_rules.xml"

if docker exec "$NAME" /var/ossec/bin/wazuh-analysisd -t 2>&1 | grep -E "ERROR|CRITICAL"; then
  echo "FAIL: Wazuh rejected the configuration" >&2
  exit 1
fi
docker exec "$NAME" /var/ossec/bin/wazuh-control restart >/dev/null 2>&1
sleep 12

status=0
i=0
while IFS= read -r line; do
  out="$(printf '%s\n' "$line" | docker exec -i "$NAME" /var/ossec/bin/wazuh-logtest 2>&1)"
  got="$(printf '%s\n' "$out" | sed -n "s/^[[:space:]]*id: '\([0-9]*\)'.*/\1/p" | head -1)"
  if [ "$got" = "${EXPECTED[$i]}" ] && printf '%s' "$out" | grep -q "Alert to be generated"; then
    echo "ok   sample $((i + 1)): rule $got"
  else
    echo "FAIL sample $((i + 1)): expected ${EXPECTED[$i]}, got '${got:-none}'" >&2
    status=1
  fi
  i=$((i + 1))
done < "$ROOT/wazuh/samples/logtest.txt"
exit $status
