#!/bin/bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
#
# Validates lyss_decoders.xml and lyss_rules.xml on a disposable Wazuh manager (Docker): every line
# of samples.log (fictitious data) must fire the rule id on the same line of expected.txt.
#   bash integrations/wazuh/test/run.sh [wazuh-manager image tag]     (default 4.14.9)
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
TAG=${1:-4.14.9}
NAME=lyss-wazuh-test-$$
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

wait_logtest() {
    for _ in $(seq 1 60); do
        docker exec "$NAME" test -S /var/ossec/queue/sockets/logtest 2>/dev/null && return 0
        sleep 3
    done
    echo "wazuh-logtest socket not ready" >&2; return 1
}

docker run -d --name "$NAME" "wazuh/wazuh-manager:$TAG" >/dev/null
wait_logtest
docker cp "$HERE/../lyss_decoders.xml" "$NAME:/var/ossec/etc/decoders/lyss_decoders.xml"
docker cp "$HERE/../lyss_rules.xml" "$NAME:/var/ossec/etc/rules/lyss_rules.xml"
docker exec "$NAME" chown wazuh:wazuh /var/ossec/etc/decoders/lyss_decoders.xml /var/ossec/etc/rules/lyss_rules.xml
docker exec "$NAME" /var/ossec/bin/wazuh-analysisd -t
docker exec "$NAME" /var/ossec/bin/wazuh-control restart >/dev/null
wait_logtest
sleep 5

# one rule id per sample ("-" when no rule fired), in order
docker exec -i "$NAME" /var/ossec/bin/wazuh-logtest < "$HERE/samples.log" 2>&1 | awk '
    /\*\*Phase 1/ { if (n++) print (id == "" ? "-" : id); id = "" }
    /^\s+id: '\''[0-9]+'\''/ { gsub(/[^0-9]/, "", $2); id = $2 }
    END { if (n) print (id == "" ? "-" : id) }' > "$HERE/.actual.txt"

if diff -u "$HERE/expected.txt" "$HERE/.actual.txt"; then
    echo "OK: $(wc -l < "$HERE/expected.txt") samples fire the expected rules (wazuh-manager $TAG)"
    rm -f "$HERE/.actual.txt"
else
    paste -d '|' "$HERE/samples.log" "$HERE/.actual.txt" | cut -c1-150
    echo "FAILED: see the diff above (expected | actual)" >&2
    exit 1
fi
