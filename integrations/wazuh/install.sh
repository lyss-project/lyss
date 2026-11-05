#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
#
# Installs the LYSS decoder and rules on a Wazuh manager, checks the configuration, restarts the
# manager. Run as root on the manager:  sudo sh install.sh        (uninstall: sudo sh install.sh --remove)
# Nothing else is changed. If the configuration check fails, the previous state is restored.
set -eu
DIR=$(cd "$(dirname "$0")" && pwd)
OSSEC=${OSSEC:-/var/ossec}
DEC="$OSSEC/etc/decoders/lyss_decoders.xml"
RUL="$OSSEC/etc/rules/lyss_rules.xml"

if [ "${1:-}" = "--remove" ]; then
    rm -f "$DEC" "$RUL"
    systemctl restart wazuh-manager
    echo "LYSS decoder and rules removed, wazuh-manager restarted."
    exit 0
fi

# refuse rule ids already used by other rule files
for id in $(grep -o 'rule id="[0-9]*"' "$DIR/lyss_rules.xml" | grep -o '[0-9][0-9]*'); do
    if grep -rlq "id=\"$id\"" "$OSSEC/etc/rules" --exclude=lyss_rules.xml 2>/dev/null; then
        echo "Rule id $id is already used in $OSSEC/etc/rules: edit the ids in lyss_rules.xml first." >&2
        exit 1
    fi
done

backup=$(mktemp -d)
[ -f "$DEC" ] && cp -p "$DEC" "$backup/"
[ -f "$RUL" ] && cp -p "$RUL" "$backup/"
install -m 660 -o wazuh -g wazuh "$DIR/lyss_decoders.xml" "$DEC"
install -m 660 -o wazuh -g wazuh "$DIR/lyss_rules.xml" "$RUL"

if ! "$OSSEC/bin/wazuh-analysisd" -t; then
    echo "Configuration check FAILED: restoring the previous state." >&2
    rm -f "$DEC" "$RUL"
    [ -f "$backup/lyss_decoders.xml" ] && cp -p "$backup/lyss_decoders.xml" "$DEC"
    [ -f "$backup/lyss_rules.xml" ] && cp -p "$backup/lyss_rules.xml" "$RUL"
    exit 1
fi
rm -rf "$backup"
systemctl restart wazuh-manager
echo "LYSS decoder and rules installed, wazuh-manager restarted."
echo "Test: echo 'Nov  5 12:00:00 host lyss: {\"lyss\":{\"event\":\"test\"}}' | $OSSEC/bin/wazuh-logtest"
