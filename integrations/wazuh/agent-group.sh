#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
#
# Makes the Wazuh agent of the machine running LYSS read the LYSS events file (JSON lines), through
# a dedicated agent group "lyss" (centralized configuration: nothing to edit on the machine itself).
# Run as root on the Wazuh manager:
#   sudo sh agent-group.sh <agent-id> '<path of the LYSS events file on that machine>'
#   sudo sh agent-group.sh --remove <agent-id>
# The agent keeps its other groups; it reloads the shared configuration by itself.
set -eu
G=/var/ossec/bin/agent_groups
SHARED=/var/ossec/etc/shared/lyss

if [ "${1:-}" = "--remove" ]; then
    $G -r -i "$2" -g lyss -q
    echo "agent $2 removed from group lyss"
    exit 0
fi
[ $# -eq 2 ] || { echo "usage: sudo sh agent-group.sh <agent-id> '<events file path>'" >&2; exit 2; }
AGENT=$1
FILE=$2

$G -l -q 2>/dev/null | grep -qx lyss || $G -a -g lyss -q
cat > "$SHARED/agent.conf" <<EOF
<agent_config>
  <!-- LYSS (switch security) events: one JSON object per line -->
  <localfile>
    <location>$FILE</location>
    <log_format>json</log_format>
  </localfile>
</agent_config>
EOF
chown wazuh:wazuh "$SHARED/agent.conf"
chmod 660 "$SHARED/agent.conf"
/var/ossec/bin/verify-agent-conf -f "$SHARED/agent.conf"
$G -a -i "$AGENT" -g lyss -q
echo "agent $AGENT groups: $($G -s -i "$AGENT" -q)"
echo "Test: in LYSS, Settings > SIEM events > Send test event, then look for rule 100808."
