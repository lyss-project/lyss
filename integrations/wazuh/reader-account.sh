#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright 2026 Mouad Lyaazale. Additional terms (author attribution, names): see NOTICE.
#
# Creates the read-only Wazuh account used by LYSS "rescan on change": it can only read, in the
# wazuh-alerts-* indices, the alerts of the groups config_changed and lyss_admin_session_end
# (document-level security), and only 5 fields of them (field-level security).
# Run as root on the Wazuh indexer node (all-in-one: the Wazuh server):
#   sudo sh reader-account.sh [account]          default account name: lyss-reader
#   sudo sh reader-account.sh --remove [account]
# The generated password is written to /root/.<account>.pw (mode 600) and never printed: enter it in
# LYSS (Settings > Rescan on change) from that file.
set -eu
CERTS=${CERTS:-/etc/wazuh-indexer/certs}
API=https://localhost:9200/_plugins/_security/api
call() { curl -sS -k --cert "$CERTS/admin.pem" --key "$CERTS/admin-key.pem" -H 'Content-Type: application/json' "$@"; echo; }

if [ "${1:-}" = "--remove" ]; then
    ACCOUNT=${2:-lyss-reader}
    echo "note: remove $ACCOUNT from the kibana_user mapping in the dashboard (Security > Roles) if needed"
    call -X DELETE "$API/rolesmapping/lyss_change_reader"
    call -X DELETE "$API/roles/lyss_change_reader"
    call -X DELETE "$API/internalusers/$ACCOUNT"
    rm -f "/root/.$ACCOUNT.pw"
    echo "account $ACCOUNT and role lyss_change_reader removed"
    exit 0
fi
ACCOUNT=${1:-lyss-reader}
PWFILE=/root/.$ACCOUNT.pw

umask 077
if [ ! -s "$PWFILE" ]; then
    # 24 random characters + required classes
    printf '%s%s\n' "$(head -c 64 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 24)" 'aZ9!' > "$PWFILE"
fi
PW=$(cat "$PWFILE")

call -X PUT "$API/roles/lyss_change_reader" -d '{
  "description": "LYSS rescan on change: read switch configuration-change alerts only",
  "cluster_permissions": [],
  "index_permissions": [{
    "index_patterns": ["wazuh-alerts-*"],
    "dls": "{\"terms\": {\"rule.groups\": [\"config_changed\", \"lyss_admin_session_end\"]}}",
    "fls": ["timestamp", "location", "rule.id", "rule.groups", "rule.description"],
    "allowed_actions": ["read"]
  }]
}'
call -X PUT "$API/internalusers/$ACCOUNT" -d "{\"password\": \"$PW\", \"description\": \"LYSS rescan on change (read-only)\"}"
call -X PUT "$API/rolesmapping/lyss_change_reader" -d "{\"users\": [\"$ACCOUNT\"]}"
# the dashboard's console proxy needs the basic dashboard user role: APPEND the account to its
# mapping ("/users/-"), never replace the users already mapped
USERS=$(call -X GET "$API/rolesmapping/kibana_user" | python3 -c '
import json, sys
m = json.load(sys.stdin).get("kibana_user", {})
print("absent" if "users" not in m else " ".join(m["users"]) or "empty")')
case " $USERS " in
    *" $ACCOUNT "*) echo "$ACCOUNT already mapped to kibana_user" ;;
    " absent ") call -X PATCH "$API/rolesmapping/kibana_user" -d "[{\"op\": \"add\", \"path\": \"/users\", \"value\": [\"$ACCOUNT\"]}]" ;;
    *) call -X PATCH "$API/rolesmapping/kibana_user" -d "[{\"op\": \"add\", \"path\": \"/users/-\", \"value\": \"$ACCOUNT\"}]" ;;
esac
unset PW
echo "account $ACCOUNT ready; password in $PWFILE (not printed)"
