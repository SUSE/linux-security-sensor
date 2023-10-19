#!/bin/bash

CONFIG="/config"
MERGE_FILE="/etc/velociraptor/init-config.json"
SERVER_CONFIG="${CONFIG}/server.conf"
CLIENT_CONFIG="${CONFIG}/client.conf"

CLIENT_DIR="/var/lib/velociraptor-client"
BUFFER_FILE="${CLIENT_DIR}/Velociraptor_Buffer.bin"
WRITEBACK_FILE="${CLIENT_DIR}/velociraptor.writeback.yaml"

usage() {
	echo "$(basename "$0") [-f]"
	exit 1
}

force=false
while getopts f value "$@"; do
	case "$value" in
	f) force=true ;;
	?) usage ;;
	esac
done

shift $(( $OPTIND - 1 ))

if test -e "${SERVER_CONFIG}" -a "$force" != "true"; then
	echo "${SERVER_CONFIG} already exists.  Will not replace without -f." >&2
	exit 1
fi

velociraptor config generate --merge_file="$MERGE_FILE" |grep -v '^  *.*{}' > "$SERVER_CONFIG"

awk "
/^Client/ { print \$0; seen_client=1; next; }
/^[A-Za-z]/ { if (seen_client == 1) exit; }
{ if (seen_client == 1 && skip_record != 1) print \$0; }
" < "${SERVER_CONFIG}" > "${CLIENT_CONFIG}"

sed -e 's#https://sensor-frontend:8000/#https//velociraptor.fqdn:8000/' < "${CLIENT_CONFIG}" > "${CLIENT_CONFIG}.template"
