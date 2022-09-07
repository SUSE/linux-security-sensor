#!/bin/sh

SERVER_CONFIG="/config/server.conf"

if test ! -e "${SERVER_CONFIG}"; then
	echo "No config file found.  Generating default at "${SERVER_CONFIG}"." >&2
	/generate-config.sh
fi

exec velociraptor frontend -v --config "${SERVER_CONFIG}"
