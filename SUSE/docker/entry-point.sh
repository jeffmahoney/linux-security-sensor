#!/bin/sh

if test ! -e /config/server.conf; then
	echo "No config file found.  Generating default at /config/server.conf." >&2 
	/generate-config.sh > /config/server.conf
fi

exec velociraptor frontend -v --config /config/server.conf
