#!/bin/bash
# Orionline release helper - promotes the staged WAR into the live webapps dir.
# Invoked as root via sudo by the deploy automation (see /etc/sudoers.d/deploy).
#
# INTENTIONALLY INSECURE: this file is world-writable (0777). The `deploy`
# account - the account Tomcat (and therefore any Manager-deployed webshell)
# runs as - can overwrite it and have root run arbitrary commands.
set -e

STAGED=/opt/orionline/releases/staged.war
LIVE=/usr/local/tomcat/webapps/app.war

if [ -f "$STAGED" ]; then
  cp "$STAGED" "$LIVE"
  echo "release: promoted $STAGED -> $LIVE"
else
  echo "release: nothing staged at $STAGED"
fi
