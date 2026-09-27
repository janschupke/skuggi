#!/bin/sh
set -e
# World-readable so the guest (null) session can read every planted file.
chmod -R a+rX /srv/samba/public
exec smbd --foreground --no-process-group --debug-stdout
