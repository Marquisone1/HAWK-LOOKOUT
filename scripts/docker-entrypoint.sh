#!/bin/sh
# Entrypoint: fix /data ownership after bind-mount then drop to appuser.
#
# When docker-compose mounts ./data:/data the host directory replaces the
# /data that was chown-ed inside the image, so appuser may not be able to
# write there.  Running as root here lets us fix that before exec-ing the
# real process under the unprivileged appuser account.
set -e

chown -R appuser:appgroup /data

exec gosu appuser "$@"
