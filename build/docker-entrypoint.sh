#!/bin/sh
set -eu
# Never select, create or boot a ship here. Preserve unfamiliar existing data.
exec python3 /opt/importer/volume_guard.py "$@"
