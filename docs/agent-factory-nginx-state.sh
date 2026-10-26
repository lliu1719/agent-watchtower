#!/bin/sh
# Agent factory nginx: let WatchTower read GET /api/wt/state (read-only), with the same rule as the paths it
# already writes to: no Basic Auth, only the allow-listed addresses. WatchTower polls it to follow the
# factory's Reset. Backs the file up, checks the config, then reloads; writes nothing if the line is not there.
# Run on the factory host:  sudo sh agent-factory-nginx-state.sh
set -e
f=/home/fred/fred-service-plane/nginx/conf.d/default.conf
if grep -q '\^/api/wt/(log|feedback|tier|state)\$' "$f"; then echo "already done"; exit 0; fi
grep -q '\^/api/wt/(log|feedback|tier)\$' "$f" || { echo "the /api/wt location was not found; nothing changed"; exit 1; }
b="$f.bak-watchtower-$(date +%Y%m%d-%H%M%S)"
cp -p "$f" "$b"
sed -i 's#\^/api/wt/(log|feedback|tier)\$#^/api/wt/(log|feedback|tier|state)$#' "$f"
grep -n 'api/wt/' "$f"
if docker exec nginx nginx -t; then
  docker exec nginx nginx -s reload && echo "reloaded (backup $b)"
else
  cp -p "$b" "$f"; echo "config test failed: restored the backup"; exit 1
fi
