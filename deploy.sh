#!/usr/bin/env bash
# Deploy WatchTower to the remote VM.
#   ./deploy.sh            sync code, rebuild, restart
#   ./deploy.sh --env      also copy the local .env (first deploy, or after rotating keys)
#   HOST=other ./deploy.sh deploy to another SSH host alias
set -euo pipefail

HOST="${HOST:-DAI-VM}"
DIR="${DIR:-agent-watchtower}"
cd "$(dirname "$0")"

echo "→ syncing code to $HOST:~/$DIR (excluding .env)"
ssh "$HOST" "mkdir -p ~/$DIR"
rsync -az --delete --exclude-from=.dockerignore --exclude=.DS_Store --exclude=backend/recordings ./ "$HOST:~/$DIR/"

if [[ "${1:-}" == "--env" ]]; then
  echo "→ copying .env"
  scp -q .env "$HOST:~/$DIR/.env"
fi

echo "→ building and restarting"
ssh "$HOST" "cd ~/$DIR && test -f .env || { echo 'missing .env on remote; rerun with --env'; exit 1; }; docker compose up -d --build"

echo "→ health check"
ssh "$HOST" 'for i in $(seq 1 15); do curl -sf localhost:8090/api/state >/dev/null && { echo "watchtower up on :8090"; exit 0; }; sleep 1; done; echo "not responding; recent logs:"; docker logs --tail 30 watchtower; exit 1'
ssh "$HOST" 'curl -s -o /dev/null -w "AI Engine gateway reachable from VM: HTTP %{http_code} (401 = reachable)\n" --max-time 10 https://prodentapigw.itaws.equinix.com/eap-backend/api/models || echo "AI Engine gateway NOT reachable from VM -> set AI_ENGINE_MODE=replay"'
