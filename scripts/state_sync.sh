#!/usr/bin/env bash
# TikZoom state persistence across GitHub Actions runs.
# usage: state_sync.sh pull|push
set -uo pipefail
MODE="${1:-pull}"

clean_bloat() {
  find bots_storage -name "__pycache__" -type d -prune -exec rm -rf {} + 2>/dev/null || true
  find bots_storage -name "node_modules" -type d -prune -exec rm -rf {} + 2>/dev/null || true
  find bots_storage -name ".venv" -type d -prune -exec rm -rf {} + 2>/dev/null || true
  find bots_storage -name "venv" -type d -prune -exec rm -rf {} + 2>/dev/null || true
  rm -rf data/logs 2>/dev/null || true
}

pull() {
  echo "[state] pulling latest state..."
  git fetch --depth=1 origin state 2>/dev/null || { echo "[state] no state branch yet — fresh start"; return 0; }
  SRC=$(git rev-parse FETCH_HEAD 2>/dev/null) || return 0
  mkdir -p /tmp/state-restore
  git archive "$SRC" data bots_storage 2>/dev/null | tar -x -C /tmp/state-restore || true
  if [ -d /tmp/state-restore/data ]; then
    cp -a /tmp/state-restore/data/. data/ 2>/dev/null || true
  fi
  if [ -d /tmp/state-restore/bots_storage ]; then
    cp -a /tmp/state-restore/bots_storage/. bots_storage/ 2>/dev/null || true
  fi
  rm -rf /tmp/state-restore
  echo "[state] restored: $(du -sh data bots_storage 2>/dev/null | tr '\n' ' ')"
}

push() {
  git config user.name "tikzoom-state"
  git config user.email "state@tikzoom.local"
  clean_bloat
  BASE=""
  if git fetch --depth=1 origin state 2>/dev/null; then
    BASE=$(git rev-parse FETCH_HEAD 2>/dev/null || true)
  fi
  if [ -n "$BASE" ]; then
    git checkout -q -B state "$BASE"
  else
    git checkout -q --orphan state
    git rm -rq --cached . 2>/dev/null || true
  fi
  mkdir -p data bots_storage
  git add -A data bots_storage 2>/dev/null || true
  git rm -rq --cached data/logs 2>/dev/null || true
  if [ -n "$BASE" ] && git diff --cached --quiet HEAD 2>/dev/null; then
    echo "[state] no changes to persist"
    return 0
  fi
  git commit -qm "state snapshot $(date -u +%Y%m%d-%H%M%S)" || { echo "[state] commit empty"; return 0; }
  git push -q origin state && echo "[state] pushed: $(du -sh data bots_storage 2>/dev/null | tr '\n' ' ')"
}

case "$MODE" in
  pull) pull ;;
  push) push ;;
  *) echo "usage: $0 pull|push"; exit 1 ;;
esac
