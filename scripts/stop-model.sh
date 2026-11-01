#!/usr/bin/env bash
# Stop the model server started with --background (either backend).
source "$(dirname "$0")/lib.sh"

if [[ "$(backend)" != "metal" ]]; then
  if docker ps -q -f "name=^${LLAMA_CONTAINER}$" 2>/dev/null | grep -q .; then
    docker stop "$LLAMA_CONTAINER" >/dev/null && ok "stopped container $LLAMA_CONTAINER"
  else
    info "no $LLAMA_CONTAINER container running"
  fi
  rm -f "$(llama_sock)"
  exit 0
fi

pidf="$RUN_DIR/llama.pid"
[[ -f "$pidf" ]] || { info "no background llama-server recorded"; exit 0; }
pid="$(cat "$pidf")"
if kill -0 "$pid" 2>/dev/null; then
  kill "$pid"
  for _ in $(seq 1 20); do kill -0 "$pid" 2>/dev/null || break; sleep 0.5; done
  kill -0 "$pid" 2>/dev/null && kill -9 "$pid"
  ok "stopped llama-server (pid $pid)"
else
  info "pid $pid is not running"
fi
rm -f "$pidf"
