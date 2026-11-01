#!/usr/bin/env bash
# Start llama-server in its sandbox for the active backend.
#
#   scripts/start-model.sh                 foreground (Ctrl-C to stop)
#   scripts/start-model.sh --background    detach; logs to logs/llama-server.log (metal)
#                                          or `docker logs re-lab-llama` (cuda/cpu)
#   scripts/start-model.sh --print-profile show the resolved macOS sandbox profile and exit
#
# metal     : native llama-server under macOS Seatbelt, TCP on 127.0.0.1 only
# cuda, cpu : llama-server container with --network none, Unix socket .run/sock/llama.sock
source "$(dirname "$0")/lib.sh"

mode="${1:-foreground}"
b="$(backend)"

if [[ "$mode" == "--print-profile" ]]; then
  [[ "$b" == "metal" ]] || die "--print-profile is for the macOS backend; cuda/cpu isolation comes from the container flags in scripts/lib.sh"
  ensure_run_dir
  render_llama_profile "$RUN_DIR/llama-server.sb"; cat "$RUN_DIR/llama-server.sb"; exit 0
fi

model="$(model_path)"
[[ -f "$model" ]] || die "$model is missing. Run: make model"
mkdir -p "$LAB_DIR/logs"
ensure_api_key

# Re-hash the model whenever its size or mtime changed since the last good check.
# shellcheck disable=SC1091
source "$MODELS_DIR/MODEL.lock"
stamp="$RUN_DIR/model.verified"
want_stamp="$MODEL_SHA256 $(file_size "$model") $(file_mtime "$model")"
if [[ "$(cat "$stamp" 2>/dev/null)" != "$want_stamp" ]]; then
  "$LAB_DIR/scripts/get-model.sh" --verify
  echo "$want_stamp" >"$stamp"
fi

if llama_curl /health >/dev/null 2>&1; then
  die "a model server is already running (make model-down first)"
fi

# Common llama-server arguments. --offline and the absence of --tools / MCP flags keep
# the server's own (experimental) agent features off.
server_args=(
  --alias "$(basename "$model" .gguf)"
  --ctx-size "$LLAMA_CTX" --parallel 1
  --jinja
  --no-ui --no-slots --no-ui-mcp-proxy --offline
)
# shellcheck disable=SC2206
server_args+=($LLAMA_EXTRA_ARGS)

# The sandbox / container can read templates/ and nothing else outside models/.
tmpl=""
if [[ -n "$LLAMA_CHAT_TEMPLATE" ]]; then
  [[ "$LLAMA_CHAT_TEMPLATE" == templates/* && "$LLAMA_CHAT_TEMPLATE" != *..* ]] \
    || die "LLAMA_CHAT_TEMPLATE must be a file inside templates/ (got '$LLAMA_CHAT_TEMPLATE')"
  [[ -f "$LAB_DIR/$LLAMA_CHAT_TEMPLATE" ]] || die "chat template $LLAMA_CHAT_TEMPLATE not found"
  tmpl="$LLAMA_CHAT_TEMPLATE"
fi

info "Backend: $b"
info "Model:   $MODEL_FILE ($MODEL_REPO @ ${MODEL_COMMIT:0:12})"
info "Chat template: ${tmpl:-embedded in the model}"

wait_healthy() {   # wait_healthy CHECK_ALIVE_CMD...
  local _
  for _ in $(seq 1 180); do
    if llama_curl /health >/dev/null 2>&1; then return 0; fi
    "$@" >/dev/null 2>&1 || return 1
    sleep 1
  done
  return 1
}

# ------------------------------------------------------------------ macOS / Metal
if [[ "$b" == "metal" ]]; then
  bin="$(llama_bin)"
  [[ -x "$bin" ]] || die "llama-server is not built yet. Run: make llama"
  profile="$RUN_DIR/llama-server.sb"
  render_llama_profile "$profile"
  write_endpoint
  # env -i: start from an empty environment so no LLAMA_ARG_* variable can switch on
  # features behind the command line's back.
  cmd=(env -i PATH=/usr/bin:/bin HOME="$HOME" TMPDIR="${TMPDIR:-/private/tmp}"
       /usr/bin/sandbox-exec -f "$profile" "$bin"
       --model "$model" --host "$LLAMA_HOST" --port "$LLAMA_PORT"
       --n-gpu-layers 99 --api-key-file "$RUN_DIR/llama.key"
       "${server_args[@]}")
  [[ -n "$tmpl" ]] && cmd+=(--chat-template-file "$LAB_DIR/$tmpl")
  info "Sandbox: $profile"
  info "Serving: http://$LLAMA_HOST:$LLAMA_PORT (API key in .run/llama.key)"
  if [[ "$mode" == "--background" ]]; then
    nohup "${cmd[@]}" >>"$LAB_DIR/logs/llama-server.log" 2>&1 &
    echo $! >"$RUN_DIR/llama.pid"
    if wait_healthy kill -0 "$(cat "$RUN_DIR/llama.pid")"; then
      ok "llama-server is up (pid $(cat "$RUN_DIR/llama.pid")); log: logs/llama-server.log"; exit 0
    fi
    tail -n 30 "$LAB_DIR/logs/llama-server.log" >&2
    die "llama-server did not become healthy; see logs/llama-server.log"
  fi
  "${cmd[@]}" 2>&1 | tee -a "$LAB_DIR/logs/llama-server.log"
  exit 0
fi

# ------------------------------------------------------------------ Linux / container
need docker "Install Docker Engine: https://docs.docker.com/engine/install/"
docker image inspect "$(llama_image)" >/dev/null 2>&1 || die "image $(llama_image) not built. Run: make llama"
docker rm -f "$LLAMA_CONTAINER" >/dev/null 2>&1 || true
rm -f "$(llama_sock)"
llama_run_flags
ngl=99; [[ "$b" == "cpu" ]] && ngl=0
write_endpoint
run=(docker run --rm --init --name "$LLAMA_CONTAINER" "${LLAMA_RUN_FLAGS[@]}"
     "$(llama_image)"
     --model "/models/$MODEL_FILE" --host /sock/llama.sock --port 8080
     --n-gpu-layers "$ngl" --api-key-file /run/secrets/llama.key
     "${server_args[@]}")
[[ -n "$tmpl" ]] && run+=(--chat-template-file "/$tmpl")
info "Serving: unix socket $(llama_sock) (container has no network interfaces besides loopback)"
if [[ "$mode" == "--background" ]]; then
  "${run[0]}" "${run[1]}" -d "${run[@]:2}" >/dev/null
  if wait_healthy docker inspect -f '{{.State.Running}}' "$LLAMA_CONTAINER"; then
    if [[ "$b" == "cuda" ]] && ! docker logs "$LLAMA_CONTAINER" 2>&1 | grep -qi "CUDA"; then
      warn "llama-server is up but its log doesn't mention CUDA: check 'docker logs $LLAMA_CONTAINER'"
    fi
    ok "llama-server is up in container $LLAMA_CONTAINER (logs: docker logs -f $LLAMA_CONTAINER)"; exit 0
  fi
  docker logs --tail 30 "$LLAMA_CONTAINER" >&2 || true
  die "llama-server did not become healthy"
fi
exec "${run[@]}"
