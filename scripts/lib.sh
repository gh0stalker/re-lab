# shellcheck shell=bash
# Shared helpers. Sourced by every script in scripts/. Written for bash 3.2 (macOS's
# /bin/bash) as well as modern bash on Linux.

set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
export LAB_DIR
# shellcheck source=../config.env
source "$LAB_DIR/config.env"

RUN_DIR="$LAB_DIR/.run"            # runtime state: api key, sandbox profile, socket, pid
VENDOR_DIR="$LAB_DIR/vendor"       # llama.cpp source + native build (macOS)
MODELS_DIR="$LAB_DIR/models"
SOCK_DIR="$RUN_DIR/sock"           # cuda/cpu: llama-server's Unix socket lives here
# shellcheck disable=SC2034  # used by the scripts that source this file
LLAMA_CONTAINER="re-lab-llama"

if [[ -t 1 ]]; then
  _b=$'\033[1m'; _g=$'\033[32m'; _y=$'\033[33m'; _r=$'\033[31m'; _n=$'\033[0m'
else
  _b=""; _g=""; _y=""; _r=""; _n=""
fi
info() { printf '%s==>%s %s\n' "$_b" "$_n" "$*"; }
ok()   { printf '%s ok %s %s\n' "$_g" "$_n" "$*"; }
warn() { printf '%swarn%s %s\n' "$_y" "$_n" "$*" >&2; }
die()  { printf '%sfail%s %s\n' "$_r" "$_n" "$*" >&2; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "missing '$1'. $2"; }

sha256() {
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  else sha256sum "$1" | awk '{print $1}'; fi
}

is_macos() { [[ "$(uname -s)" == "Darwin" ]]; }
ncpu() { sysctl -n hw.ncpu 2>/dev/null || nproc; }
file_mtime() { stat -f %m "$1" 2>/dev/null || stat -c %Y "$1"; }
file_size()  { stat -f %z "$1" 2>/dev/null || stat -c %s "$1"; }

# ---------------------------------------------------------------- backend
backend() {
  local b="${LLAMA_BACKEND:-auto}"
  if [[ "$b" == "auto" ]]; then
    if is_macos; then b=metal
    elif command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L >/dev/null 2>&1; then b=cuda
    else b=cpu; fi
  fi
  case "$b" in
    metal) is_macos || die "LLAMA_BACKEND=metal only works on macOS" ;;
    cuda|cpu) is_macos && die "LLAMA_BACKEND=$b is for Linux hosts; on macOS use metal (Docker on a Mac has no GPU and can't share the socket)" ;;
    *) die "LLAMA_BACKEND must be auto, metal, cuda or cpu (got '$b')" ;;
  esac
  echo "$b"
}

llama_bin() { echo "$VENDOR_DIR/llama.cpp/build/bin/llama-server"; }
llama_image() { echo "$LLAMA_IMAGE-$(backend)"; }   # separate tags for cuda and cpu builds
llama_sock() { echo "$SOCK_DIR/llama.sock"; }

# curl against the model server, whichever transport the backend uses
llama_curl() {
  local path="$1"; shift
  if [[ "$(backend)" == "metal" ]]; then
    curl -fsS -m 3 "$@" "http://$LLAMA_HOST:$LLAMA_PORT$path"
  else
    curl -fsS -m 3 --unix-socket "$(llama_sock)" "$@" "http://localhost$path"
  fi
}

model_path() {
  [[ -f "$MODELS_DIR/MODEL.lock" ]] || die "no model yet. Run: make model"
  # shellcheck disable=SC1091
  ( source "$MODELS_DIR/MODEL.lock"; echo "$MODELS_DIR/$MODEL_FILE" )
}

ensure_run_dir() { mkdir -p "$RUN_DIR" "$SOCK_DIR"; chmod 700 "$RUN_DIR" "$SOCK_DIR"; }

ensure_api_key() {
  ensure_run_dir
  if [[ ! -s "$RUN_DIR/llama.key" ]]; then
    ( umask 077; python3 -c 'import secrets; print(secrets.token_hex(32))' >"$RUN_DIR/llama.key" )
  fi
}

# Written by start-model.sh, read by the agent: how to reach the model server.
write_endpoint() {
  if [[ "$(backend)" == "metal" ]]; then
    printf 'LLAMA_ENDPOINT_KIND="tcp"\nLLAMA_ENDPOINT="http://%s:%s"\n' "$LLAMA_HOST" "$LLAMA_PORT"
  else
    printf 'LLAMA_ENDPOINT_KIND="unix"\nLLAMA_ENDPOINT="%s"\n' "$(llama_sock)"
  fi >"$RUN_DIR/llama.endpoint"
}

# ---------------------------------------------------------------- metal sandbox
# render_llama_profile OUT [EXTRA_EXECUTABLE...]
# Fills sandbox/llama-server.sb. Extra executables are only used by verify.sh to run
# probe commands (curl, cat, ...) under exactly the same rules as the model server.
render_llama_profile() {
  local out="$1"; shift
  local home extra="" p
  home="$(cd "$HOME" && pwd -P)"
  for p in "$LAB_DIR" "$home" "$(llama_bin)" "$@"; do
    [[ "$p" != *'"'* && "$p" != *'|'* ]] || die "paths containing \" or | are not supported: $p"
  done
  for p in "$@"; do extra="$extra (literal \"$p\")"; done
  sed -e "s|@PORT@|$LLAMA_PORT|g" \
      -e "s|@LAB_DIR@|$LAB_DIR|g" \
      -e "s|@HOME@|$home|g" \
      -e "s|@LLAMA_BIN@|$(llama_bin)|g" \
      -e "s|@EXTRA_EXEC@|$extra|g" \
      "$LAB_DIR/sandbox/llama-server.sb" >"$out"
}

# ---------------------------------------------------------------- container flags
# Both containers are started from these arrays so that verify.sh probes exactly the
# isolation the real runs get. Containers run as your own uid so bind mounts work on
# Linux without chown games.

# llama_run_flags: sets LLAMA_RUN_FLAGS (cuda/cpu backends)
llama_run_flags() {
  # shellcheck disable=SC2054  # the commas are tmpfs mount options
  LLAMA_RUN_FLAGS=(
    --network none
    --read-only --tmpfs /tmp:rw,nosuid,nodev,size=512m
    --cap-drop ALL --security-opt no-new-privileges
    --user "$(id -u):$(id -g)"
    --pids-limit 512
    -v "$MODELS_DIR:/models:ro"
    -v "$LAB_DIR/templates:/templates:ro"
    -v "$RUN_DIR/llama.key:/run/secrets/llama.key:ro"
    -v "$SOCK_DIR:/sock"
  )
  if [[ "$(backend)" == "cuda" ]]; then LLAMA_RUN_FLAGS+=(--gpus "$LLAMA_GPUS"); fi
}

# ghidra_run_flags: sets GHIDRA_RUN_FLAGS
ghidra_run_flags() {
  local cpus="$GHIDRA_CPUS" have
  have="$(docker info -f '{{.NCPU}}' 2>/dev/null || echo "$cpus")"
  if (( have < cpus )); then cpus="$have"; fi     # docker refuses --cpus above the VM's count
  # shellcheck disable=SC2054  # the commas are tmpfs mount options
  GHIDRA_RUN_FLAGS=(
    --network none
    --read-only --tmpfs /tmp:rw,nosuid,nodev,size=4g
    --cap-drop ALL --security-opt no-new-privileges
    --user "$(id -u):$(id -g)"
    --pids-limit 2048 --memory "$GHIDRA_MEM" --memory-swap "$GHIDRA_MEM" --cpus "$cpus"
    -e JAVA_TOOL_OPTIONS="-Xmx$GHIDRA_HEAP"
    -v "$LAB_DIR/samples:/samples:ro"
    -v "$LAB_DIR/projects:/projects"
  )
  if [[ "$GHIDRA_SYMBOLS" == "local" ]]; then
    mkdir -p "$LAB_DIR/symbols"
    GHIDRA_RUN_FLAGS+=(-v "$LAB_DIR/symbols:/symbols")
  fi
}
