#!/usr/bin/env bash
# One-time setup: check prerequisites for this OS, create the lab folders, and build
# the agent's Python environment from hash-pinned packages.
source "$(dirname "$0")/lib.sh"

b="$(backend)"
info "OS: $(uname -s) $(uname -m), model backend: $b"

# ---------------------------------------------------------------- prerequisites
missing=0
req() { if command -v "$1" >/dev/null 2>&1; then ok "$1"; else warn "missing $1: $2"; missing=1; fi; }

req git    "$(is_macos && echo 'xcode-select --install' || echo 'install with your package manager')"
req curl   "install with your package manager"
req docker "$(is_macos && echo 'install Docker Desktop or OrbStack' || echo 'https://docs.docker.com/engine/install/')"
case "$b" in
  metal)
    req cmake "brew install cmake"
    xcode-select -p >/dev/null 2>&1 && ok "Xcode Command Line Tools" \
      || { warn "missing Xcode Command Line Tools: xcode-select --install"; missing=1; }
    [[ -x /usr/bin/sandbox-exec ]] && ok "sandbox-exec" || { warn "/usr/bin/sandbox-exec not found"; missing=1; }
    ;;
  cuda)
    req nvidia-smi "install the NVIDIA driver (570 or newer for CUDA $CUDA_VERSION)"
    if command -v nvidia-smi >/dev/null 2>&1; then
      info "GPU: $(nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv,noheader | head -1)"
    fi
    if docker info -f '{{json .Runtimes}}' 2>/dev/null | grep -q nvidia || [[ -d /etc/cdi || -d /var/run/cdi ]]; then
      ok "NVIDIA Container Toolkit"
    else
      warn "Docker has no nvidia runtime: install the NVIDIA Container Toolkit and run 'sudo nvidia-ctk runtime configure --runtime=docker && sudo systemctl restart docker'"
      missing=1
    fi
    ;;
  cpu)
    warn "no NVIDIA GPU detected: the model will run on CPU (slow). Set LLAMA_BACKEND in config.env to override."
    ;;
esac
if command -v docker >/dev/null 2>&1; then
  if docker info >/dev/null 2>&1; then ok "docker daemon reachable"
  else warn "docker is installed but not reachable (not running, or your user is not in the docker group)"; missing=1; fi
fi

# ---------------------------------------------------------------- folders
mkdir -p "$LAB_DIR"/{samples,projects,logs,models}
ensure_run_dir
[[ -f "$LAB_DIR/samples/README.txt" ]] || cat >"$LAB_DIR/samples/README.txt" <<'EOF'
Put the binaries you want to analyse here. The folder is mounted read-only into the
Ghidra container; nothing in it is ever executed. Files starting with "." or "README"
are ignored.
EOF
ok "folders: samples/ projects/ logs/ models/ .run/"

# ---------------------------------------------------------------- agent venv
venv="$LAB_DIR/agent/.venv"
lock="$LAB_DIR/agent/requirements.lock"
if [[ ! -x "$venv/bin/python" ]]; then
  if command -v uv >/dev/null 2>&1; then
    info "Creating agent environment with uv (Python 3.12)"
    uv venv --quiet --python 3.12 "$venv"
  else
    py=""
    for c in python3.13 python3.12 python3.11 python3.10 python3; do
      if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(sys.version_info < (3, 10))'; then
        py="$c"; break
      fi
    done
    [[ -n "$py" ]] || die "need Python 3.10+ for the agent (macOS: brew install uv, or brew install python@3.12)"
    info "Creating agent environment with $py"
    "$py" -m venv "$venv"
  fi
fi
info "Installing hash-pinned agent packages"
if command -v uv >/dev/null 2>&1; then
  uv pip install --quiet --python "$venv/bin/python" --require-hashes --only-binary=:all: -r "$lock"
else
  "$venv/bin/python" -m pip install --quiet --require-hashes --only-binary=:all: -r "$lock"
fi
ok "agent environment: agent/.venv"

if (( missing )); then
  warn "fix the items above, then re-run: make setup"
  exit 1
fi
ok "setup complete. Next: make llama model ghidra"
