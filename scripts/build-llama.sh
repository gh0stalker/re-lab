#!/usr/bin/env bash
# Build llama-server for the active backend (see LLAMA_BACKEND in config.env).
#   metal     : native build on macOS (scripts/get-llama.sh)
#   cuda, cpu : container image llama/Dockerfile
source "$(dirname "$0")/lib.sh"
b="$(backend)"
info "backend: $b"

if [[ "$b" == "metal" ]]; then
  exec "$LAB_DIR/scripts/get-llama.sh"
fi

need docker "Install Docker Engine: https://docs.docker.com/engine/install/"
docker info >/dev/null 2>&1 || die "Docker is installed but not running (or your user is not in the docker group)"

args=(--build-arg BACKEND="$b"
      --build-arg LLAMA_CPP_TAG="$LLAMA_CPP_TAG"
      --build-arg LLAMA_CPP_COMMIT="$LLAMA_CPP_COMMIT")
if [[ "$b" == "cuda" ]]; then
  if ! docker info -f '{{json .Runtimes}}' 2>/dev/null | grep -q nvidia \
     && [[ ! -d /etc/cdi && ! -d /var/run/cdi ]]; then
    warn "Docker doesn't list an nvidia runtime. Install the NVIDIA Container Toolkit:"
    warn "  https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/install-guide.html"
  fi
  if command -v nvidia-smi >/dev/null 2>&1; then
    drv="$(nvidia-smi --query-gpu=driver_version --format=csv,noheader 2>/dev/null | head -1)"
    info "GPU: $(nvidia-smi --query-gpu=name,memory.total --format=csv,noheader | head -1), driver $drv"
  fi
  args+=(--build-arg CUDA_VERSION="$CUDA_VERSION" --build-arg CUDA_ARCHS="$CUDA_ARCHS")
  info "CUDA build for compute capabilities $CUDA_ARCHS (narrow CUDA_ARCHS in config.env to speed this up)"
else
  args+=(--build-arg BUILD_BASE=ubuntu:24.04 --build-arg RUNTIME_BASE=ubuntu:24.04)
fi

info "Building $(llama_image)"
docker build "${args[@]}" -t "$(llama_image)" "$LAB_DIR/llama"
ok "built $(llama_image)"
