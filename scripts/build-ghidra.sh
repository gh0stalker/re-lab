#!/usr/bin/env bash
# Build the Ghidra + pyghidra-mcp image. This is the only step of the Ghidra side
# that touches the network; the container never does.
source "$(dirname "$0")/lib.sh"
need docker "Install Docker Desktop (or OrbStack / Colima) first"
docker info >/dev/null 2>&1 || die "Docker is installed but not running"

grep -q "^pyghidra-mcp==$PYGHIDRA_MCP_VERSION " "$LAB_DIR/ghidra/requirements.lock" \
  || die "ghidra/requirements.lock does not pin pyghidra-mcp==$PYGHIDRA_MCP_VERSION (see README: re-locking)"

arch="$(docker info -f '{{.Architecture}}')"
mem_gib=$(( $(docker info -f '{{.MemTotal}}') / 1024 / 1024 / 1024 ))
want_gib="${GHIDRA_MEM%g}"
if (( mem_gib < want_gib )); then
  warn "Docker's VM has ${mem_gib} GiB but GHIDRA_MEM=$GHIDRA_MEM. Raise it in Docker settings or lower GHIDRA_MEM."
fi
[[ "$arch" == "aarch64" || "$arch" == "arm64" ]] && \
  info "arm64 build: Ghidra's native decompiler gets compiled from source (adds a few minutes)"

info "Building $GHIDRA_IMAGE for $arch"
docker build \
  --build-arg GHIDRA_VERSION="$GHIDRA_VERSION" \
  --build-arg GHIDRA_DATE="$GHIDRA_DATE" \
  --build-arg GHIDRA_SHA256="$GHIDRA_SHA256" \
  -t "$GHIDRA_IMAGE" "$LAB_DIR/ghidra"
ok "built $GHIDRA_IMAGE"
