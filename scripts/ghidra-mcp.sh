#!/usr/bin/env bash
# Run pyghidra-mcp in its locked-down container and speak MCP over stdin/stdout.
# The agent launches this; you can also point any stdio MCP client at it.
#
# stdout carries MCP JSON-RPC, so everything this script prints goes to stderr.
#
#   scripts/ghidra-mcp.sh [--project NAME]
#
# Every file under samples/ is imported (read-only mount). Analysis results live in
# projects/ and are reused next time.
source "$(dirname "$0")/lib.sh"
exec 3>&1 1>&2   # fd 3 = the real stdout (for docker); our own messages go to stderr

project="$GHIDRA_PROJECT"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --project) project="$2"; shift 2 ;;
    *) die "unknown argument: $1" ;;
  esac
done
[[ "$project" =~ ^[A-Za-z0-9_.-]+$ ]] || die "project name may only contain letters, digits, . _ -"

need docker "Install Docker (Docker Desktop / OrbStack on macOS, Docker Engine on Linux)"
docker image inspect "$GHIDRA_IMAGE" >/dev/null 2>&1 || die "image $GHIDRA_IMAGE not built. Run: make ghidra"
mkdir -p "$LAB_DIR/samples" "$LAB_DIR/projects"

# Pass only samples this project hasn't imported yet. pyghidra-mcp 0.2.7 rebuilds a
# binary's whole code index when an already-imported file is passed again, and
# decompile requests stall while that runs. The list is keyed by content hash, so
# renaming a sample doesn't re-import it. Delete the .re-lab-imported file to start over.
manifest="$LAB_DIR/projects/$project.re-lab-imported"
[[ -f "$LAB_DIR/projects/$project.gpr" ]] || rm -f "$manifest"
touch "$manifest"
inputs=()
while IFS= read -r -d '' f; do
  rel="${f#"$LAB_DIR/samples/"}"
  h="$(sha256 "$f")"
  if grep -q "^$h " "$manifest"; then continue; fi
  inputs+=("/samples/$rel")
  printf '%s %s\n' "$h" "$rel" >>"$manifest"
done < <(find "$LAB_DIR/samples" -type f ! -name '.*' ! -name 'README*' -print0 | sort -z)

# "off" also stops pyghidra-mcp from configuring Microsoft's public symbol server
# (which would leak PDB GUIDs of your samples if the container ever had a network).
sym_args=(--no-symbols)
[[ "$GHIDRA_SYMBOLS" == "local" ]] && sym_args=(--symbols-path /symbols)

name="re-lab-ghidra-$project"
if [[ -n "$(docker ps -q -f "name=^${name}$")" ]]; then
  info "waiting up to 5 minutes for the previous $name container to finish saving ..."
  for _ in $(seq 1 150); do
    [[ -z "$(docker ps -q -f "name=^${name}$")" ]] && break
    sleep 2
  done
  [[ -z "$(docker ps -q -f "name=^${name}$")" ]] \
    || die "$name is still running. If it is stuck: docker stop $name (unsaved annotations from that session may be lost)"
fi

ghidra_run_flags
info "Ghidra MCP: project '$project', ${#inputs[@]} new sample(s) to import, no network"
# --sig-proxy=false: when the client hangs up, the server sees EOF on stdin and saves
# the project cleanly instead of being killed mid-write by a forwarded SIGTERM.
exec docker run --rm -i --init --sig-proxy=false --name "$name" \
  "${GHIDRA_RUN_FLAGS[@]}" \
  "$GHIDRA_IMAGE" \
  -t stdio --project-path /projects --project-name "$project" "${sym_args[@]}" ${inputs[@]+"${inputs[@]}"} \
  1>&3
