#!/usr/bin/env bash
# List the Ghidra projects in projects/ with their size and the samples each one imported.
source "$(dirname "$0")/lib.sh"

shopt -s nullglob
gprs=("$LAB_DIR"/projects/*.gpr)
(( ${#gprs[@]} )) || { info "no projects yet (make agent creates '$GHIDRA_PROJECT')"; exit 0; }

for gpr in "${gprs[@]}"; do
  name="$(basename "$gpr" .gpr)"
  size="$(du -shc "$LAB_DIR/projects/$name.rep" "$LAB_DIR/projects/$name-pyghidra-mcp" 2>/dev/null | tail -1 | cut -f1)"
  marker=""; [[ "$name" == "$GHIDRA_PROJECT" ]] && marker="  (default, GHIDRA_PROJECT)"
  printf '%s  %s\n' "$name" "$size$marker"
  manifest="$LAB_DIR/projects/$name.re-lab-imported"
  if [[ -s "$manifest" ]]; then
    while read -r hash file; do printf '    %s  sha256 %s...\n' "$file" "${hash:0:12}"; done <"$manifest"
  else
    printf '    (no import record)\n'
  fi
done
