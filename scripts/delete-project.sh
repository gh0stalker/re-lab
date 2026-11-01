#!/usr/bin/env bash
# Delete a Ghidra project from projects/: its database, the pyghidra-mcp search index
# and the record of which samples it imported. Files in samples/ are not touched.
#
#   scripts/delete-project.sh NAME          asks before deleting
#   scripts/delete-project.sh NAME --yes    no question
source "$(dirname "$0")/lib.sh"

name="${1:-}"
[[ -n "$name" ]] || die "usage: scripts/delete-project.sh NAME [--yes]   (make projects lists them)"
[[ "$name" =~ ^[A-Za-z0-9_.-]+$ ]] || die "project names only contain letters, digits, . _ -"

if command -v docker >/dev/null 2>&1 && [[ -n "$(docker ps -q -f "name=^re-lab-ghidra-${name}$" 2>/dev/null)" ]]; then
  die "project '$name' is open in a running session (container re-lab-ghidra-$name). Quit that agent first."
fi

targets=()
for p in "$name.gpr" "$name.rep" "$name.lock" "$name.lock~" "$name-pyghidra-mcp" "$name.re-lab-imported"; do
  [[ -e "$LAB_DIR/projects/$p" ]] && targets+=("$LAB_DIR/projects/$p")
done
(( ${#targets[@]} )) || die "no project '$name' in projects/ (make projects lists them)"

info "This deletes project '$name':"
for t in "${targets[@]}"; do
  printf '    projects/%s  (%s)\n' "${t#"$LAB_DIR/projects/"}" "$(du -sh "$t" 2>/dev/null | cut -f1)"
done
if [[ "$GHIDRA_PROJECT" == "$name" ]]; then
  warn "'$name' is GHIDRA_PROJECT in config.env; the next 'make agent' will recreate it empty, importing whatever is in samples/"
fi

if [[ "${2:-}" != "--yes" ]]; then
  read -r -p "Delete? [y/N] " answer
  [[ "$answer" == "y" || "$answer" == "Y" ]] || { info "nothing deleted"; exit 0; }
fi
rm -rf "${targets[@]}"
ok "deleted project '$name'"
