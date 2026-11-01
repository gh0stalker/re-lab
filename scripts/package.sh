#!/usr/bin/env bash
# Package the files needed to run the lab into dist/re-lab-<date>-<time>.tar.gz.
#
# The archive is built from an explicit list (below), not by excluding things, so
# samples, models, Ghidra projects, logs, the llama.cpp build, virtualenvs and runtime
# state can never end up in it, whatever else is in the folder. Unpack it anywhere
# and run `make all` to rebuild the rest.
source "$(dirname "$0")/lib.sh"

files=(
  Makefile README.md config.env .gitignore
  agent/agent.py agent/system_prompt.md agent/requirements.in agent/requirements.lock
  ghidra/Dockerfile ghidra/requirements.in ghidra/requirements.lock
  llama/Dockerfile
  sandbox/llama-server.sb
  tests/fuzz_agent.py
  .githooks/pre-commit
  .github/workflows/ci.yml
)
# ...plus every script and every chat template.
for f in "$LAB_DIR"/scripts/*.sh "$LAB_DIR"/scripts/*.py "$LAB_DIR"/templates/*; do
  [[ -f "$f" ]] && files+=("${f#"$LAB_DIR/"}")
done

missing=()
for f in "${files[@]}"; do [[ -f "$LAB_DIR/$f" ]] || missing+=("$f"); done
(( ${#missing[@]} == 0 )) || die "missing from the lab folder: ${missing[*]}"

stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
for f in "${files[@]}"; do
  mkdir -p "$stage/re-lab/$(dirname "$f")"
  # -p keeps the executable bits; -X (macOS) leaves out extended attributes such as quarantine flags
  if is_macos; then cp -pX "$LAB_DIR/$f" "$stage/re-lab/$f"; else cp -p "$LAB_DIR/$f" "$stage/re-lab/$f"; fi
done

mkdir -p "$LAB_DIR/dist"
out="$LAB_DIR/dist/re-lab-$(date +%Y%m%d-%H%M%S).tar.gz"
# COPYFILE_DISABLE: stop macOS tar from adding ._ metadata files
COPYFILE_DISABLE=1 tar -czf "$out" -C "$stage" re-lab

# Double-check the result rather than trusting the list.
contents="$(tar -tzf "$out")"
if grep -E '^re-lab/(samples|projects|models|logs|vendor|dist|symbols|\.run)/.|\.venv/|__pycache__|(^|/)\._' <<<"$contents"; then
  rm -f "$out"
  die "the archive contained the files above, which must not be packaged; nothing was written"
fi

info "Contents:"
sed -n 's|^re-lab/||p' <<<"$contents" | grep -v '/$' | grep -v '^$' | sort | sed 's/^/    /'
ok "${out#"$LAB_DIR/"}  ($(du -h "$out" | cut -f1 | tr -d ' '), ${#files[@]} files)"
echo "     sha256 $(sha256 "$out")"
echo "     to use it: tar -xzf $(basename "$out") && cd re-lab && make all"
