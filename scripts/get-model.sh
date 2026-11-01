#!/usr/bin/env bash
# Download the GGUF model once, pinned to a commit, and verify it against the
# SHA-256 that Hugging Face publishes for the file (its LFS object id).
#
#   scripts/get-model.sh            download (or re-verify if already present)
#   scripts/get-model.sh --verify   only re-hash the local file against models/MODEL.lock
source "$(dirname "$0")/lib.sh"
need curl    "curl ships with macOS"
need python3 "python3 ships with the Xcode Command Line Tools"
mkdir -p "$MODELS_DIR"
lock="$MODELS_DIR/MODEL.lock"

verify_lock() {
  # shellcheck disable=SC1090
  source "$lock"
  local f="$MODELS_DIR/$MODEL_FILE"
  [[ -f "$f" ]] || die "$f is missing (re-run without --verify)"
  info "Hashing $MODEL_FILE"
  local got; got="$(sha256 "$f")"
  [[ "$got" == "$MODEL_SHA256" ]] || die "SHA-256 mismatch for $MODEL_FILE: got $got, lock says $MODEL_SHA256"
  ok "$MODEL_FILE matches $lock ($MODEL_REPO @ ${MODEL_COMMIT:0:12})"
}

if [[ "${1:-}" == "--verify" ]]; then verify_lock; exit 0; fi
if [[ -f "$lock" ]]; then
  info "models/MODEL.lock exists; verifying instead of downloading (delete it to re-download)"
  verify_lock; exit 0
fi

api="https://huggingface.co/api/models/$MODEL_REPO"
info "Resolving $MODEL_REPO @ $MODEL_REVISION"
commit="$(curl -fsSL "$api/revision/$MODEL_REVISION" | python3 -c 'import json,sys; print(json.load(sys.stdin)["sha"])')" \
  || die "could not resolve $MODEL_REPO@$MODEL_REVISION (repo name wrong, or no network?)"
tree="$(curl -fsSL "$api/tree/$commit")" || die "could not list files in $MODEL_REPO@$commit"

# Pick the first quant from MODEL_QUANTS that exists as a single-file GGUF.
read -r file size oid < <(MODEL_QUANTS="$MODEL_QUANTS" python3 -c '
import json, os, re, sys
files = [f for f in json.loads(sys.stdin.read()) if f.get("type") == "file" and f["path"].lower().endswith(".gguf")]
files = [f for f in files if not re.search(r"-\d{5}-of-\d{5}", f["path"])]   # skip split files
for q in os.environ["MODEL_QUANTS"].split():
    for f in files:
        name = os.path.basename(f["path"])
        if re.search(r"(^|[^a-z0-9])" + re.escape(q.lower()) + r"([^a-z0-9]|$)", name.lower()) and f.get("lfs"):
            print(f["path"], f["lfs"]["size"], f["lfs"]["oid"]); sys.exit(0)
print("available:", ", ".join(os.path.basename(f["path"]) for f in files) or "none", file=sys.stderr)
sys.exit(1)
' <<<"$tree") || die "none of [$MODEL_QUANTS] found in $MODEL_REPO (see list above); edit MODEL_QUANTS in config.env"

name="$(basename "$file")"
info "Selected $name ($((size / 1024 / 1024)) MiB), expected sha256 $oid"
part="$MODELS_DIR/$name.part"
curl -fL --retry 3 -C - -o "$part" "https://huggingface.co/$MODEL_REPO/resolve/$commit/$file" \
  || die "download failed (re-run to resume)"

info "Verifying"
got="$(sha256 "$part")"
[[ "$got" == "$oid" ]] || die "SHA-256 mismatch: got $got, Hugging Face says $oid. Deleted nothing; inspect $part"
mv "$part" "$MODELS_DIR/$name"

cat >"$lock" <<EOF
# Written by scripts/get-model.sh. The model is only ever loaded if it still matches this.
MODEL_REPO="$MODEL_REPO"
MODEL_COMMIT="$commit"
MODEL_FILE="$name"
MODEL_SHA256="$oid"
MODEL_BYTES="$size"
DOWNLOADED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
EOF
ok "saved models/$name and models/MODEL.lock"
