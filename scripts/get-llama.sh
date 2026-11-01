#!/usr/bin/env bash
# Build llama-server from source at the pinned tag (Metal backend on Apple Silicon).
# Built locally, so there is no unsigned downloaded binary to trust or un-quarantine.
source "$(dirname "$0")/lib.sh"

need git   "Install the Xcode Command Line Tools: xcode-select --install"
need cmake "Install it with: brew install cmake"
is_macos || warn "not macOS: this builds without Metal (fine for testing, slow for real use)"

src="$VENDOR_DIR/llama.cpp"
mkdir -p "$VENDOR_DIR"
if [[ ! -d "$src/.git" ]]; then
  info "Cloning llama.cpp $LLAMA_CPP_TAG"
  git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$LLAMA_CPP_TAG" \
      https://github.com/ggml-org/llama.cpp "$src"
else
  info "Switching existing checkout to $LLAMA_CPP_TAG"
  git -C "$src" fetch --quiet --depth 1 origin tag "$LLAMA_CPP_TAG"
  git -C "$src" -c advice.detachedHead=false checkout --quiet "$LLAMA_CPP_TAG"
fi

actual="$(git -C "$src" rev-parse HEAD)"
[[ "$actual" == "$LLAMA_CPP_COMMIT" ]] \
  || die "tag $LLAMA_CPP_TAG resolves to $actual but config.env pins $LLAMA_CPP_COMMIT"
ok "llama.cpp $LLAMA_CPP_TAG = $actual"

info "Building llama-server (a few minutes)"
# LLAMA_OPENSSL=OFF        : no HTTPS client in the binary, so it cannot download models
#                            (the sandbox blocks the network anyway; this is a second layer)
# LLAMA_USE_PREBUILT_UI=OFF: don't fetch the web UI from Hugging Face during the build
cmake -S "$src" -B "$src/build" -DCMAKE_BUILD_TYPE=Release \
  -DLLAMA_OPENSSL=OFF -DLLAMA_USE_PREBUILT_UI=OFF -DLLAMA_BUILD_UI=OFF \
  -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF -DLLAMA_BUILD_SERVER=ON \
  >/dev/null
cmake --build "$src/build" --target llama-server -j "$(ncpu)" >/dev/null

"$(llama_bin)" --version 2>&1 | tail -2
ok "built $(llama_bin)"
