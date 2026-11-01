# llama-server for Linux hosts: NVIDIA GPUs (BACKEND=cuda) or plain CPU (BACKEND=cpu).
# macOS does not use this image; there llama-server runs natively under Seatbelt.
#
# The network is used only while building (apt, git clone of the pinned tag).
# scripts/start-model.sh runs the container with --network none, a read-only root
# filesystem and no capabilities. Its only channel is a Unix socket in .run/sock/.
#
# Build with scripts/build-llama.sh (it passes the pins from config.env).

ARG BACKEND=cuda
ARG CUDA_VERSION=12.8.1
ARG UBUNTU_VERSION=24.04
ARG BUILD_BASE=nvidia/cuda:${CUDA_VERSION}-devel-ubuntu${UBUNTU_VERSION}
ARG RUNTIME_BASE=nvidia/cuda:${CUDA_VERSION}-runtime-ubuntu${UBUNTU_VERSION}

# --------------------------------------------------------------------- build
FROM ${BUILD_BASE} AS build
ARG BACKEND
ARG LLAMA_CPP_TAG
ARG LLAMA_CPP_COMMIT
# GPU generations to compile kernels for: Turing (75) through Blackwell (120).
# Set CUDA_ARCHS in config.env to just your card (e.g. 89 for RTX 40xx, 120 for RTX 50xx)
# to cut build time several-fold.
ARG CUDA_ARCHS="75;80;86;89;90;120"
# ON tunes the CPU code for the machine doing the build, which is also the machine
# that runs it in this setup. Use OFF if you build on one host and run on another.
ARG GGML_NATIVE=ON

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates git cmake build-essential \
 && rm -rf /var/lib/apt/lists/*

RUN test -n "$LLAMA_CPP_TAG" && test -n "$LLAMA_CPP_COMMIT" \
 && git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$LLAMA_CPP_TAG" \
      https://github.com/ggml-org/llama.cpp /src \
 && test "$(git -C /src rev-parse HEAD)" = "$LLAMA_CPP_COMMIT" \
 || { echo "llama.cpp tag $LLAMA_CPP_TAG does not match pinned commit $LLAMA_CPP_COMMIT" >&2; exit 1; }

# LLAMA_OPENSSL=OFF        : no HTTPS client in the binary, so it cannot download anything
# LLAMA_USE_PREBUILT_UI=OFF: don't fetch the web UI from Hugging Face during the build
RUN set -eu; \
    extra=""; \
    if [ "$BACKEND" = cuda ]; then \
      extra="-DGGML_CUDA=ON -DCMAKE_CUDA_ARCHITECTURES=${CUDA_ARCHS} -DCMAKE_EXE_LINKER_FLAGS=-Wl,--allow-shlib-undefined"; \
    fi; \
    cmake -S /src -B /src/build -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_SHARED_LIBS=OFF -DGGML_NATIVE="$GGML_NATIVE" \
      -DLLAMA_OPENSSL=OFF -DLLAMA_USE_PREBUILT_UI=OFF -DLLAMA_BUILD_UI=OFF \
      -DLLAMA_BUILD_TESTS=OFF -DLLAMA_BUILD_EXAMPLES=OFF -DLLAMA_BUILD_SERVER=ON \
      $extra; \
    cmake --build /src/build --target llama-server -j"$(nproc)"

# ------------------------------------------------------------------- runtime
FROM ${RUNTIME_BASE} AS runtime
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends libgomp1 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/build/bin/llama-server /usr/local/bin/llama-server
ENTRYPOINT ["/usr/local/bin/llama-server"]
