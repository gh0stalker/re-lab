# Headless Ghidra + pyghidra-mcp for an offline reverse-engineering lab.
#
# The network is used ONLY while building this image (apt, the Ghidra release,
# Python wheels, Gradle on arm64, and Chroma's embedding model). At runtime the
# container is started by scripts/ghidra-mcp.sh with --network none, a read-only
# root filesystem, no capabilities and a non-root user.
#
# Build with scripts/build-ghidra.sh (it passes the pinned values from config.env).

ARG BASE_IMAGE=ubuntu:24.04

# --------------------------------------------------------------------- build
FROM ${BASE_IMAGE} AS build

ARG GHIDRA_VERSION=12.1.4
ARG GHIDRA_DATE=20260921
ARG GHIDRA_SHA256=ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl unzip build-essential \
      openjdk-21-jdk-headless python3 python3-venv \
 && rm -rf /var/lib/apt/lists/*

# Ghidra release, checked against the SHA-256 published in its GitHub release notes.
RUN curl -fsSL -o /tmp/ghidra.zip \
      "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip" \
 && echo "${GHIDRA_SHA256}  /tmp/ghidra.zip" | sha256sum -c - \
 && unzip -q /tmp/ghidra.zip -d /opt \
 && mv "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC" /opt/ghidra \
 && rm /tmp/ghidra.zip

# Official releases ship native components (decompiler, demangler, lzfse) for
# linux_x86_64 only. On Apple Silicon Docker builds linux/arm64, so compile them
# here with Ghidra's own Gradle wrapper. Gradle writes them to each module's
# build/os/<platform>/; they are copied into os/<platform>/ (the layout a release
# uses) and Gradle's intermediate files are removed. The final `test` fails the
# build if the decompiler is still missing.
RUN set -eu; \
    case "$(uname -m)" in \
      x86_64)        plat=linux_x86_64 ;; \
      aarch64|arm64) plat=linux_arm_64 ;; \
      *) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;; \
    esac; \
    if [ ! -x "/opt/ghidra/Ghidra/Features/Decompiler/os/${plat}/decompile" ]; then \
      echo "Building Ghidra native components for ${plat} ..."; \
      cd /opt/ghidra/support/gradle && ./gradlew --no-daemon --console=plain buildNatives; \
      for built in $(find /opt/ghidra -type d -path "*/build/os/${plat}"); do \
        module="${built%/build/os/${plat}}"; \
        mkdir -p "${module}/os/${plat}"; \
        cp -a "${built}/." "${module}/os/${plat}/"; \
        rm -rf "${module}/build"; \
        echo "installed natives: ${module#/opt/ghidra/}/os/${plat}: $(ls "${module}/os/${plat}" | tr '\n' ' ')"; \
      done; \
      rm -rf /root/.gradle /opt/ghidra/support/gradle/.gradle /opt/ghidra/support/gradle/build; \
    fi; \
    test -x "/opt/ghidra/Ghidra/Features/Decompiler/os/${plat}/decompile"; \
    ls -l "/opt/ghidra/Ghidra/Features/Decompiler/os/${plat}/"

# Python side: every package pinned by hash, wheels only (no setup.py runs).
COPY requirements.lock /tmp/requirements.lock
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --require-hashes --only-binary=:all: -r /tmp/requirements.lock \
 && /opt/venv/bin/pyghidra-mcp --version

# Chroma (pyghidra-mcp's code index behind search_code AND search_strings)
# downloads an ONNX embedding model on first use. Offline that download fails and
# both tools stay broken for the whole session, so fetch it now. Chroma checks
# the archive's SHA-256 itself before unpacking.
ENV HOME=/opt/home
RUN mkdir -p /opt/home \
 && /opt/venv/bin/python -c "from chromadb.utils.embedding_functions import ONNXMiniLM_L6_V2 as E; print(len(E()(['warm up'])[0]), 'dims')" \
 && rm -f /opt/home/.cache/chroma/onnx_models/all-MiniLM-L6-v2/onnx.tar.gz \
 && chmod -R a+rX /opt/home
# ^ the container runs as your own user id, not root, so the model must be world-readable.
#   Otherwise Chroma can't see it, tries to download it again, and indexing fails.

# ------------------------------------------------------------------- runtime
FROM ${BASE_IMAGE} AS runtime

ENV DEBIAN_FRONTEND=noninteractive
# No compilers, curl, git or package caches in the runtime image.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openjdk-21-jdk-headless python3 \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -g 1001 ghidra && useradd -u 1001 -g 1001 -M -d /opt/home -s /usr/sbin/nologin ghidra

COPY --from=build /opt/ghidra /opt/ghidra
COPY --from=build /opt/venv   /opt/venv
COPY --from=build /opt/home   /opt/home

# HOME is read-only at runtime (it only holds the embedding model). Everything
# Ghidra writes goes to /tmp (a tmpfs) or to the /projects bind mount.
ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    GHIDRA_INSTALL_DIR=/opt/ghidra \
    HOME=/opt/home \
    XDG_CONFIG_HOME=/tmp/xdg/config \
    XDG_CACHE_HOME=/tmp/xdg/cache \
    ANONYMIZED_TELEMETRY=False \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 \
    DO_NOT_TRACK=1

RUN mkdir -p /projects /samples /symbols && chown 1001:1001 /projects
USER 1001:1001
WORKDIR /projects

ENTRYPOINT ["pyghidra-mcp"]
CMD ["-t", "stdio"]
