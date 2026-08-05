# Reproducible Linux build and run path for sql-proxy-service.
#
# Multi-stage: the builder compiles the service (and every vcpkg dependency)
# from source; the runtime stage carries only the stripped executable.
#
# The runtime image needs NO apt packages: every third-party dependency
# (libpqxx, libpq, OpenSSL, zlib, spdlog/fmt) is statically linked, so the
# binary requires only libstdc++, libm, libgcc_s and libc — all present in
# the ubuntu:24.04 base.
#
# The runtime base MUST stay on the same distribution release as the builder.
# ubuntu:24.04 ships glibc 2.39; a runtime image with an older glibc (for
# example debian:bookworm-slim, glibc 2.36) would fail to start.

# ---------------------------------------------------------------- builder ---
FROM ubuntu:24.04 AS builder

# bison/flex are required by vcpkg's PostgreSQL (libpq) port.
# git is required by both vcpkg and CMake FetchContent (hyrise/sql-parser).
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        git \
        curl \
        zip \
        unzip \
        tar \
        pkg-config \
        autoconf \
        automake \
        libtool \
        bison \
        flex \
        python3 \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Pinned to the same commit as "builtin-baseline" in vcpkg.json, so the port
# versions resolved here match the native build exactly.
ARG VCPKG_REF=9d7f79f56ae1a9b4704d6a7fb8237e347a974133
RUN git clone https://github.com/microsoft/vcpkg /opt/vcpkg \
    && git -C /opt/vcpkg checkout ${VCPKG_REF} \
    && /opt/vcpkg/bootstrap-vcpkg.sh -disableMetrics

WORKDIR /src

# --- Target architecture ----------------------------------------------------
# TARGETARCH is set by BuildKit to the architecture being built (amd64 on an
# Intel host, arm64 on Apple Silicon). dpkg is only a fallback for builders
# that do not provide it. The resolved triplet is written to a file so that
# vcpkg and CMake below use the same value; letting CMake detect the
# architecture on its own would make it look in a directory vcpkg never
# populated.
ARG TARGETARCH
RUN set -eu; \
    arch="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    case "$arch" in \
        amd64) triplet=x64-linux ;; \
        arm64) triplet=arm64-linux ;; \
        *) echo "ERROR: unsupported architecture '$arch' (supported: amd64, arm64)" >&2; \
           exit 1 ;; \
    esac; \
    printf '%s\n' "$triplet" > /vcpkg-triplet; \
    echo "Building for $arch using vcpkg triplet $triplet"

# --- Dependency layer -------------------------------------------------------
# vcpkg.json is copied alone and the dependencies installed first, so editing
# src/ or tests/ does not invalidate the slow dependency build. Manifest mode
# installs to <cwd>/vcpkg_installed, i.e. /src/vcpkg_installed; the configure
# step below points at that directory and skips a second install.
COPY vcpkg.json ./
RUN /opt/vcpkg/vcpkg install --triplet="$(cat /vcpkg-triplet)"

# --- Source layer -----------------------------------------------------------
# tests/ is copied because CMakeLists.txt lists the test sources in
# add_executable(); CMake validates that those files exist at configure time
# even though only the service target is built below. Nothing from tests/
# reaches the runtime image.
COPY CMakeLists.txt ./
COPY src ./src
COPY tests ./tests

RUN cmake -S . -B build \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_TOOLCHAIN_FILE=/opt/vcpkg/scripts/buildsystems/vcpkg.cmake \
        -DVCPKG_INSTALLED_DIR=/src/vcpkg_installed \
        -DVCPKG_MANIFEST_INSTALL=OFF \
        -DVCPKG_TARGET_TRIPLET="$(cat /vcpkg-triplet)" \
    && cmake --build build --target sql_proxy_service -j"$(nproc)" \
    && strip build/sql_proxy_service

# ---------------------------------------------------------------- runtime ---
FROM ubuntu:24.04

# Non-root service account. /var/lib/sql-proxy is created and owned BEFORE any
# volume is mounted: Docker seeds a fresh named volume from the image contents
# at that path, ownership included, so the service can write its audit file.
RUN useradd --system --uid 10001 --no-create-home sqlproxy \
    && mkdir -p /var/lib/sql-proxy \
    && chown sqlproxy:sqlproxy /var/lib/sql-proxy

COPY --from=builder /src/build/sql_proxy_service /usr/local/bin/sql_proxy_service

# Working directory is the writable audit location, so the service's default
# relative path (audit.jsonl) resolves somewhere writable even when
# AUDIT_LOG_PATH is not supplied. The directory already exists and is owned by
# sqlproxy, so WORKDIR does not re-create it as root.
WORKDIR /var/lib/sql-proxy

USER sqlproxy

# Documentation only; the actual port comes from PORT (default 8080).
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/sql_proxy_service"]
