#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${NOVA_BUILD_DIR:-build-linux}"

if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1090
    . "$HOME/.cargo/env"
fi

export PATH="$HOME/.local/bin:$PATH"
export NOVA_BUILD_DIR="$BUILD_DIR"

TRACE_CMAKE_ARGS=()
for trace_var in \
    NOVA_BOOT_TRACE_LEVEL \
    NOVA_BOOT_TRACE_BOOT_LEVEL \
    NOVA_BOOT_TRACE_APIC_LEVEL \
    NOVA_BOOT_TRACE_TRAP_LEVEL \
    NOVA_BOOT_TRACE_RESTORE_LEVEL \
    NOVA_BOOT_TRACE_SCHED_LEVEL; do
    trace_value="${!trace_var-}"
    if [ -n "$trace_value" ]; then
        TRACE_CMAKE_ARGS+=("-D${trace_var}=${trace_value}")
    fi
done

cd "$ROOT_DIR"
cmake -S "$ROOT_DIR" -B "$ROOT_DIR/$BUILD_DIR" -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug \
    -DKernelSel4Arch=x86_64 \
    -DKernelPlatform=pc99 \
    -DKernelVerificationBuild=OFF \
    -DKernelDebugBuild=ON \
    -DKernelPrinting=ON \
    -DKernelIRQReporting=ON \
    -DKernelColourPrinting=ON \
    "${TRACE_CMAKE_ARGS[@]}"
cmake --build "$ROOT_DIR/$BUILD_DIR"
exec pwsh -NoLogo -NoProfile -File "$ROOT_DIR/test.ps1"
