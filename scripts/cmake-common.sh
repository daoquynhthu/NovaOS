#!/usr/bin/env bash

# NovaOS common shell build configuration.
# Intended to be sourced by scripts/build.sh, scripts/test.sh, and scripts/run_qemu.sh.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_DIR="${NOVA_BUILD_DIR:-build}"

if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1090
    . "$HOME/.cargo/env"
fi

export PATH="$HOME/.local/bin:$PATH"
export NOVA_BUILD_DIR="$BUILD_DIR"

: "${NOVA_BOOT_TRACE_LEVEL:=0}"
: "${NOVA_BOOT_TRACE_BOOT_LEVEL:=0}"
: "${NOVA_BOOT_TRACE_APIC_LEVEL:=0}"
: "${NOVA_BOOT_TRACE_TRAP_LEVEL:=0}"
: "${NOVA_BOOT_TRACE_RESTORE_LEVEL:=0}"
: "${NOVA_BOOT_TRACE_SCHED_LEVEL:=0}"
export NOVA_BOOT_TRACE_LEVEL
export NOVA_BOOT_TRACE_BOOT_LEVEL
export NOVA_BOOT_TRACE_APIC_LEVEL
export NOVA_BOOT_TRACE_TRAP_LEVEL
export NOVA_BOOT_TRACE_RESTORE_LEVEL
export NOVA_BOOT_TRACE_SCHED_LEVEL

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

# Configure the seL4 kernel build with NovaOS defaults.
nova_configure_cmake() {
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
}
