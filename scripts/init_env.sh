#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

need_cmd() {
    local cmd="$1"
    local hint="$2"
    if ! command -v "$cmd" >/dev/null 2>&1; then
        printf 'missing: %s (%s)\n' "$cmd" "$hint" >&2
        return 1
    fi
}

if [ -f "$HOME/.cargo/env" ]; then
    # shellcheck disable=SC1090
    . "$HOME/.cargo/env"
fi

need_cmd cargo "install rustup or source ~/.cargo/env"
need_cmd rustup "install rustup from https://rustup.rs"
need_cmd cmake "apt install cmake"
need_cmd ninja "apt install ninja-build"
need_cmd python3 "apt install python3"
need_cmd qemu-system-x86_64 "apt install qemu-system-x86"
need_cmd pwsh "install PowerShell or add ~/.local/bin to PATH"

rustup toolchain install nightly --profile minimal
rustup component add rust-src
rustup target add x86_64-unknown-none

if ! python3 -c 'import jinja2, lxml, ply' >/dev/null 2>&1; then
    printf '%s\n' "Missing seL4 Python generator dependencies." >&2
    printf '%s\n' "On Ubuntu/Pop!_OS install:" >&2
    printf '%s\n' "  sudo apt-get install -y python3-jinja2 python3-ply python3-lxml python3-six python3-future python3-pyelftools python3-jsonschema python3-yaml python3-psutil python3-bs4 python3-pexpect" >&2
    exit 1
fi

printf 'NovaOS Linux environment ready in %s\n' "$ROOT_DIR"
printf 'Next steps:\n'
printf '  cmake -S . -B build-linux -G Ninja -DKernelSel4Arch=x86_64 -DKernelPlatform=pc99\n'
printf '  cmake --build build-linux\n'
printf '  NOVA_BUILD_DIR=build-linux ./test.sh\n'
