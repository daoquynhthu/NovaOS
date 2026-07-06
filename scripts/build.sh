#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/cmake-common.sh"

cd "$ROOT_DIR"
nova_configure_cmake
cmake --build "$ROOT_DIR/$BUILD_DIR"
exec pwsh -NoLogo -NoProfile -File "$ROOT_DIR/scripts/build.ps1"
