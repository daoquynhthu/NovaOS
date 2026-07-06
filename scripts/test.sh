#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/cmake-common.sh"

: "${NOVA_TEST_SLEEP_SCALE:=0.35}"
: "${NOVA_TEST_CHAR_DELAY_MS:=1}"
: "${NOVA_TEST_DEFAULT_POST_DELAY_MS:=150}"
: "${NOVA_TEST_RM_POST_DELAY_MS:=450}"
: "${NOVA_TEST_POLL_DELAY_MS:=5}"
: "${NOVA_TEST_BULK_SEND:=0}"
: "${NOVA_TEST_BIGFILE_KB:=4}"
export NOVA_TEST_SLEEP_SCALE
export NOVA_TEST_CHAR_DELAY_MS
export NOVA_TEST_DEFAULT_POST_DELAY_MS
export NOVA_TEST_RM_POST_DELAY_MS
export NOVA_TEST_POLL_DELAY_MS
export NOVA_TEST_BULK_SEND
export NOVA_TEST_BIGFILE_KB

cd "$ROOT_DIR"
nova_configure_cmake
cmake --build "$ROOT_DIR/$BUILD_DIR"
exec pwsh -NoLogo -NoProfile -File "$ROOT_DIR/scripts/test.ps1"
