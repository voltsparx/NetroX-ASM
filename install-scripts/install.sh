#!/usr/bin/env bash
set -euo pipefail

BINARY_NAME="NetroX-ASC"
INSTALL_BIN="/usr/local/bin/NetroX-ASC"
INSTALL_DATA="/usr/share/NetroX-ASC"
BUILD_OUTPUT="bin/NetroX-ASC"
VERSION_FILE="VERSION"
TEST_DIR="test-tool"
PROFILE_SCRIPT="/etc/profile.d/NetroX-ASC.sh"

C_RESET="\033[0m"
C_CYAN="\033[36m"
C_GREEN="\033[92m"
C_YELLOW="\033[93m"
C_RED="\033[91m"
C_WHITE="\033[97m"

step() { echo -e "${C_CYAN}[*]${C_RESET} $*"; }
ok()   { echo -e "${C_GREEN}[+]${C_RESET} $*"; }
warn() { echo -e "${C_YELLOW}[!]${C_RESET} $*"; }
fail() { echo -e "${C_RED}[-]${C_RESET} $*"; }
info() { echo -e "    ${C_WHITE}$*${C_RESET}"; }

read_version() {
  if [[ ! -f "$VERSION_FILE" ]]; then
    fail "E014: Source missing VERSION file."
    exit 1
  fi
  cat "$VERSION_FILE"
}

print_banner() {
  local ver
  ver="$(read_version)"
  echo -e "╔══════════════════════════════════════════╗"
  echo -e "║   NetroX-ASC INSTALLER v${ver}            ║"
  echo -e "║   Pure x86_64 NASM network diagnostic    ║"
  echo -e "╚══════════════════════════════════════════╝"
}

usage() {
  echo "Usage: sudo ./install-scripts/install.sh [install|uninstall|update|test]"
  echo "  install   - build and install NetroX-ASC"
  echo "  uninstall - remove NetroX-ASC from system"
  echo "  update    - update existing installation"
  echo "  test      - build and run smoke tests"
}

check_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    fail "E001: Run as root or use sudo"
    exit 2
  fi
}

is_installed() {
  [[ -f "$INSTALL_BIN" ]]
}

get_installed_version() {
  if [[ -f "${INSTALL_DATA}/VERSION" ]]; then
    cat "${INSTALL_DATA}/VERSION"
  else
    echo "unknown"
  fi
}

check_build_tools() {
  command -v nasm >/dev/null 2>&1 || { fail "E002: nasm not found"; info "Install nasm: apt install nasm"; exit 1; }
  command -v make >/dev/null 2>&1 || { fail "E003: make not found"; info "Install make: apt install make"; exit 1; }
  command -v ld >/dev/null 2>&1 || { fail "E003: ld not found"; info "Install binutils: apt install binutils"; exit 1; }
}

build_binary() {
  step "Building binary from source..."
  if ! make linux; then
    fail "E004: Build failed. See error above."
    exit 1
  fi
  if [[ ! -f "$BUILD_OUTPUT" ]]; then
    fail "E005: Binary missing after build."
    exit 1
  fi
  ok "Build successful: $BUILD_OUTPUT ($(ls -lh "$BUILD_OUTPUT" | awk '{print $5}'))"
}

apply_capability() {
  if command -v setcap >/dev/null 2>&1; then
    if setcap cap_net_raw+ep "$INSTALL_BIN"; then
      ok "Applied cap_net_raw+ep"
      return
    else
      warn "E008: setcap failed, attempting setuid fallback"
    fi
  else
    warn "E007: setcap not found, attempting setuid fallback"
  fi
  if chmod u+s "$INSTALL_BIN"; then
    ok "Applied setuid fallback"
  else
    warn "E009: Cannot set raw socket capability"
  fi
}

verify_install() {
  if ! "$INSTALL_BIN" --about >/dev/null 2>&1; then
    fail "E010: Binary verify failed (--about non-zero)"
    exit 4
  fi
}

add_to_path_profile() {
  local dir
  dir="$(dirname "$INSTALL_BIN")"
  if [[ "$dir" != "/usr/local/bin" ]]; then
    echo "export PATH=\"${dir}:\$PATH\"" > "$PROFILE_SCRIPT"
  fi
}

remove_from_path_profile() {
  if [[ -f "$PROFILE_SCRIPT" ]]; then
    rm -f "$PROFILE_SCRIPT"
  fi
}

do_install() {
  check_root install
  print_banner
  if is_installed; then
    warn "E011: Already installed. Use --update."
    exit 0
  fi
  local ver
  ver="$(read_version)"
  check_build_tools
  build_binary
  mkdir -p "$(dirname "$INSTALL_BIN")" "$INSTALL_DATA"
  cp "$BUILD_OUTPUT" "$INSTALL_BIN"
  chmod 755 "$INSTALL_BIN"
  cp "$VERSION_FILE" "${INSTALL_DATA}/VERSION"
  apply_capability
  add_to_path_profile
  verify_install
  echo "┌──────────────────────────────────────────┐"
  echo "│  Installed NetroX-ASC v${ver}             │"
  echo "│  Binary: ${INSTALL_BIN}"
  echo "└──────────────────────────────────────────┘"
}

do_uninstall() {
  check_root uninstall
  print_banner
  if ! is_installed; then
    warn "E012: Not installed. Nothing to remove."
    exit 0
  fi
  local installed_ver
  installed_ver="$(get_installed_version)"
  rm -f "$INSTALL_BIN"
  rm -rf "$INSTALL_DATA"
  rm -f /usr/share/man/man1/NetroX-ASC.1 || true
  remove_from_path_profile
  echo "Uninstalled NetroX-ASC v${installed_ver}"
}

do_update() {
  check_root update
  print_banner
  if ! is_installed; then
    do_install
    return
  fi
  local new_ver
  local installed_ver
  new_ver="$(read_version)"
  installed_ver="$(get_installed_version)"
  if [[ "$new_ver" == "$installed_ver" ]]; then
    ok "Already up to date."
    exit 0
  fi
  check_build_tools
  build_binary
  if ! cp "$INSTALL_BIN" "${INSTALL_BIN}.bak"; then
    fail "E013: Cannot backup old binary. Abort."
    exit 1
  fi
  if ! cp "$BUILD_OUTPUT" "$INSTALL_BIN"; then
    cp "${INSTALL_BIN}.bak" "$INSTALL_BIN"
    fail "E004: Build failed. See error above."
    exit 1
  fi
  chmod 755 "$INSTALL_BIN"
  apply_capability
  cp "$VERSION_FILE" "${INSTALL_DATA}/VERSION"
  verify_install
  rm -f "${INSTALL_BIN}.bak"
  echo "┌──────────────────────────────────────────┐"
  echo "│  Updated NetroX-ASC ${installed_ver} -> ${new_ver}"
  echo "└──────────────────────────────────────────┘"
}

run_test() {
  local name="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    ok "Test passed: ${name}"
    return 0
  else
    warn "Test failed: ${name}"
    return 1
  fi
}

do_test() {
  print_banner
  check_build_tools
  build_binary
  mkdir -p "$TEST_DIR"
  cp "$BUILD_OUTPUT" "${TEST_DIR}/${BINARY_NAME}"
  chmod 755 "${TEST_DIR}/${BINARY_NAME}"

  local passed=0
  local failed=0
  run_test "about" "${TEST_DIR}/${BINARY_NAME}" --about && passed=$((passed+1)) || failed=$((failed+1))
  run_test "help" "${TEST_DIR}/${BINARY_NAME}" --help && passed=$((passed+1)) || failed=$((failed+1))
  run_test "version-info" "${TEST_DIR}/${BINARY_NAME}" --version-info && passed=$((passed+1)) || failed=$((failed+1))
  run_test "scan" "${TEST_DIR}/${BINARY_NAME}" 127.0.0.1 --scan syn -p 80 --bench -T5 && passed=$((passed+1)) || failed=$((failed+1))

  echo "${passed}/4 tests passed"
  if [[ "$failed" -eq 0 ]]; then
    echo "┌──────────────────────────┐"
    echo "│  TEST SUITE PASSED       │"
    echo "└──────────────────────────┘"
    exit 0
  else
    echo "┌──────────────────────────┐"
    echo "│  TEST SUITE FAILED       │"
    echo "└──────────────────────────┘"
    exit 4
  fi
}

case "${1:-}" in
  install) do_install ;;
  uninstall) do_uninstall ;;
  update) do_update ;;
  test) do_test ;;
  *)
    print_banner
    fail "Unknown action: ${1:-}"
    usage
    exit 1
    ;;
esac

