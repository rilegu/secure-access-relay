#!/usr/bin/env bash
# Build sardiag and run its tests, without a build system.
#
# Four source files and one test binary. CMakeLists.txt exists for consumers who
# expect it; this is what the task runner and CI use, because the compiler
# invocation is more readable than the configuration that would generate it.
set -euo pipefail

cd "$(dirname "$0")"
mkdir -p build

# Find a C compiler.
#
# $CC wins if set. Otherwise gcc from PATH, and failing that a few places MinGW
# is commonly installed - because a shell launched from PowerShell or from a
# task runner does not inherit the PATH a login shell would, and "gcc: command
# not found" on a machine that has gcc is a confusing way to learn that.
find_cc() {
  if [ -n "${CC:-}" ]; then
    printf '%s' "$CC"
    return 0
  fi
  for candidate in gcc clang       /c/ProgramData/mingw64/mingw64/bin/gcc       "${MINGW_PREFIX:-/mingw64}/bin/gcc"       /c/msys64/mingw64/bin/gcc       /c/mingw64/bin/gcc; do
    # Bare names go through PATH, which resolves the .exe suffix on Windows.
    if command -v "$candidate" >/dev/null 2>&1; then
      printf '%s' "$candidate"
      return 0
    fi
    # Absolute paths do not: command -v checks the literal name, and the file
    # on disk is gcc.exe. Testing both is the difference between finding a
    # compiler that is installed and reporting that none is.
    if [ -x "$candidate" ] || [ -x "$candidate.exe" ]; then
      printf '%s' "$candidate"
      return 0
    fi
  done
  return 1
}

if ! CC="$(find_cc)"; then
  echo "no C compiler found. Install MinGW-w64 or set CC to one." >&2
  echo "The agent does not need it: sardiag is optional and the Go binaries" >&2
  echo "build without a C toolchain." >&2
  exit 1
fi
echo "==> using $CC"
WARN="-Wall -Wextra -Wpedantic -Wconversion -Werror"
SRC="src/sardiag.c src/jbuf.c src/collect_windows.c src/collect_stub.c"

# Windows links the IP Helper and WinHTTP libraries; other platforms compile the
# stub collector and need none of them.
case "$(uname -s 2>/dev/null || echo unknown)" in
  MINGW*|MSYS*|CYGWIN*|Windows*) LIBS="-lws2_32 -liphlpapi -lwinhttp" ;;
  *)                             LIBS="" ;;
esac

echo "==> sardiag tests"
# shellcheck disable=SC2086
$CC -std=c99 $WARN -O1 -Iinclude -Isrc -o build/test_sardiag tests/test_sardiag.c $SRC $LIBS
./build/test_sardiag

echo "==> sardiag library"
# shellcheck disable=SC2086
$CC -std=c99 $WARN -O2 -shared -DSARDIAG_BUILD_DLL -Iinclude -Isrc \
    -o build/sardiag.dll $SRC $LIBS

echo "==> exports"
# A library that exports nothing loads and then cannot be called, which at
# runtime looks like a missing file rather than a missing keyword.
#
# The check needs an objdump that understands this binary's format. A machine
# can easily have one on PATH that does not - a cross-toolchain for a different
# architecture, say - and that objdump reports no exports for a perfectly good
# library. So each candidate is tried and the first that can actually read the
# file wins; if none can, the check says it was skipped rather than passing
# quietly. A check that cannot fail is worse than no check.
#
# Scanning the file for the symbol name is not an alternative: the name appears
# in the binary whether or not it is exported, so that test always passes.
#
# The authoritative check is TestLoadsAndReportsMatchingABI in
# internal/diagbridge, which loads the library and calls it.
checked=0
for od in objdump "${MINGW_PREFIX:-/mingw64}/bin/objdump"           /c/ProgramData/mingw64/mingw64/bin/objdump x86_64-w64-mingw32-objdump; do
  command -v "$od" >/dev/null 2>&1 || continue
  if out=$("$od" -p build/sardiag.dll 2>/dev/null) && [ -n "$out" ]; then
    if printf '%s' "$out" | grep -q sardiag_abi_version; then
      echo "ok (via $od)"
    else
      echo "sardiag.dll exports no symbols; SARDIAG_BUILD_DLL was not defined" >&2
      exit 1
    fi
    checked=1
    break
  fi
done
if [ "$checked" -eq 0 ]; then
  echo "skipped: no objdump on this machine can read the built format"
fi
