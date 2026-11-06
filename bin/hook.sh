#!/bin/sh
# Hook launcher for Claude Code on macOS, Linux and Windows (Git Bash).
# Finds a working Python 3: on Windows "python3" is often a Microsoft Store stub
# that is on PATH but does not run, so each candidate is probed first.
# Override with EXFIL_GUARD_PYTHON (e.g. "py -3" or a full path).
DIR=$(cd "$(dirname "$0")" && pwd)
for c in "$EXFIL_GUARD_PYTHON" python3 python "py -3"; do
  [ -n "$c" ] || continue
  if $c -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' >/dev/null 2>&1; then
    exec $c -I "$DIR/exfil-guard" hook "$@"
  fi
done
echo "exfil-guard: no Python 3.9+ found (tried python3, python, py -3); set EXFIL_GUARD_PYTHON" >&2
exit 1
