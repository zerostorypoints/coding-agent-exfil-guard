"""Desktop / push notifications. Never blocks the hook and never raises."""
from __future__ import annotations

import shutil
import subprocess
import sys

_SEV = {"low": 0, "medium": 1, "high": 2}


def _escape_applescript(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def send(cfg: dict, title: str, message: str, severity: str = "medium") -> None:
    if _SEV.get(severity, 1) < _SEV.get(cfg.get("notify_min_severity", "medium"), 1):
        return
    message = message.replace("\n", " ")[:300]
    try:
        cmd = cfg.get("notify_command")
        if cmd:
            argv = [str(a).replace("{title}", title).replace("{message}", message) for a in cmd]
        elif sys.platform == "darwin" and shutil.which("osascript"):
            argv = ["osascript", "-e",
                    f'display notification "{_escape_applescript(message)}" '
                    f'with title "{_escape_applescript(title)}" sound name "Basso"']
        elif shutil.which("notify-send"):
            argv = ["notify-send", "-u", "critical" if severity == "high" else "normal", title, message]
        else:
            return
        subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    except Exception:
        pass
