"""Desktop / push notifications. Never blocks the hook and never raises.

macOS: osascript. Linux: notify-send. Windows: a WinRT toast through Windows
PowerShell (no modules needed). Title and message are passed through
environment variables, never interpolated into a script.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys

_SEV = {"low": 0, "medium": 1, "high": 2}

_WIN_TOAST = (
    "[Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null;"
    "$t = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent("
    "[Windows.UI.Notifications.ToastTemplateType]::ToastText02);"
    "$n = $t.GetElementsByTagName('text');"
    "$n.Item(0).AppendChild($t.CreateTextNode($env:EXFIL_GUARD_TITLE)) | Out-Null;"
    "$n.Item(1).AppendChild($t.CreateTextNode($env:EXFIL_GUARD_MESSAGE)) | Out-Null;"
    "[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier("
    "'{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe')"
    ".Show([Windows.UI.Notifications.ToastNotification]::new($t))"
)


def _escape_applescript(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def build_argv(cfg: dict, title: str, message: str, severity: str, platform: str = sys.platform):
    """Return (argv, extra_env) or None. Separated out for tests."""
    cmd = cfg.get("notify_command")
    if cmd:
        return [str(a).replace("{title}", title).replace("{message}", message) for a in cmd], {}
    if platform == "darwin" and shutil.which("osascript"):
        return ["osascript", "-e",
                f'display notification "{_escape_applescript(message)}" '
                f'with title "{_escape_applescript(title)}" sound name "Basso"'], {}
    if platform == "win32":
        exe = shutil.which("powershell") or shutil.which("powershell.exe") or "powershell.exe"
        return [exe, "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden", "-Command", _WIN_TOAST], \
               {"EXFIL_GUARD_TITLE": title, "EXFIL_GUARD_MESSAGE": message}
    if shutil.which("notify-send"):
        return ["notify-send", "-u", "critical" if severity == "high" else "normal", title, message], {}
    return None


def send(cfg: dict, title: str, message: str, severity: str = "medium") -> None:
    if not cfg.get("desktop_notifications", True):
        return
    if _SEV.get(severity, 1) < _SEV.get(cfg.get("notify_min_severity", "medium"), 1):
        return
    message = message.replace("\n", " ")[:300]
    try:
        built = build_argv(cfg, title, message, severity)
        if not built:
            return
        argv, extra = built
        kw = dict(stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                  env={**os.environ, **extra})
        if os.name == "nt":
            kw["creationflags"] = 0x00000008 | 0x08000000  # DETACHED_PROCESS | CREATE_NO_WINDOW
        else:
            kw["start_new_session"] = True
        subprocess.Popen(argv, **kw)
    except Exception:
        pass
