"""Configuration and filesystem locations.

Locations (override everything with EXFIL_GUARD_HOME, used by tests):
  config: $XDG_CONFIG_HOME/exfil-guard/config.json   (default ~/.config/...; Windows %APPDATA%)
  state:  $XDG_STATE_HOME/exfil-guard/               (default ~/.local/state/...; Windows %LOCALAPPDATA%)
"""
from __future__ import annotations

import json
import os
from pathlib import Path

DEFAULTS: dict = {
    # enforce: return ask/deny decisions. monitor: log and notify only, never block.
    "mode": "enforce",
    # Decision used when a tainted session calls an outbound tool. Codex has no
    # "ask", so its adapter turns "ask" into "deny" (see docs/codex.md).
    "tainted_outbound_decision": "ask",
    # Notification command. None = built-in (osascript on macOS, notify-send on Linux).
    # A list is run as argv with "{title}" and "{message}" substituted, e.g.
    # ["curl", "-s", "-d", "{title}: {message}", "https://ntfy.sh/your-topic"]
    "notify_command": None,
    # False = messages only inside the agent session, no desktop notifications.
    "desktop_notifications": True,
    # high: desktop alerts only for critical events (blocked exfiltration, a secret in an
    # outbound call, an explicit attempt to override the agent). Everything else still
    # appears inside the session and in the log. "medium" adds every outbound call after
    # untrusted input and weaker injection signals.
    "notify_min_severity": "high",
    # Domains WebFetch/browser may query even when the session is tainted.
    "trusted_domains": [],
    # MCP server names (regex, matched against the server segment of the tool name)
    # whose tools are never treated as untrusted sources or outbound sinks.
    "trusted_servers": [r"^ccd_", r"^visualize$"],
    # Extra regexes on the bare tool name (last "__" segment), lowercase.
    "extra_untrusted_read_tools": [],
    "extra_outbound_tools": [],
    # Extra protected paths (glob-ish prefixes; ~ expanded).
    "extra_protected_paths": [],
    # Gate browser interaction (typing, form fill, upload) in tainted sessions.
    "gate_browser_input": True,
}


def home_override() -> Path | None:
    v = os.environ.get("EXFIL_GUARD_HOME")
    return Path(v) if v else None


def config_path() -> Path:
    h = home_override()
    if h:
        return h / "config.json"
    base = os.environ.get("XDG_CONFIG_HOME") or (
        os.environ.get("APPDATA") if os.name == "nt" else None) or os.path.expanduser("~/.config")
    return Path(base) / "exfil-guard" / "config.json"


def state_dir() -> Path:
    h = home_override()
    if h:
        return h / "state"
    base = os.environ.get("XDG_STATE_HOME") or (
        os.environ.get("LOCALAPPDATA") if os.name == "nt" else None) or os.path.expanduser("~/.local/state")
    return Path(base) / "exfil-guard"


def load() -> dict:
    cfg = dict(DEFAULTS)
    p = config_path()
    try:
        with open(p) as f:
            user = json.load(f)
        if isinstance(user, dict):
            cfg.update(user)
    except FileNotFoundError:
        pass
    except Exception as e:  # broken config must not silently disable the guard
        cfg["_config_error"] = f"{p}: {e}"
    return cfg
