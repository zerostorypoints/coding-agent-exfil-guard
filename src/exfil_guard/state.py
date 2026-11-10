"""Per-session taint state and the event log."""
from __future__ import annotations

import json
import os
import re
import time
from pathlib import Path

from . import config


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")


def _safe(session: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.\-]", "_", session or "unknown")[:120]


def _session_file(agent: str, session: str) -> Path:
    return config.state_dir() / "sessions" / f"{_safe(agent)}-{_safe(session)}.json"


def get(agent: str, session: str) -> dict:
    try:
        with open(_session_file(agent, session)) as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return {"tainted": False, "reasons": []}


def taint(agent: str, session: str, reason: str, tool: str) -> dict:
    st = get(agent, session)
    first = not st.get("tainted")
    st["tainted"] = True
    st.setdefault("since", _now())
    reasons = st.setdefault("reasons", [])
    if len(reasons) < 50:
        reasons.append({"ts": _now(), "tool": tool, "reason": reason})
    p = _session_file(agent, session)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(f"{p.name}.{os.getpid()}.tmp")  # parallel hooks must not share a temp file
    with open(tmp, "w") as f:
        json.dump(st, f, ensure_ascii=False, indent=1)
    os.replace(tmp, p)
    st["_first"] = first
    return st


def set_key(agent: str, session: str, key: str, value) -> None:
    st = get(agent, session)
    st.pop("_first", None)
    st[key] = value
    p = _session_file(agent, session)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_name(f"{p.name}.{os.getpid()}.tmp")  # parallel hooks must not share a temp file
    with open(tmp, "w") as f:
        json.dump(st, f, ensure_ascii=False, indent=1)
    os.replace(tmp, p)


def clear(agent: str, session: str) -> bool:
    try:
        _session_file(agent, session).unlink()
        return True
    except FileNotFoundError:
        return False


def log(event: dict) -> None:
    p = config.state_dir() / "events.jsonl"
    p.parent.mkdir(parents=True, exist_ok=True)
    rec = {"ts": _now(), **event}
    with open(p, "a") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")


def recent(n: int = 30) -> list[dict]:
    p = config.state_dir() / "events.jsonl"
    try:
        lines = p.read_text().splitlines()[-n:]
    except FileNotFoundError:
        return []
    out = []
    for l in lines:
        try:
            out.append(json.loads(l))
        except ValueError:
            pass
    return out


def rate_limited(key: str, seconds: int = 60) -> bool:
    """True if `key` fired within the last `seconds` (and records this firing)."""
    d = config.state_dir() / "ratelimit"
    d.mkdir(parents=True, exist_ok=True)
    p = d / _safe(key)
    now = time.time()
    try:
        if now - p.stat().st_mtime < seconds:
            return True
    except FileNotFoundError:
        pass
    p.touch()
    os.utime(p, (now, now))
    return False
