"""User allow rules: traffic the user has marked as safe.

A rule lives in config.json under "allow_rules" and turns a prompt into an allow.
Every field present must match:

  {"category": "outbound",                 # or "protected-write"; omit for both
   "destination": "ssh:nas.local",         # glob; every destination of the call must match
   "tool": "Bash",                         # regex, full match on the tool name
   "command": "^rsync ",                   # regex, searched in the command or path
   "note": "backups to my NAS"}

Destinations look like  git:github.com/owner/repo  ssh:host  http:host
mcp:server/tool  path:/absolute/path.

Rules never override: requests that carry an encoded blob or a secret, and
writes to the guard's own configuration.
"""
from __future__ import annotations

import fnmatch
import json
import os
import re

from . import classify, config

CATEGORIES = ("outbound", "protected-write")
_FIELDS = ("destination", "tool", "command")


def valid(rule: dict) -> bool:
    if not isinstance(rule, dict) or not any(rule.get(f) for f in _FIELDS):
        return False
    if rule.get("category") not in (None, *CATEGORIES):
        return False
    for f in ("tool", "command"):
        if rule.get(f):
            try:
                re.compile(rule[f])
            except re.error:
                return False
    return True


def matches(rule: dict, category: str, tool: str, text: str, dests: list[str]) -> bool:
    if not valid(rule):
        return False
    if rule.get("category") and rule["category"] != category:
        return False
    if rule.get("tool") and not re.fullmatch(rule["tool"], tool, re.I):
        return False
    if rule.get("command") and not re.search(rule["command"], text or "", re.I | re.S):
        return False
    if rule.get("destination"):
        pats = rule["destination"] if isinstance(rule["destination"], list) else [rule["destination"]]
        pats = [str(p).lower() for p in pats]
        if not dests or not all(any(fnmatch.fnmatchcase(d.lower(), p) for p in pats) for d in dests):
            return False
    return True


def find(cfg: dict, category: str, tool: str, text: str, dests: list[str]) -> dict | None:
    if any("/exfil-guard/" in d for d in dests):
        return None
    for rule in cfg.get("allow_rules", []) or []:
        if matches(rule, category, tool, text, dests):
            return rule
    return None


# ---------------------------------------------------------------------------
# suggestions and editing (used by the CLI, never by the hook)

def suggest(event: dict, by: str = "destination") -> dict | None:
    cat = "protected-write" if event.get("category") == "protected-write" else "outbound"
    rule: dict = {"category": cat}
    targets = event.get("target") or []
    if by == "destination" and targets:
        kinds = {t.split(":", 1)[0] for t in targets}
        if len(set(targets)) == 1 or len(kinds) == 1 and kinds == {"path"}:
            t = targets[0]
            if t.startswith("path:"):
                common = os.path.commonpath([x[5:] for x in targets]) if len(targets) > 1 else os.path.dirname(t[5:])
                common = common.rstrip("/")
                # A rule for one worktree is useless in the next one: cover the repo
                # itself and all its worktrees.
                m = re.match(r"(.*)/\.claude/worktrees/[^/]+(/.*)?$", common)
                if m:
                    rest = m.group(2) or ""
                    rule["destination"] = [f"path:{m.group(1)}{rest}/*",
                                           f"path:{m.group(1)}/.claude/worktrees/*{rest}/*"]
                else:
                    rule["destination"] = "path:" + common + "/*"
            else:
                rule["destination"] = t
            return rule
        by = "tool"
    if by == "tool" and event.get("tool"):
        rule["tool"] = re.escape(event["tool"])
        if event.get("tool") in classify.SHELL_TOOLS and event.get("input"):
            by = "command"
        else:
            return rule
    if by == "command" and event.get("input"):
        first = re.split(r"\s+", event["input"].strip())[:2]
        rule["command"] = "^" + re.escape(" ".join(first))
        return rule
    return None


def load_raw() -> dict:
    try:
        with open(config.config_path()) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except FileNotFoundError:
        return {}


def save_raw(data: dict) -> None:
    p = config.config_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(tmp, p)


def add(rule: dict) -> None:
    if not valid(rule):
        raise ValueError(f"invalid rule: {rule}")
    data = load_raw()
    data.setdefault("allow_rules", []).append(rule)
    save_raw(data)


def remove(index: int) -> dict:
    data = load_raw()
    rules = data.get("allow_rules", [])
    rule = rules.pop(index)
    save_raw(data)
    return rule
