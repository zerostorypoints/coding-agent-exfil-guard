"""Claude Code hook adapter (PreToolUse, PostToolUse, PostToolUseFailure).

Reads the hook JSON from stdin, writes the hook JSON response to stdout.
Reference: https://code.claude.com/docs/en/hooks
"""
from __future__ import annotations

import json
import sys

from .. import config, policy, state

AGENT = "claude-code"
_KIND = {"PreToolUse": "pre", "PostToolUse": "post", "PostToolUseFailure": "post_failure"}
_CAP = 9_500  # Claude Code caps additionalContext/systemMessage at 10,000 chars


def _as_text(v, _depth: int = 0) -> str:
    """Flatten a tool response to the text the model will read.

    Structured responses are walked and their string leaves joined with
    newlines; serialising them as JSON would turn line breaks into literal
    "\\n" sequences and hide word boundaries from the detectors.
    """
    if v is None or _depth > 20:
        return ""
    if isinstance(v, str):
        return v
    if isinstance(v, dict):
        return "\n".join(t for t in (_as_text(x, _depth + 1) for x in v.values()) if t)
    if isinstance(v, (list, tuple)):
        return "\n".join(t for t in (_as_text(x, _depth + 1) for x in v) if t)
    return str(v)


def to_event(d: dict) -> policy.Event:
    name = d.get("hook_event_name", "")
    kind = _KIND.get(name, "other")
    out = d.get("error") if kind == "post_failure" else d.get("tool_response")
    return policy.Event(agent=AGENT, kind=kind, session=str(d.get("session_id") or "unknown"),
                        tool=str(d.get("tool_name") or ""), tool_input=d.get("tool_input") or {},
                        output=_as_text(out), cwd=d.get("cwd"))


def to_response(ev: policy.Event, dec: policy.Decision) -> dict | None:
    if ev.kind == "pre":
        if dec.action == policy.ALLOW:
            return {"systemMessage": dec.user_message[:_CAP]} if dec.user_message else None
        r = {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                    "permissionDecision": dec.action,
                                    "permissionDecisionReason": dec.reason[:_CAP]}}
        if dec.action == policy.DENY:
            r["systemMessage"] = dec.reason[:_CAP]
        return r
    if ev.kind in ("post", "post_failure") and (dec.model_context or dec.user_message):
        name = "PostToolUse" if ev.kind == "post" else "PostToolUseFailure"
        r = {}
        if dec.model_context:
            r["hookSpecificOutput"] = {"hookEventName": name, "additionalContext": dec.model_context[:_CAP]}
        if dec.user_message:
            r["systemMessage"] = dec.user_message[:_CAP]
        return r
    return None


def main() -> int:
    raw = sys.stdin.read()
    try:
        d = json.loads(raw)
    except ValueError:
        return 0
    ev = to_event(d)
    try:
        dec = policy.decide(ev, config.load())
        resp = to_response(ev, dec)
    except Exception as e:  # fail closed for pre-tool decisions
        try:
            state.log({"agent": AGENT, "event": "guard-error", "kind": ev.kind, "session": ev.session,
                       "tool": ev.tool, "reason": repr(e)})
        except Exception:
            pass
        if ev.kind != "pre":
            return 0
        resp = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "ask",
                                       "permissionDecisionReason": f"exfil-guard internal error ({type(e).__name__}); "
                                                                   "approve only if you expected this call."}}
    if resp:
        sys.stdout.write(json.dumps(resp, ensure_ascii=False))
    return 0
