"""Agent-neutral classification of tool calls.

Three questions per call:
  untrusted_source  - can its output carry attacker-controlled text?
  outbound          - can it send data out of the machine / account?
  protected_write   - does it modify agent instructions, config or persistence?

Tool names are matched on their *bare* name (the last "__" segment of an MCP
tool), because hosted connectors carry per-install UUIDs in the server segment
(e.g. mcp__0a1b2c3d-...__send_message).
"""
from __future__ import annotations

import os
import re
import shlex
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .detect import urls_in


@dataclass
class Tool:
    name: str
    server: str | None
    bare: str

    @property
    def is_mcp(self) -> bool:
        return self.server is not None


def parse_tool(name: str) -> Tool:
    if name.startswith("mcp__"):
        parts = name.split("__")
        server = parts[1] if len(parts) > 2 else ""
        return Tool(name, server, parts[-1].lower())
    return Tool(name, None, name.lower())


def _any(patterns, s: str) -> bool:
    return any(re.search(p, s, re.I) for p in patterns)


def is_trusted_server(t: Tool, cfg: dict) -> bool:
    return t.is_mcp and _any(cfg.get("trusted_servers", []), t.server or "")


BROWSER_SERVER = re.compile(r"chrome|browser|playwright|puppeteer|selenium", re.I)


def is_browser(t: Tool) -> bool:
    return bool(t.is_mcp and BROWSER_SERVER.search(t.server or ""))


# ---------------------------------------------------------------------------
# untrusted sources

_READ_BARE = re.compile(
    r"^(get|read|search|fetch|download|query|export)(_|$)"
    r"|_(read|search|fetch|download|export)(_|$)"
    r"|^list_(messages|threads|emails|mails|comments|replies|issues|pull_requests|notifications)$"
    r"|_get_(message|thread|attachment|file|page|issue|comment)",
    re.I,
)
_BROWSER_NON_CONTENT = re.compile(r"^(tabs_|preview_(list|stop)|resize|list_connected|select_browser|switch_browser)")

DEFAULT_UNTRUSTED_PATHS = ["~/Downloads", "~/Library/Mail", "~/Library/Containers/com.apple.mail"]

_NET_FETCH = re.compile(
    r"\b(curl|wget|http|httpie|xh|lynx|w3m|links)\b|\bgh\s+api\b|\bgit\s+(clone|fetch|pull)\b"
    r"|\b(Invoke-WebRequest|iwr|Invoke-RestMethod|irm|Start-BitsTransfer)\b|\.Download(String|File|Data)\b",
    re.I)

# Shell tools: Claude Code's Bash and PowerShell (Windows); Codex's shell later.
SHELL_TOOLS = {"Bash", "PowerShell"}

_WIN_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")
_GITBASH_DRIVE = re.compile(r"^/([A-Za-z])/")
_HOME_VARS = re.compile(r"^(\$env:USERPROFILE|\$env:HOME|%USERPROFILE%|\$HOME|\$\{HOME\})(?=[\\/]|$)", re.I)


def _looks_windows(p: str) -> bool:
    return bool(_WIN_DRIVE.match(p)) or ("\\" in p and "/" not in p)


def _expand(p: str, cwd: str | None = None) -> str:
    """Normalise a path for pattern matching: forward slashes, home expanded.

    Windows-shaped paths (C:\\..., Git Bash /c/...) are normalised textually so
    the same rules work on every OS and can be tested anywhere.
    """
    p = (p or "").strip().strip("'\"")
    home = os.path.expanduser("~")
    p = _HOME_VARS.sub(lambda m: home.replace("\\", "/"), p)
    if p.startswith("~"):
        p = home.replace("\\", "/") + p[1:]
    if _looks_windows(p) or (cwd and _looks_windows(cwd) and not p.startswith("/")):
        p = p.replace("\\", "/")
        if not _WIN_DRIVE.match(p) and cwd:
            p = cwd.replace("\\", "/").rstrip("/") + "/" + p
        return re.sub(r"/+", "/", p)
    m = _GITBASH_DRIVE.match(p)
    if m and os.name == "nt":
        return f"{m.group(1)}:/" + p[3:]
    p = os.path.expandvars(p)
    if cwd and not os.path.isabs(p):
        p = os.path.join(cwd, p)
    return os.path.realpath(p).replace("\\", "/")


def _under(path: str, base: str) -> bool:
    a, b = path.lower().rstrip("/"), base.lower().rstrip("/")
    return a == b or a.startswith(b + "/")


def untrusted_source(t: Tool, tool_input: dict, cfg: dict) -> str | None:
    """Reason string if this call's output should be treated as untrusted."""
    if is_trusted_server(t, cfg):
        return None
    if t.name in ("WebFetch", "WebSearch"):
        return f"web content via {t.name}"
    if is_browser(t):
        return None if _BROWSER_NON_CONTENT.search(t.bare) else f"web page via {t.name}"
    if t.is_mcp and (_READ_BARE.search(t.bare) or _any(cfg.get("extra_untrusted_read_tools", []), t.bare)):
        return f"external content via {t.name}"
    if t.name in ("Read", "NotebookRead"):
        fp = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
        if fp:
            rp = _expand(fp)
            for base in DEFAULT_UNTRUSTED_PATHS + cfg.get("untrusted_paths", []):
                if _under(rp, _expand(base)):
                    return f"downloaded file {fp}"
    if t.name in SHELL_TOOLS:
        cmd = str(tool_input.get("command") or "")
        if _NET_FETCH.search(cmd) and urls_in(cmd):
            return "network fetch in shell command"
    return None


# ---------------------------------------------------------------------------
# outbound sinks

OUTBOUND_VERBS = {
    "send", "reply", "forward", "post", "publish", "share", "schedule", "upload",
    "submit", "push", "draft", "comment", "respond", "invite", "gist", "transfer",
    "tweet", "broadcast", "notify", "email",
}
_OUTBOUND_BARE = re.compile(
    r"^(drive_)?(create|update|copy|move)_files?$|^create_or_update_file$|^push_files$"
    r"|create_canvas|update_canvas|create_event|update_event|create_pr$|create_pull_request"
    r"|create_issue|create_gist|create_filter|create_label|create_record|update_record"
    r"|create_deployment|write_session_files|add_comment|create_comment|merge_pull_request"
    r"|create_project_env|edit_project_env|start_session|send_message",
    re.I,
)

_BASH_OUTBOUND = [
    (r"\bgit\s+push\b", "git push"),
    (r"\bgh\s+(pr|issue|gist|release|repo\s+create|secret)\b", "GitHub CLI write"),
    (r"\bgh\s+api\b.*(-X\s*(POST|PUT|PATCH|DELETE)|--method\s+(POST|PUT|PATCH|DELETE)|-f\s|-F\s|--field|--input)", "GitHub API write"),
    (r"\bcurl\b.*(\s-d\b|--data|\s-F\b|--form|\s-T\b|--upload-file|-X\s*(POST|PUT|PATCH)|--request\s+(POST|PUT|PATCH))", "HTTP upload via curl"),
    (r"\bwget\b.*--(post|body)", "HTTP upload via wget"),
    (r"\b(scp|sftp|rsync|rclone)\b", "file transfer"),
    (r"\b(nc|ncat|netcat|socat|telnet)\b\s", "raw socket"),
    (r"\b(sendmail|mail|mailx|mutt)\b\s", "local mail"),
    (r"osascript\b.*\b(Mail|Messages|Slack|Outlook)\b", "AppleScript messaging"),
    (r"\bssh\b\s+\S+.*\b(cat|tee|dd|curl)\b", "remote command"),
    # PowerShell (Windows)
    (r"\b(Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b.*(-Method\s+['\"]?(Post|Put|Patch)\b|-Body\b|-InFile\b|-Form\b)",
     "HTTP upload via PowerShell"),
    (r"\bSend-MailMessage\b", "PowerShell mail"),
    (r"\bStart-BitsTransfer\b.*-TransferType\s+Upload", "BITS upload"),
    (r"\.Upload(String|File|Data|Values)(Async)?\s*\(", ".NET upload"),
    (r"Net\.Sockets\.(TcpClient|UdpClient|Socket)\b", "raw socket"),
    (r"\bOutlook\.Application\b", "Outlook automation"),
]


def bash_outbound(cmd: str) -> str | None:
    for rx, label in _BASH_OUTBOUND:
        if re.search(rx, cmd, re.I | re.S):
            return label
    return None


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _trusted_host(host: str, cfg: dict) -> bool:
    for d in cfg.get("trusted_domains", []):
        d = d.lower().lstrip(".")
        if host == d or host.endswith("." + d):
            return True
    return False


def outbound(t: Tool, tool_input: dict, cfg: dict) -> str | None:
    """Reason string if this call can carry data out."""
    if is_trusted_server(t, cfg):
        return None
    if t.name == "WebFetch":
        url = str(tool_input.get("url") or "")
        if urlsplit(url).query and not _trusted_host(_host(url), cfg):
            return f"WebFetch with query string to {_host(url)}"
        return None
    if t.name in SHELL_TOOLS:
        label = bash_outbound(str(tool_input.get("command") or ""))
        return f"shell: {label}" if label else None
    if is_browser(t):
        if not cfg.get("gate_browser_input", True):
            return None
        if t.bare in ("form_input", "file_upload", "upload_image"):
            return f"browser {t.bare}"
        if t.bare == "computer" and str(tool_input.get("action", "")) in ("type", "key"):
            return "browser typing"
        if t.bare in ("navigate",) and urlsplit(str(tool_input.get("url") or "")).query:
            url = str(tool_input.get("url"))
            if not _trusted_host(_host(url), cfg):
                return f"browser navigation with query string to {_host(url)}"
        return None
    if t.is_mcp:
        tokens = set(re.split(r"[_\-]+", t.bare))
        if tokens & OUTBOUND_VERBS or _OUTBOUND_BARE.search(t.bare) \
                or _any(cfg.get("extra_outbound_tools", []), t.bare):
            return f"outbound tool {t.name}"
    return None


def network_urls(t: Tool, tool_input: dict) -> list[str]:
    """URLs this call will request (for exfil-shape checks)."""
    if t.name == "WebFetch" or (is_browser(t) and t.bare == "navigate"):
        u = str(tool_input.get("url") or "")
        return [u] if u else []
    if t.name in SHELL_TOOLS:
        cmd = str(tool_input.get("command") or "")
        if _NET_FETCH.search(cmd):
            return urls_in(cmd)
    return []


# ---------------------------------------------------------------------------
# protected writes (instructions, config, persistence)

ALWAYS = "always"     # ask even in a clean session
TAINTED = "tainted"   # ask only in a tainted session

_ALWAYS_PATTERNS = [
    r"/\.claude/settings(\.local)?\.json$", r"/\.claude/(hooks|agents|commands|skills|plugins|output-styles)/",
    r"/\.claude\.json$", r"/\.claude/CLAUDE\.md$", r"/\.mcp\.json$", r"/\.codex/", r"/\.cursor/mcp\.json$",
    r"/Library/Application Support/ClaudeCode/", r"/etc/claude-code/",
    r"/\.(zshrc|zprofile|zshenv|bashrc|bash_profile|profile)$", r"/Library/LaunchAgents/", r"/\.ssh/",
    r"/\.gitconfig$", r"/\.git/hooks/", r"/exfil-guard/",
    # Windows
    r"/Program Files/ClaudeCode/", r"/Start Menu/Programs/Startup/",
    r"/Documents/(Windows)?PowerShell/[^/]*profile[^/]*\.ps1$",
]
_TAINTED_PATTERNS = [
    r"/(CLAUDE|AGENTS|GEMINI|CLAUDE\.local)\.md$", r"/\.claude/projects/[^/]+/memory/", r"/memory/[^/]+\.md$",
    r"/\.cursorrules$", r"/\.github/workflows/", r"/\.claude/",
]


def protected_level(path: str, cfg: dict, cwd: str | None = None) -> str | None:
    if not path:
        return None
    p = _expand(path, cwd)
    for extra in cfg.get("extra_protected_paths", []):
        if _under(p, _expand(extra)):
            return ALWAYS
    if _any(_ALWAYS_PATTERNS, p):
        return ALWAYS
    if _any(_TAINTED_PATTERNS, p):
        return TAINTED
    return None


_WRITE_OP = re.compile(
    r"(^|[^<>&0-9])>{1,2}(?!&)|\btee\b|\bsed\b[^|;&]*\s-i|\bperl\b[^|;&]*\s-p?i|\b(mv|cp|rm|ln|chmod|chown|truncate|install|dd|touch|unlink)\b"
    r"|\bpython3?\b[^|;&]*\s-c\b|\bnode\b[^|;&]*\s-e\b|\bdefaults\s+write\b"
    # PowerShell cmdlets and common aliases
    r"|\b(Set-Content|Add-Content|Out-File|New-Item|Remove-Item|Move-Item|Copy-Item|Rename-Item|"
    r"Set-ItemProperty|New-ItemProperty|Clear-Content|Export-Clixml)\b"
    r"|\[(System\.)?IO\.File\]::(Write|Append|Copy|Move|Delete)"
    r"|(^|[;|&\s])(del|erase|copy|move|ren|ni|ri|mi|cpi|sc|ac)\s",
    re.I,
)
_PERSIST_CMD = re.compile(
    r"\bcrontab\b(?!\s+-l)|\blaunchctl\s+(load|bootstrap|submit|enable)\b"
    r"|\bexfil-guard\b\s+(untaint|clear|disable|uninstall)"
    r"|\bclaude\s+plugins?\s+(disable|uninstall|remove|marketplace\s+remove)\b"
    r"|\bschtasks(\.exe)?\s+/create\b|\bRegister-ScheduledTask\b|\bNew-Service\b"
    r"|\breg(\.exe)?\s+add\b.*\\(Run|RunOnce)\b|\b(Set|New)-ItemProperty\b.*\\(Run|RunOnce)\b",
    re.I)


def _path_tokens(cmd: str) -> list[str]:
    windows = "\\" in cmd
    try:
        toks = shlex.split(cmd, posix=not windows)
    except ValueError:
        toks = cmd.split()
    out = []
    for tok in toks:
        tok = tok.strip("'\"")
        for piece in re.split(r"[;|&<>=,()]+" if windows else r"(?<!\\)[;|&<>=]+", tok):
            piece = piece.strip("'\"")
            if ("/" in piece or "\\" in piece or piece.startswith("~") or piece.lower().startswith("$env:")
                    or piece.endswith(".md") or piece.endswith(".json")):
                out.append(piece)
    return out


def protected_write(t: Tool, tool_input: dict, cfg: dict, cwd: str | None = None) -> tuple[str, str] | None:
    """(level, description) if this call modifies a protected path."""
    if t.name in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        fp = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
        lvl = protected_level(fp, cfg, cwd)
        return (lvl, f"{t.name} {fp}") if lvl else None
    if t.name in SHELL_TOOLS:
        cmd = str(tool_input.get("command") or "")
        if _PERSIST_CMD.search(cmd):
            return (ALWAYS, f"persistence command: {cmd[:120]}")
        if not _WRITE_OP.search(cmd):
            return None
        best = None
        for tok in _path_tokens(cmd):
            lvl = protected_level(tok, cfg, cwd)
            if lvl == ALWAYS:
                return (ALWAYS, f"shell write touching {tok}")
            if lvl == TAINTED:
                best = (TAINTED, f"shell write touching {tok}")
        return best
    return None
