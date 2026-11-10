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
from urllib.parse import parse_qsl, urlsplit

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

# Tools whose output only echoes what the agent itself wrote; not scanned.
SELF_ECHO_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit", "TodoWrite"}

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


_LOCAL_HOST = re.compile(r"^(localhost|127\.\d+\.\d+\.\d+|\[?::1\]?|0\.0\.0\.0|[^.]+\.localhost|.+\.test)$", re.I)


def is_local_url(url: str) -> bool:
    return bool(_LOCAL_HOST.match(_host(url)))


def browser_target_local(t: Tool, tool_input: dict) -> bool | None:
    """For browser calls that choose what the tab shows: is it a local dev server?
    None when the call does not change the page."""
    if t.bare not in ("navigate", "preview_start"):
        return None
    url = str(tool_input.get("url") or "")
    if not url:
        # preview_start by name starts a dev server from .claude/launch.json
        return True if t.bare == "preview_start" else None
    if url in ("back", "forward"):
        return None
    return is_local_url(url if "://" in url else "https://" + url)


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
        urls = urls_in(cmd) if _NET_FETCH.search(cmd) else []
        if any(not is_local_url(u) for u in urls):
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
    (r"\bgh\s+(pr\s+(create|merge|comment|edit|review|close|reopen|ready)"
     r"|issue\s+(create|comment|edit|close|reopen|transfer|delete|develop)"
     r"|gist\s+(create|edit)|release\s+(create|upload|edit)|repo\s+(create|fork)|secret\s+set)\b",
     "GitHub CLI write"),
    (r"\bgh\s+api\b.*(-X\s*(POST|PUT|PATCH|DELETE)|--method\s+(POST|PUT|PATCH|DELETE)|-f\s|-F\s|--field|--input)", "GitHub API write"),
    (r"\bcurl\b.*(\s-d\b|--data|\s-F\b|--form|\s-T\b|--upload-file|-X\s*(POST|PUT|PATCH)|--request\s+(POST|PUT|PATCH))", "HTTP upload via curl"),
    (r"\bwget\b.*--(post|body)", "HTTP upload via wget"),
    (r"\b(scp|sftp|rsync|rclone)\b", "file transfer"),
    (r"\b(nc|ncat|netcat|socat|telnet)\b\s", "raw socket"),
    (r"(^|[;&|(]|\$\()\s*(sendmail|mail|mailx|mutt)\s", "local mail"),
    (r"osascript\b.*\b(Mail|Messages|Slack|Outlook)\b", "AppleScript messaging"),
    # Data piped or redirected into ssh, or written on the remote side. Plain reads
    # over ssh (ssh host 'cat log') bring data in, not out.
    (r"\|\s*ssh\b|\bssh\b[^|;&]*\s<\s*\S|\bssh\b\s+\S+.*(\bcat\s*>|\btee\b|\bdd\b.*\bof=|\bcurl\b)",
     "remote command"),
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
    import fnmatch
    for d in cfg.get("trusted_domains", []):
        d = d.lower().lstrip(".")
        if "*" in d or "?" in d:
            if fnmatch.fnmatchcase(host, d):
                return True
        elif host == d or host.endswith("." + d):
            return True
    return False


_PERSONAL = re.compile(r"[^@\s]+@[^@\s]+\.[a-z]{2,}|\+?\d[\d\s().-]{8,}\d", re.I)


def query_carries_data(url: str, cfg: dict) -> bool:
    """A query string worth asking about: a long value, or one that looks like an
    e-mail address or a phone/account number. Short search terms and ids are not."""
    limit = int(cfg.get("query_value_max_len", 32))
    if limit <= 0:
        return bool(urlsplit(url).query)
    try:
        pairs = parse_qsl(urlsplit(url).query, keep_blank_values=True)
    except ValueError:
        return True
    return any(len(v) > limit or _PERSONAL.search(v) for _, v in pairs)


def outbound(t: Tool, tool_input: dict, cfg: dict) -> str | None:
    """Reason string if this call can carry data out."""
    if is_trusted_server(t, cfg):
        return None
    if t.name == "WebFetch":
        url = str(tool_input.get("url") or "")
        if urlsplit(url).query and not _trusted_host(_host(url), cfg) and query_carries_data(url, cfg):
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
            if not _trusted_host(_host(url), cfg) and query_carries_data(url, cfg):
                return f"browser navigation with query string to {_host(url)}"
        return None
    if t.is_mcp:
        # gmail_get_draft, list_drafts, delete_draft: reading or removing is not sending
        if re.search(r"(^|_)(get|list|search|read|fetch|delete|trash|remove)(_|$)", t.bare):
            return None
        tokens = set(re.split(r"[_\-]+", t.bare))
        if tokens & OUTBOUND_VERBS or _OUTBOUND_BARE.search(t.bare) \
                or _any(cfg.get("extra_outbound_tools", []), t.bare):
            return f"outbound tool {t.name}"
    return None


# ---------------------------------------------------------------------------
# git destinations (for trusted_git_remotes)

_REMOTE_URL = re.compile(r"^(?:[a-z+]+://)?(?:[^@/]+@)?([^/:]+)[:/]+(.+?)(?:\.git)?/?$", re.I)


def normalize_remote(url: str) -> str | None:
    """git@github.com:o/r.git, https://github.com/o/r -> github.com/o/r"""
    m = _REMOTE_URL.match((url or "").strip())
    if not m or "/" not in m.group(2):
        return None
    return f"{m.group(1).lower()}/{m.group(2).strip('/')}".lower()


def _remote_url(cwd: str | None, remote: str) -> str | None:
    import subprocess
    try:
        r = subprocess.run(["git", "-C", cwd or ".", "remote", "get-url", "--push", remote],
                           capture_output=True, text=True, timeout=2)
        return r.stdout.strip() or None if r.returncode == 0 else None
    except Exception:
        return None


def _effective_cwd(cmd: str, upto: int, cwd: str | None) -> str | None:
    """Directory a command segment runs in, following 'cd X' before it."""
    for m in re.finditer(r"\b(?:cd|pushd)\s+(\"[^\"]*\"|'[^']*'|[^\s;&|]+)", cmd[:upto]):
        d = m.group(1).strip("'\"")
        cwd = _expand(d, cwd)
    return cwd


def git_destinations(cmd: str, cwd: str | None) -> list[str] | None:
    """Repositories a git push / gh write in this command goes to, normalised as
    host/owner/repo. None if any destination cannot be determined."""
    out = []
    for m in re.finditer(r"\bgit\s+(?:-C\s+(\"[^\"]*\"|'[^']*'|\S+)\s+)?push\b([^;&|]*)", cmd):
        wd = _expand(m.group(1).strip("'\""), cwd) if m.group(1) else _effective_cwd(cmd, m.start(), cwd)
        args = [a for a in m.group(2).split() if not a.startswith("-")]
        target = args[0] if args else "origin"
        url = target if ("/" in target or ":" in target) else _remote_url(wd, target)
        dest = normalize_remote(url or "")
        if not dest:
            return None
        out.append(dest)
    for m in re.finditer(r"\bgh\s+(pr|issue|release)\b([^;&|]*)", cmd):
        r = re.search(r"(?:-R|--repo)[=\s]+(\S+)", m.group(2))
        if r:
            repo = r.group(1).strip("'\"")
            dest = normalize_remote(repo if "." in repo.split("/")[0] else "github.com/" + repo)
        else:
            dest = normalize_remote(_remote_url(_effective_cwd(cmd, m.start(), cwd), "origin") or "")
        if not dest:
            return None
        out.append(dest)
    return out


_SSH_ARG_OPTS = set("bcDEeFIiJLlmOoPpQRSWw")


def ssh_hosts(cmd: str) -> list[str]:
    hosts = []
    for m in re.finditer(r"\bssh\s+([^;&|]*)", cmd):
        toks = m.group(1).split()
        i = 0
        while i < len(toks):
            tk = toks[i]
            if tk.startswith("-"):
                i += 2 if (len(tk) == 2 and tk[1] in _SSH_ARG_OPTS) else 1
                continue
            hosts.append(tk.strip("'\"").split("@")[-1].lower())
            break
    return hosts


_ASSIGN = re.compile(r"(?:^|[;&|\s])([A-Za-z_][A-Za-z0-9_]*)=(\"[^\"]*\"|'[^']*'|[^\s;&|]+)")


def expand_assignments(cmd: str) -> str:
    """Substitute simple NAME=value assignments made in the same command,
    so 'nas=me@host; ssh $nas' resolves to the host."""
    env = {m.group(1): m.group(2).strip("'\"") for m in _ASSIGN.finditer(cmd)}
    if not env:
        return cmd
    return re.sub(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?", lambda m: env.get(m.group(1), m.group(0)), cmd)


def destinations(t: Tool, tool_input: dict, cwd: str | None = None) -> list[str]:
    """Where a call sends data or writes, as typed strings for allow rules."""
    out: list[str] = []
    if t.name in SHELL_TOOLS:
        cmd = expand_assignments(str(tool_input.get("command") or ""))
        if re.search(r"\bgit\b[^;&|]*\bpush\b|\bgh\s+(pr|issue|release)\b", cmd):
            out += ["git:" + d for d in (git_destinations(cmd, cwd) or [])]
        out += ["ssh:" + h for h in ssh_hosts(cmd)]
        for m in re.finditer(r"\b(scp|rsync|sftp)\b([^;&|]*)", cmd):
            for h in re.findall(r"(?:^|\s)(?:[^\s@:/]+@)?([A-Za-z0-9][A-Za-z0-9.\-]*):", m.group(2)):
                out.append("ssh:" + h.lower())
        if _NET_FETCH.search(cmd):
            out += ["http:" + _host(u) for u in urls_in(cmd) if _host(u)]
    elif t.name == "WebFetch" or (is_browser(t) and tool_input.get("url")):
        h = _host(str(tool_input.get("url") or ""))
        if h:
            out.append("http:" + h)
    elif t.is_mcp:
        out.append(f"mcp:{t.server}/{t.bare}")
    if t.name in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
        fp = str(tool_input.get("file_path") or tool_input.get("notebook_path") or "")
        if fp:
            out.append("path:" + _expand(fp, cwd))
    return list(dict.fromkeys(out))


def trusted_git_destination(cmd: str, cwd: str | None, cfg: dict) -> bool:
    import fnmatch
    pats = [p.lower().rstrip("/") for p in cfg.get("trusted_git_remotes", [])]
    if not pats:
        return False
    dests = git_destinations(cmd, cwd)
    if not dests:
        return False
    return all(any(fnmatch.fnmatchcase(d, p) for p in pats) for d in dests)


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


_WORKTREE = re.compile(r"/\.claude/worktrees/[^/]+(/|$)")


# Claude Code's own session data (transcripts, tool results, uploads) is not
# configuration; only memory/ under projects/ carries instructions.
_CLAUDE_DATA = re.compile(r"/\.claude/(projects/[^/]+/(?!memory/)|uploads/|shell-snapshots/|todos/|debug/)")


def protected_level(path: str, cfg: dict, cwd: str | None = None) -> str | None:
    if not path:
        return None
    p = _expand(path, cwd)
    # Claude Code worktrees live in <repo>/.claude/worktrees/<name>/. Inside one,
    # paths are relative to that worktree root, not to the repo's .claude/ folder.
    p = _WORKTREE.sub("/", p)
    for extra in cfg.get("extra_protected_paths", []):
        if _under(p, _expand(extra)):
            return ALWAYS
    if _any(_ALWAYS_PATTERNS, p):
        return ALWAYS
    if _any(_TAINTED_PATTERNS, p) and not _CLAUDE_DATA.search(p):
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
    r"|\bexfil-guard\b\s+(untaint|clear|disable|uninstall|allow|rules\s+rm)"
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
        # Directory changes are not writes: drop "cd <dir>" and "git -C <dir>".
        cmd = re.sub(r"\b(cd|pushd)\s+(\"[^\"]*\"|'[^']*'|\S+)|\bgit\s+-C\s+(\"[^\"]*\"|'[^']*'|\S+)", " ", cmd)
        for tok in _path_tokens(cmd):
            lvl = protected_level(tok, cfg, cwd)
            if lvl == ALWAYS:
                return (ALWAYS, f"shell write touching {tok}")
            if lvl == TAINTED:
                best = (TAINTED, f"shell write touching {tok}")
        return best
    return None
