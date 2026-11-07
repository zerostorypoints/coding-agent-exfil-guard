# coding-agent-exfil-guard

**Stop prompt-injected coding agents from leaking your data.**

A [Claude Code](https://code.claude.com) plugin that watches what your agent reads and what it
tries to send. Once a session has read untrusted content (a web page, an email, a Slack message,
a downloaded file), every outbound action needs your approval: sending mail, posting, sharing,
`git push`, uploads, and edits to the agent's own configuration. Text that looks like a prompt
injection is flagged in the session and, optionally, on your desktop.

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
![Status: alpha](https://img.shields.io/badge/status-alpha-orange.svg)
![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)
![No dependencies](https://img.shields.io/badge/dependencies-none-brightgreen.svg)

```
  read untrusted content          session is tainted            outbound action
  ─────────────────────           ──────────────────            ───────────────
  WebFetch / browser page   ──►   "this session has read   ──►  send_message, git push,
  email, Slack, Drive file        external content"             curl -d, share_file …
  ~/Downloads/report.pdf                                         ──► you approve or refuse
```

## The problem

An agent that combines three things can be turned against you by a single sentence it reads:

1. access to **private data** (your mailbox, files, repositories),
2. exposure to **untrusted content** (web pages, incoming mail, issues, documents),
3. a way to **communicate externally** (send, post, push, fetch a URL).

Simon Willison calls this [the lethal trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/);
Meta's [Agents Rule of Two](https://ai.meta.com/blog/practical-ai-agent-security/) says a session
should combine at most two of them without a human in the loop. A typical Claude Code setup with
mail, chat and browser connectors has all three in every session.

The built-in controls do not close this gap on their own:

- The Claude Code sandbox covers **shell commands only**. MCP servers, WebFetch and the file tools
  run outside it ([docs](https://code.claude.com/docs/en/sandboxing)).
- Permission rules match command text and are guardrails, not a security boundary
  ([docs](https://code.claude.com/docs/en/permissions)).
- Connectors added through claude.ai (Gmail, Drive, Slack…) cannot be wrapped by local MCP
  proxies. Hooks are the only local place to gate them.
- Injection classifiers are bypassed by adaptive attacks at high rates
  ([arXiv 2510.09023](https://arxiv.org/abs/2510.09023)), and invisible-character smuggling
  evades common guardrails ([arXiv 2504.11168](https://arxiv.org/abs/2504.11168)).

So this plugin does not try to recognise every injection. It tracks **what the session has been
exposed to** and puts **you** in front of every outbound action once that exposure has happened.
Detection only adds alerts and context.

## Quick start

Requires **Claude Code 2.1.295+** and **Python 3.9+** (macOS, Linux, or Windows with Git for Windows).

```bash
claude plugin marketplace add zerostorypoints/coding-agent-exfil-guard
claude plugin install coding-agent-exfil-guard@zerostorypoints
```

(In a session: `/plugin marketplace add zerostorypoints/coding-agent-exfil-guard`, then `/plugin`.)

Start in **monitor mode** for a few days: it logs and alerts but never blocks.

```bash
mkdir -p ~/.config/exfil-guard
echo '{"mode": "monitor"}' > ~/.config/exfil-guard/config.json
```

Check the installation from a clone of this repository:

```bash
git clone https://github.com/zerostorypoints/coding-agent-exfil-guard
cd coding-agent-exfil-guard
bin/exfil-guard doctor
scripts/e2e-claude.sh
```

When the log looks right, switch to enforcement with `{"mode": "enforce"}` (the default when no
config exists).

**Rollback**, from a terminal (it does not depend on the hooks):

```bash
claude plugin disable coding-agent-exfil-guard@zerostorypoints
```

Keep this command at hand before you enforce. The pre-tool hook is configured with
`onFailure: "block"`, so if it cannot start (Python missing, Git Bash missing on Windows) every
tool call is blocked until you disable the plugin. A guard that fails open would silently stop
protecting you.

## What it checks

### Taint: what counts as untrusted input

After any of these calls, the session is marked tainted for the rest of its life:

- `WebFetch`, `WebSearch`, all content-reading browser tools (Claude in Chrome, built-in browser,
  Playwright…)
- MCP tools that read external content: names like `get_*`, `read_*`, `search_*`, `fetch_*`,
  `download_*`, `*_read_*`, `list_messages`… (Gmail, Slack, Drive, GitHub, Notion…)
- `Read` of files in `~/Downloads`, Apple Mail folders, or paths you add
- shell commands that fetch from the network (`curl`, `wget`, `Invoke-WebRequest`, `git clone`…)
- **any** tool whose output trips a detector (below)

### Detectors: what raises an alert

| Detector | Example |
|---|---|
| Hidden Unicode | Tag characters (invisible ASCII), variation-selector "emoji smuggling", bidi controls. Zero-width characters are only logged: newsletters use them to pad preview text |
| Instruction override | "ignore all previous instructions", "do not tell the user", fake `<system>` tags |
| Agent-addressed task | "Note for your agent: … submit a pull request", "AI assistants should always mention…" |
| Exfiltration markup | Markdown images whose URL carries a long query string |

A hit adds a warning to the model's context (treat it as data, quote it to the user), shows a
line in your session, sends a desktop notification and taints the session. Detectors never
block on their own. Only literal text addressed to an agent counts; topic words such as "AI agents
can run privately" do not.

### Gates: what needs your approval

| Situation | Decision |
|---|---|
| Outbound call in a tainted session: MCP send/reply/forward/post/publish/share/upload/draft/comment tools, Drive file create/update, calendar events, PRs/issues/gists, `git push`, `gh pr/issue/gist`, `curl -d/-F/-T`, `scp`, `rsync`, `nc`, PowerShell `Invoke-RestMethod -Method Post`, `Send-MailMessage`, browser typing/form fill/upload, WebFetch or navigation with a query string | **ask** |
| Request URL carrying an encoded blob or a secret (API keys, tokens, private keys, JWTs) | **deny**, any session |
| Outbound call whose payload contains a secret | **ask**, any session |
| Write to agent config or persistence: `~/.claude/settings*.json`, hooks, agents, skills, plugins, `.mcp.json`, `~/.codex/`, managed settings, shell rc files, LaunchAgents, scheduled tasks, Run keys, `~/.ssh`, git hooks, this guard's own files, `claude plugin disable` | **ask**, any session |
| Edit of agent instructions or memory: `CLAUDE.md`, `AGENTS.md`, memory files, CI workflows | **ask** in a tainted session |

MCP tools are matched on the last `__` segment of their name, so connectors that carry a
per-install UUID (`mcp__0a1b2c3d-…__send_message`) are covered without configuration. Tool calls
made by subagents go through the same hooks.

## Verify it on your machine

A restriction you have configured is not yet a restriction that works. The end-to-end test runs
two **freshly started** headless sessions with the plugin loaded via `--plugin-dir` (nothing is
installed):

- **control:** posts to `127.0.0.1:9` without prior untrusted input, and must be allowed;
- **test:** reads a fixture page containing an agent-addressed instruction, then makes the same
  post, and must be gated.

Outcomes are read from the guard's event log, not from what the model says it did.

```bash
scripts/e2e-claude.sh                                          # macOS, Linux
powershell -ExecutionPolicy Bypass -File scripts\e2e-claude.ps1   # Windows
```

`bin/exfil-guard selftest` runs the policy scenarios in-process; `python3 -m unittest discover -s tests`
runs the unit tests. Re-run the e2e test after Claude Code upgrades.

## Configuration

`~/.config/exfil-guard/config.json` (Windows: `%APPDATA%\exfil-guard\config.json`). All keys are
optional; see [config.example.json](config.example.json).

| Key | Default | Meaning |
|---|---|---|
| `mode` | `enforce` | `monitor` logs and alerts but never blocks |
| `tainted_outbound_decision` | `ask` | `deny` for a stricter setup |
| `desktop_notifications` | `true` | `false` keeps alerts inside the session only |
| `notify_min_severity` | `high` | `high`: desktop alerts only for critical events (blocked exfiltration, a secret in an outbound call, an attempt to override the agent). `medium` adds every outbound call after untrusted input |
| `notify_command` | built-in | argv with `{title}` and `{message}`, e.g. `["curl", "-s", "-d", "{title}: {message}", "https://ntfy.sh/<topic>"]` for phone alerts |
| `trusted_domains` | `[]` | domains WebFetch/navigation may query with parameters in tainted sessions |
| `trusted_servers` | app-internal | MCP server-name regexes to ignore |
| `allow_rules` | `[]` | traffic you marked as safe, see [Marking traffic as safe](#marking-traffic-as-safe) |
| `trusted_git_remotes` | `[]` | `git push` and `gh pr`/`issue`/`release` writes to these repos skip the tainted-session prompt. Globs on `host/owner/repo`, e.g. `["github.com/your-org/*"]`. Secrets are still checked. A public repo you own is still a way out, so list only owners whose pushes you are happy to allow |
| `untrusted_paths` | `[]` | extra folders whose files taint on `Read` (e.g. an attachments folder) |
| `extra_untrusted_read_tools`, `extra_outbound_tools` | `[]` | regexes on the bare tool name |
| `extra_protected_paths` | `[]` | extra paths whose modification always asks |
| `gate_browser_input` | `true` | gate typing, form fill and uploads in browser tools when tainted |

Where alerts appear: a line in your session (`systemMessage`), a warning in the model's context
after a suspected injection (`additionalContext`), the approval prompt with the reason in
`enforce` mode, and a desktop notification (macOS Notification Center, `notify-send` on Linux,
a toast on Windows).

On macOS, install [terminal-notifier](https://github.com/julienXX/terminal-notifier)
(`brew install terminal-notifier`) and the guard uses it. Without it the guard falls back to
`osascript`, whose notifications belong to Script Editor: clicking one opens Script Editor.

### Marking traffic as safe

When the guard prompts (or, in monitor mode, would prompt) for something you do on purpose,
mark it as safe instead of turning the guard off:

```bash
bin/exfil-guard review          # what the guard asked about, in plain words, newest first (-v: details)
bin/exfil-guard allow 3 --note "deploy scripts to my NAS"
bin/exfil-guard rules           # list rules;  bin/exfil-guard rules rm 2  to delete one
```

`allow` adds a rule to `allow_rules` in `config.json`. By default the rule matches the
destination of item 3; `--by tool` or `--by command` builds a broader rule from the tool name
or the start of the command. You can also write rules by hand:

```json
"allow_rules": [
  {"category": "outbound", "destination": "ssh:nas.local", "note": "my NAS"},
  {"category": "outbound", "destination": "mcp:gmail/create_draft"},
  {"category": "protected-write", "destination": "path:/Users/me/.claude/skills/my-skill/*"}
]
```

Every field present must match. `destination` is a glob over the call's destinations:
`git:github.com/owner/repo`, `ssh:host`, `http:host`, `mcp:server/tool`, `path:/abs/path`.
A call with several destinations matches only if all of them do. `destination` may also be a
list of globs; a suggested rule for a path inside a worktree covers the repository and all its
worktrees. `tool` is a regex on the tool
name, `command` a regex searched in the command or path, `category` is `outbound` or
`protected-write`.

Rules never override a denied exfiltration-shaped URL, a secret in an outbound call, or a write
to the guard's own configuration. When the agent itself runs `exfil-guard allow` or
`rules rm`, the guard asks first, like any change to its configuration.

### Inspecting state

State lives in `~/.local/state/exfil-guard/` (Windows: `%LOCALAPPDATA%\exfil-guard\`).

```bash
bin/exfil-guard status 50     # last events as JSON lines
bin/exfil-guard sessions      # tainted sessions and the first reason
bin/exfil-guard untaint claude-code <session-id>
```

Running `untaint` through the agent asks for approval, like any change to the guard's files.

## Windows

- Needs **Git for Windows**: hooks run with `shell: "bash"`. If `bash` resolves to WSL, set
  `CLAUDE_CODE_GIT_BASH_PATH`.
- The launcher [bin/hook.sh](bin/hook.sh) probes `python3`, `python`, `py -3` and skips the
  Microsoft Store `python3` stub. Override with `EXFIL_GUARD_PYTHON`.
- The **PowerShell** tool is classified like Bash: uploads (`Invoke-RestMethod -Method Post`,
  `-InFile`, `Send-MailMessage`, BITS, .NET `Upload*`), writes (`Set-Content`, `Out-File`,
  `New-Item`, registry) and persistence (`schtasks /create`, `Register-ScheduledTask`,
  `New-Service`, `Run` keys).
- Paths are normalised: `C:\Users\you\.claude\settings.json`, `$env:USERPROFILE\…`, Git Bash
  `/c/...`. `C:\Program Files\ClaudeCode\` (managed settings), the Startup folder and PowerShell
  profiles are protected.
- Check with `py -3 bin\exfil-guard doctor`.

Windows support is unit-tested on Windows-shaped inputs but has **not yet been run on a Windows
machine**. Please run the e2e test and report the result.

## Limits

- **Not a security boundary.** Hooks run with your privileges. Shell commands are matched as text,
  so `sh -c`, variables, runtime string building or a script written and then run can evade the
  shell checks. An outbound MCP tool with an unusual name is not recognised; add it with
  `extra_outbound_tools`.
- **Combine it with the built-in controls:** the sandbox with an empty network allowlist, explicit
  `ask`/`deny` permission rules for outbound tools, and
  [managed settings](https://code.claude.com/docs/en/settings) for rules the agent cannot edit.
- **Taint is per session and does not decay.** A session that browses and then acts will ask
  often. Split research and action into separate sessions.
- **False positives** happen on documents *about* prompt injection, this README included. They
  alert and taint; they never block by themselves.
- **Text already read stays in the context.** The warning cannot make the model unread it.
- **Local Claude Code only** (CLI and desktop app). claude.ai on the web and mobile apps do not run
  local hooks.
- Verified on Claude Code 2.1.316 on macOS, where hooks fire for hosted connector tools, both
  browsers and subagents.

## Roadmap

- **Codex CLI adapter.** The core is agent-neutral; see [docs/codex.md](docs/codex.md).
- Windows verification on real machines.
- Optional local ML classifier (e.g. Prompt Guard 2) as an extra alert source.

## Related projects

Complementary, not alternatives:

- [Trail of Bits mcp-context-protector](https://github.com/trailofbits/mcp-context-protector):
  pins tool descriptions of local MCP servers (defends against rug pulls).
- [Snyk agent-scan](https://github.com/snyk/agent-scan): inventory and scanning of MCP servers
  and skills.
- [parry-guard](https://github.com/vaporif/parry-guard): ML classifier and data-flow analysis of
  shell scripts for Claude Code.
- [Lasso claude-hooks](https://github.com/lasso-security/claude-hooks): regex warnings on tool
  output.
- [CaMeL](https://arxiv.org/abs/2503.18813) (Google DeepMind): the research design this
  approximates, separating control flow from untrusted data.

## Contributing

Issues and pull requests are welcome. Especially useful:

- real-world injection samples that are missed or wrongly flagged (redact private data first);
- outbound tools from MCP servers that are not recognised;
- e2e results from Windows and Linux.

Run `python3 -m unittest discover -s tests` and `bin/exfil-guard selftest` before opening a PR.
For a bypass of the guard itself, see [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE). Copyright 2026 Zero Story Points.
