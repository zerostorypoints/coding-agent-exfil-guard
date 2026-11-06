# coding-agent-exfil-guard

Taint-gated outbound control for coding agents. Once a session has read untrusted
content (a web page, an email, a chat message, a downloaded file), sending, sharing,
publishing and edits to the agent's own configuration need your approval. Likely
prompt injections and exfiltration-shaped URLs raise a desktop notification.

Status: **alpha (0.1.0)**. Claude Code adapter works and is tested. A Codex CLI adapter is
planned ([docs/codex.md](docs/codex.md)). Python 3 standard library only, no dependencies (tested on Python 3.15, macOS).

## Why

An agent that has **private data**, reads **untrusted content** and has an **outbound
channel** can be steered by text it reads into leaking that data ([the lethal
trifecta](https://simonwillison.net/2025/Jun/16/the-lethal-trifecta/); Meta's
[Agents Rule of Two](https://ai.meta.com/blog/practical-ai-agent-security/)). Real pages already
carry instructions addressed to agents, both visible and hidden.

What the built-in controls do not cover, per Anthropic's own documentation:

- The Claude Code sandbox covers shell commands only. MCP servers, WebFetch and file tools run
  outside it ([sandboxing](https://code.claude.com/docs/en/sandboxing)).
- Permission deny rules match command text and are guardrails, not a security boundary
  ([permissions](https://code.claude.com/docs/en/permissions)).
- Hosted connectors (Gmail, Drive, Slack added through claude.ai) cannot be wrapped by local
  MCP proxies or gateways. Hooks are the only place to gate them.

Injection classifiers are bypassed by adaptive attacks at high rates
([arXiv 2510.09023](https://arxiv.org/abs/2510.09023)), and character smuggling evades common
guardrails ([arXiv 2504.11168](https://arxiv.org/abs/2504.11168)). So detection in this project
only alerts and taints. The gate is behavioural: **untrusted input followed by an outbound
action needs a human**.

## What it does

| Hook | Check | Result |
|---|---|---|
| PostToolUse / PostToolUseFailure | Output came from an untrusted source (WebFetch, WebSearch, browser tools, MCP read/search/get tools, files in `~/Downloads` and Apple Mail folders (add your own with `untrusted_paths`), shell `curl`/`wget`) | Session is **tainted** |
| PostToolUse | Output contains hidden Unicode (tag characters, variation-selector smuggling, zero-width, bidi), instruction-override phrases, text addressed to an agent with a task verb ("Note for your agent: … submit a pull request"), markdown images with query strings | Session tainted, **notification**, warning added to the model's context, message in the UI |
| PreToolUse | Outbound call in a tainted session: MCP tools whose name contains send/reply/forward/post/publish/share/upload/draft/comment/…, Drive file create/update, calendar events, PRs/issues/gists, `git push`, `gh pr/issue/gist`, `curl -d/-F/-T`, `scp`/`rsync`/`nc`, browser typing/form fill/upload, WebFetch or navigation with a query string | **ask** (configurable) + notification |
| PreToolUse | Request URL carries an encoded blob or a secret (API keys, tokens, private keys, JWTs) | **deny** in any session |
| PreToolUse | Outbound call whose input contains a secret | **ask** in any session |
| PreToolUse | Write to agent config or persistence: `~/.claude/settings*.json`, hooks, agents, skills, plugins, `.mcp.json`, `~/.codex/`, managed settings, shell rc files, LaunchAgents, `~/.ssh`, git hooks, `crontab`, this guard's own config and state | **ask** in any session |
| PreToolUse | Edit of agent instructions or memory: `CLAUDE.md`, `AGENTS.md`, memory files, CI workflows | **ask** in a tainted session |

Tool names are matched on their last `__` segment, so hosted connectors with per-install UUIDs
(`mcp__0a1b2c3d-…__send_message`) are covered without configuration. Subagent tool calls fire
the same hooks.

## Install (Claude Code)

Requires Claude Code **2.1.295 or newer**: older versions ignore `onFailure: "block"` and the
pre-tool hook then fails open on errors and timeouts.

```bash
claude plugin marketplace add zerostorypoints/coding-agent-exfil-guard
claude plugin install coding-agent-exfil-guard@zerostorypoints
```

Then, from a clone of this repository, check the installation and run the fresh-session test:

```bash
bin/exfil-guard doctor
```

To try it without installing, start a session with `claude --plugin-dir /path/to/checkout`.

## Verify it on your machine

A rule you have written is not yet a rule that works. Test it in a **freshly started session**,
with a **control run** that proves the test can tell "blocked" from "failed for another reason":

```bash
scripts/e2e-claude.sh
```

It runs two headless sessions with the plugin loaded. The control session posts to
`127.0.0.1:9` (nothing leaves the machine) and must be allowed. The test session first reads a
fixture page carrying an agent-addressed instruction and must then be gated. Both outcomes are
read from the event log, not from the model's own account.

`exfil-guard selftest` runs the policy scenarios in-process.

## Configuration

`~/.config/exfil-guard/config.json` (see [config.example.json](config.example.json)):

| Key | Default | Meaning |
|---|---|---|
| `mode` | `enforce` | `monitor` logs and notifies but never blocks. Use it for the first days to tune. |
| `tainted_outbound_decision` | `ask` | `deny` for a stricter setup |
| `notify_command` | built-in | argv list with `{title}` and `{message}`, e.g. an [ntfy](https://ntfy.sh) `curl` for phone alerts |
| `notify_min_severity` | `medium` | `high` for fewer notifications |
| `trusted_domains` | `[]` | domains WebFetch/navigation may query with parameters in tainted sessions |
| `trusted_servers` | app-internal | MCP server-name regexes ignored entirely |
| `extra_untrusted_read_tools`, `extra_outbound_tools` | `[]` | regexes on the bare tool name |
| `extra_protected_paths`, `untrusted_paths` | `[]` | additional paths |
| `gate_browser_input` | `true` | gate typing, form fill and uploads in browser tools when tainted |

State and the event log live in `~/.local/state/exfil-guard/`:

```bash
exfil-guard status 50     # last events
exfil-guard sessions      # tainted sessions and why
exfil-guard untaint claude-code <session-id>
```

Running `untaint` through the agent asks for approval, as do edits to the guard's own files.

## Limits

- **Not a security boundary.** Hooks run with your privileges, pattern matching on shell commands
  can be evaded (`sh -c`, variables, scripts written then run), and an outbound tool with an
  unusual name is not recognised. Pair this with the built-in sandbox (empty network allowlist)
  and explicit `ask`/`deny` permission rules. For rules the agent cannot edit, put them in
  [managed settings](https://code.claude.com/docs/en/settings).
- **Taint is per session and does not decay.** Long sessions that browse will ask often. That is
  the intended trade-off: split research and action into separate sessions.
- **Detectors produce false positives** on documents *about* prompt injection (security reports,
  this README). They alert and taint; they never block on their own.
- **Content already in the context stays there.** The PostToolUse warning cannot unread text.
- **Claude Code desktop and CLI only.** claude.ai web and mobile do not run local hooks.
- Hooks fire for hosted connector tools in the desktop app (verified on Claude Code 2.1.316,
  macOS). Re-run `scripts/e2e-claude.sh` after upgrades.

## Related work

- [parry-guard](https://github.com/vaporif/parry-guard): Rust, ML classifier, data-flow analysis of
  shell scripts. Complementary; both can be installed.
- [Lasso claude-hooks](https://github.com/lasso-security/claude-hooks): regex warnings on tool output.
- [Trail of Bits mcp-context-protector](https://github.com/trailofbits/mcp-context-protector):
  pins tool descriptions of local MCP servers (rug-pull defence). Recommended alongside.
- [Snyk agent-scan](https://github.com/snyk/agent-scan): inventory and scan of MCP servers and skills.
- [CaMeL](https://arxiv.org/abs/2503.18813): the design this approximates, separating control flow
  from untrusted data.

## License

MIT
