# Codex CLI adapter (planned)

Codex CLI has `PreToolUse`/`PostToolUse` hooks with a JSON shape close to Claude Code's,
configured in `~/.codex/hooks.json` or `[hooks]` in `config.toml`; new hooks must be trusted
with `/hooks`. Not yet verified against OpenAI's documentation
(<https://developers.openai.com/codex/hooks>); third-party write-ups report:

- `PreToolUse` supports `deny` but not `ask`. The adapter will map the core's `ask` to `deny`
  with a reason telling the model to ask the user to approve the action explicitly, or rely on
  Codex's own approval policy. This makes Codex stricter than Claude Code by default.
- Tool names differ (shell, patch application, MCP tools). The core classifies on bare names,
  so mostly a mapping table is needed.
- Protected paths already include `~/.codex/` and `AGENTS.md`.

Plan: first a log-only probe (as was done for Claude Code) to record real tool names and
payloads, then `src/exfil_guard/adapters/codex.py`, an installer that writes the hook entries,
and `scripts/e2e-codex.sh` with the same control-run structure.
