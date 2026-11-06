# Security policy

## Reporting a bypass

If you find a way to get data out of a guarded session without an approval prompt, to disable or
modify the guard from inside a session, or to make the hook fail open, please report it
privately through GitHub's [private vulnerability reporting](https://github.com/zerostorypoints/coding-agent-exfil-guard/security/advisories/new)
rather than a public issue.

Include the Claude Code version, OS, the tool calls involved (from `bin/exfil-guard status`) and,
if possible, a minimal fixture that reproduces it. Redact private data.

Known classes of evasion are listed under **Limits** in the README (text matching of shell
commands, unrecognised tool names, runtime-built URLs). Reports that extend those with a concrete
working case are still useful.

## Scope

This project reduces the risk of prompt-injection-driven exfiltration. It is not a sandbox and does
not protect against a malicious user, malicious local software, or a compromised Claude Code or
Python installation.
