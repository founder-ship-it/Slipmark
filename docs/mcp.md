# Slipmark as an MCP server

`slipmark mcp` serves two tools over the Model Context Protocol, so any coding
agent that speaks MCP can record and check verdicts without shelling out:
OpenAI Codex, Claude Code, Cursor, GitHub Copilot in VS Code, Gemini CLI and
others.

| Tool | What it does |
|---|---|
| `slipmark_attest` | Records a verdict (`pass`, `cleared`, `fail`, `blocked`) on the files the agent read, bound to the SHA-256 of each. Same file format as `slipmark attest`, written to `.slipmark/attestations/`. With a `context` section in the policy, it also records the agent's instructions. |
| `slipmark_verify` | Checks every verdict against the files as they are now, and with `coverageBase` every changed file. Read-only. |

The server runs in the folder it is started in, which should be the
repository root. It makes no network calls, except to check Sigstore
signatures on signed verdicts. The check against GitHub's renderer stays in CI.

It is deliberately narrower than the CLI. An agent can't record a `human`
verdict through it, which is how agent instruction changes are approved, and
it can't run commands (`--run`) or sign. Verdicts it records are `kind: agent`
and always record the agent's context. Each is written to a new file of its
own (`mcp--<by>--<hash>.json`): the server never overwrites a verdict, so an
agent can't replace a person's approval or another reviewer's `fail` by
reusing their name. It refuses to write through a linked `.slipmark` folder.

## Setup

Each snippet starts the server with `npx`. Pin the version, as you would the
Action.

**Claude Code**

```bash
claude mcp add slipmark -- npx -y slipmark@0.7.0 mcp
```

Or use the [Claude Code plugin](../claude-plugin/README.md), which adds skills
and a Stop hook as well.

**OpenAI Codex**, in `~/.codex/config.toml`:

```toml
[mcp_servers.slipmark]
command = "npx"
args = ["-y", "slipmark@0.7.0", "mcp"]
```

**Cursor**, in `.cursor/mcp.json`:

```json
{
  "mcpServers": {
    "slipmark": { "command": "npx", "args": ["-y", "slipmark@0.7.0", "mcp"] }
  }
}
```

**GitHub Copilot in VS Code**, in `.vscode/mcp.json`:

```json
{
  "servers": {
    "slipmark": { "type": "stdio", "command": "npx", "args": ["-y", "slipmark@0.7.0", "mcp"] }
  }
}
```

**Gemini CLI**, in `.gemini/settings.json`:

```json
{
  "mcpServers": {
    "slipmark": { "command": "npx", "args": ["-y", "slipmark@0.7.0", "mcp"] }
  }
}
```

The server must run at the repository root, where agents read their
instructions and CI checks verdicts. It starts in the folder the client starts
it in. If your client starts servers somewhere else (global configs often do),
add `"--root", "/path/to/repo"` to the args, or set `SLIPMARK_ROOT`. Started
inside a repository but not at its root, it refuses to run.

Adding the server to a config file in the repository (`.cursor/mcp.json`,
`.vscode/mcp.json`, `.gemini/settings.json`) changes the agent's context. With
a `context` section in the policy, that change needs an approver's verdict
like any other. That is the point: a pull request shouldn't add MCP servers
for the agent unnoticed, this one included.

## Tell the agent to use it

The tools describe themselves, but agents follow instructions more reliably.
The block `slipmark init` writes into AGENTS.md says to record a verdict after
every review and to verify before handing over. With the server connected,
the agent can do both through the tools instead of `npx`.
