<p align="center"><img src="assets/logo.svg" width="112" alt="Slipmark logo"></p>

# Slipmark

*A [Reply Intelligence Group](https://www.replyintelligencegroup.co.uk/products/slipmark) project.*

**Make AI agents prove what they checked.**

Add it to a workflow:

```yaml
- uses: actions/checkout@v4
- uses: founder-ship-it/Slipmark@v0.7.0
  with:
    require: |
      specs/your-spec.md
```

When a file changes after an agent signed it off, the build refuses:

```
Slipmark verify: 1 verified · 1 refused

  ✓ verified             review-agent verified examples/attestation/brief.md
  ✗ hash_mismatch        security-audit-agent gave "cleared" for a different version of
                         examples/attestation/spec.md. The file changed after the verdict.
```

Set it up in one command: `npx slipmark init`. Your coding agents then write their sign-off with `slipmark attest` (see [Works with your coding agent](#works-with-your-coding-agent)). No model calls, no account, one GitHub Action.

A slip mark is the paint line engineers draw across a bolt once it has been
tightened and checked. If the bolt ever moves, the line breaks and everyone can
see it. Slipmark does the same for AI agent verdicts: once an agent signs off a
file, any change after that breaks the mark.

Agents now review code, audit specs and sign off their own work. The weak point
is the verdict. An agent can report "passed" about a file that has since
changed, or that it never looked at, and nothing downstream can tell.

Slipmark does two things:

1. **Verdict attestation.** Every agent verdict is bound to a SHA-256 hash of
   the exact files the agent read. Before anything ships, the gate re-hashes
   them. Mismatch, missing file, failing verdict, or nothing attested at all:
   it refuses. Deterministic, no model calls, one GitHub Action.
2. **Drift diagnosis.** Behavioural "locks" for your AI features. When a change
   breaks one, Slipmark says what likely broke it, how sure it is (and refuses
   to fake confidence it doesn't have), and hands your coding agent a repair
   prompt.

> Status: `v0.7.0`, early. Apache-2.0. Optional hosted layer: [Slipmark Cloud](#slipmark-cloud).

## Why the gate exists

We run a nightly pipeline of 20+ agents: research, architecture, security
audit, build, QA. Every morning they reported what passed.

Then we found the final verification job had been checking the wrong branch
for months. It could not fail, so it never did. Months of green ticks, proving
nothing.

So we built the gate: bind every verdict to the hash of what it read, and
re-check before shipping. Pointed at 23 open agent pull requests, it refused
all 23.

## What Slipmark proves, and what it doesn't

Slipmark doesn't decide whether your agent is right. It makes sure the verdict
you are trusting is about the code you are shipping.

**It proves:**

- The verdict was given on these exact bytes. Change one and the verdict stops
  counting.
- Every file you require has a current, passing verdict. A missing verdict is
  a refusal, not a silent pass.
- The answer is the same every time. No model calls, no scoring, no judgement.

**It doesn't prove:**

- That the agent was smart. If an agent misses a bug on day one, Slipmark will
  pass that file for as long as it stays unchanged. That is the agent's
  verdict, faithfully kept.
- Who wrote an unsigned attestation. Anyone who can push can write
  `"by": "security-reviewer"`. Require [signed verdicts](#signed-verdicts)
  and only verdicts signed by a workflow you trust count.

So pair it with the checks you already trust. Slipmark is the lock on the
verdict, not the verdict. If you want stronger verdicts, require more of them:
coverage of every changed file, checks Slipmark runs itself, or a re-review
when the model changes. Those are on `main` now
([docs/attestation.md](./docs/attestation.md#coverage-every-changed-file-needs-a-verdict)).
Two independent reviewers on sensitive paths, and the rest of
[attestation v2](./docs/attestation-v2.md), are next.

## Quick start

In the repository you want to protect (Node 22.6 or later):

```bash
npx slipmark init
```

```
  + create .slipmark/attestations/.gitkeep      attestation directory, committed with the repo
  + create .github/workflows/slipmark.yml       report-only gate on pull requests
  + create AGENTS.md                            agent instructions for attesting verdicts
  ~ update CLAUDE.md                            agent instructions for attesting verdicts
```

That is the whole setup:

- **A workflow** that runs the gate on every pull request. It starts in
  report-only mode, because a repo with no verdicts yet would otherwise fail.
  Set `fail-on-refusal: "true"` once your agents are attesting.
- **Agent instructions** in `AGENTS.md`, plus `CLAUDE.md`, Cursor rules or
  Copilot instructions if your repo already has them. Re-running `init` updates
  the block in place and never touches anything else in those files.

Check any time with `npx slipmark verify`. Commit `.slipmark/attestations/`.

## Works with your coding agent

The instructions `init` writes are enough for agents to attest on their own. We
gave Claude Code a plain review task in a fresh repo, with no mention of
Slipmark:

> Review src/export.ts against specs/invoice-export.md. Does it meet the spec?

It read both files, found the export was not CSV, and recorded:

```json
{
  "by": "reviewer",
  "verdict": "fail",
  "subjects": [
    { "path": "src/export.ts", "sha256": "0ea6029f…" },
    { "path": "specs/invoice-export.md", "sha256": "81994e0f…" }
  ],
  "note": "Tenant filter and 10k limit OK; no CSV output, returns raw query result"
}
```

Both files it based the verdict on, not just the one under review. When the
code is fixed, the old verdict stops counting until the agent reads it again.

Setup notes for Claude Code, Cursor, Copilot and Codex are in
[docs/agents.md](./docs/agents.md).

### Claude Code plugin

For Claude Code there is also a plugin. It adds a skill so Claude records
verdicts without any repo instructions, `/slipmark:verify` and
`/slipmark:setup` commands, and a stop check that asks Claude to re-read and
re-attest when a file it signed off has changed since.

```text
/plugin marketplace add founder-ship-it/Slipmark
/plugin install slipmark@slipmark
```

Details, including exactly what it runs, in [claude-plugin/](./claude-plugin/README.md).

### MCP server: Codex, Cursor, Copilot, Gemini

`slipmark mcp` serves `slipmark_attest` and `slipmark_verify` as MCP tools, so
any agent that speaks MCP can record and check verdicts. For OpenAI Codex, in
`~/.codex/config.toml`:

```toml
[mcp_servers.slipmark]
command = "npx"
args = ["-y", "slipmark@0.7.0", "mcp"]
```

Setup for Claude Code, Cursor, Copilot in VS Code and Gemini CLI is in
[docs/mcp.md](./docs/mcp.md). Agents can't record a human approval through it.

## Verdict attestation

**1. The agent attests what it read.** Call this at the end of any agent step
that gives a verdict:

```bash
slipmark attest --by security-audit-agent --verdict cleared \
  --subject specs/invoice-export.md --subject src/export.ts
```

That writes `.slipmark/attestations/<agent>--<file>.json`:

```json
{
  "schema": "slipmark/attestation@1",
  "by": "security-audit-agent",
  "verdict": "cleared",
  "at": "2026-10-17T09:00:00.000Z",
  "subjects": [
    { "path": "specs/invoice-export.md", "sha256": "cf89da70…" }
  ]
}
```

**2. The gate checks it before anything ships.**

```bash
slipmark verify --require specs/invoice-export.md
```

| Result | Meaning |
|---|---|
| `verified` | Passing verdict, and the file is byte-for-byte what the agent saw |
| `hash_mismatch` | The file changed after the verdict. The verdict is about a different file. |
| `subject_missing` | The attested file no longer exists |
| `verdict_not_passing` | The agent said fail or blocked |
| `unattested` | A `--require`d file has no current, passing verdict, or there are no attestations at all |
| `invalid` | Malformed attestation, or a path outside the repo |

Passing verdicts are `pass` and `cleared`. An empty gate is a refusal, never a
silent pass. `--json` prints the full report for other tools.

**Stronger verdicts** (on `main`, unreleased). Record what the verdict was
checked against, and let Slipmark run the checks itself:

```bash
slipmark attest --by reviewer --verdict pass --subject src/export.ts \
  --against specs/invoice-export.md --run "npm test"
```

A failing `--run` refuses a passing verdict. Then require a verdict for every
changed file, not just the ones you listed:

```bash
slipmark verify --coverage diff --base origin/main
```

Details in [docs/attestation.md](./docs/attestation.md#version-2-fields).

### Agent context

Your reviewer passed the code. But who wrote the reviewer's instructions?
The coding-agent attacks of 2026 changed AGENTS.md, skills and MCP configs and
left the reviewed code alone. Add `"context": {}` to `.slipmark/policy.json`
and Slipmark binds each verdict to the agent's instructions too:

- a verdict given under instructions that later changed stops counting
- a change to AGENTS.md, CLAUDE.md, a skill or an MCP config needs an approver's verdict (pair it with CODEOWNERS, or require signed approvals)
- changed instructions must be plain Markdown that GitHub shows in full: an allow-list refuses anything else (HTML, comments, images, diagrams, anything GitHub adds later), and in GitHub Actions each file is checked against GitHub's own renderer
- context files that link outside the watched set are refused

The policy is read from the base branch, so a pull request can't switch this
off. What it doesn't cover yet is listed in the docs. Details in [docs/attestation.md](./docs/attestation.md#agent-context).

See it refuse five real attack patterns (Ghostcommit, Deadbugz, hidden comments,
invisible Unicode, a PR switching the checks off) as open pull requests in
[slipmark-context-demo](https://github.com/founder-ship-it/slipmark-context-demo).

### Signed verdicts

**Prove who gave the verdict, not just what it was about** (on `main`,
unreleased). Run the review agent in a GitHub Actions job and sign as it attests:

```bash
slipmark attest --by security-reviewer --verdict pass --subject src/auth/session.ts --sign
```

The verdict is signed with the job's own GitHub identity through
[Sigstore](https://www.sigstore.dev): no keys to manage, and every signature is
in a public transparency log. Then only count verdicts from the workflow you trust:

```yaml
- uses: founder-ship-it/Slipmark@main
  with:
    require-signed: "true"
    trusted-signers: |
      https://github.com/acme/api/.github/workflows/agent-review.yml@refs/heads/main
```

A verdict typed by hand, made by another workflow, or edited after signing is
refused. Details, including which ref to trust, in
[docs/attestation.md](./docs/attestation.md#signed-verdicts).

**As a GitHub Action:**

```yaml
- uses: actions/checkout@v4
- uses: founder-ship-it/Slipmark@v0.7.0
  with:
    require: |
      specs/invoice-export.md
```

Rolling it out gently? Set `fail-on-refusal: "false"` to report refusals as
warnings without failing the build. The step's `result` output is `passed` or
`refused` either way.

**Formatters.** A formatter run changes the bytes, so it breaks a verdict like any other change. Run
formatters before your agent attests (first in your pre-commit hooks) and most of this goes away.
Formatting-tolerant [hash modes](./docs/hash-modes.md) and re-reviewing only the diff are planned for v0.5.

Run it on the branch you are about to merge. Because it checks content, not
branch names, a verdict produced on one branch can't clear a different tree.

More in [docs/attestation.md](./docs/attestation.md).

## Slipmark Cloud

The gate above is free, open source and needs no account. [Slipmark Cloud](https://app.slipmark.dev)
is the optional hosted layer for teams that need the record, not just the build result:

- **An append-only, hash-chained ledger** of every run, with a proof page per run. Nothing in it can be edited
  or deleted, and the chain heads are published daily to Sigstore's public Rekor log, so anyone can check
  the history wasn't rewritten.
- **It doesn't take CI's word for it.** Cloud re-reads the attestations and the attested files from GitHub's
  own copy of the commit and works out every result again.
- **Rules as a required check.** For example, "changes under `src/auth/**` need a passing verdict from
  `security-reviewer`", posted to the pull request as **Slipmark policy**. Admins can approve a failing
  check, but only with a written reason that goes on the record.
- **Alerts that say what to do.** Slack, Microsoft Teams, Discord, Google Chat, PagerDuty, email, or signed
  webhooks ([Standard Webhooks](https://www.standardwebhooks.com)) to anything else. Each failure names the rule,
  the files, the agent that needs to sign off and the command to fix it. Route by repository and rule, and ping
  the right people. PagerDuty incidents close themselves when the pull request passes.
- **The Slipmark Slack app.** One thread per pull request, and admins can approve a failing check from Slack with
  a written reason that goes on the record.
- **Weekly summary** of runs, blocked pull requests, stale verdicts caught and every override.
- **Insights and audit evidence packs** for SOC 2 CC8.1 and ISO 27001 change-management controls: a PDF for the
  auditor with the JSON attached inside it.

Turn it on by installing the [Slipmark GitHub App](https://github.com/apps/slipmark/installations/new) and
adding two lines to the workflow:

```yaml
jobs:
  verify:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      id-token: write   # GitHub signs a token saying which repo and run this is. No API key.
    steps:
      - uses: actions/checkout@v4
      - uses: founder-ship-it/Slipmark@v0.7.0
        with:
          cloud: "true"
```

`cloud` never changes the gate result. The gate itself is free for every repository, public or private.
Cloud is free for public repositories. Private repositories are £15 a seat a month on Team (minimum 3
seats), with a 14-day free trial. See the
[quick start](https://app.slipmark.dev/docs/quick-start) and
[pricing](https://app.slipmark.dev/#pricing).

## Drift diagnosis: why it's different

Most AI-eval / observability tools focus on **detection** (score outputs, flag a
regression, draw a dashboard). Slipmark's distinctive half is **diagnosis +
repair**, and it is deliberately honest about certainty.

**Confidence is earned, not guessed — a three-tier honesty cap:**

| Evidence available | Confidence ceiling | Meaning |
|---|---|---|
| Signature/pattern only | **0.40** (low/medium) | A heuristic, not proof — `investigate_first` |
| + execution trace | **0.69** (medium) | We know the *mechanism*, not the commit |
| + git diff **or** bisected commit | **uncapped** (up to high) | Causal evidence links it to a specific change |

- **It refuses to fake precision.** At low confidence it **withholds ranked files
  entirely** and flips into an explicit *investigation mode* ("do not apply blind
  fixes").
- **The repair prompt is mode-gated** — `suggest_patch` (high), `minimal_fix`
  (medium), `investigate_first` (low) — so an agent gets the right amount of rope.
- **Anti-gaming:** every prompt forbids editing the lock/fixtures to force a pass.

### Earned causal evidence

When the evidence exists, Slipmark surfaces the smoking gun, not a guess:

- **Execution traces** — a lock instruments itself (modules/symbols exercised,
  observations like `intentSourceUsed="first"`), so diagnosis is backed by what
  the code *actually did*.
- **Bisection** — `bisectFirstFailing()` is a real "git-bisect for AI behavior":
  given a commit history and a probe, it binary-searches the culprit commit in
  ~log₂(n) steps. The host supplies the probe (check out + re-run); the engine
  owns the algorithm.
- **Changed watched-symbols** — a lock declares the symbols its invariant depends
  on; when the diff changes one of them, that's earned evidence the specific code
  behind the behavior moved.

## The drift demo

The demo (`packs/demo-shop`) is an e-commerce support assistant — **deliberately
not the original product** — to prove the engine generalizes. It ships with one
planted regression so you can watch Slipmark catch and diagnose it.

```
Slipmark — pack `demo-shop`
  1 passed · 1 drifted · 0 errored (of 2)
  ✗ shop.latest_intent_wins — drift
      cause: Likely: stale intent carryover …  Probable hot-spot: `…/shopAssist.ts` (85% relevance).
      confidence: high (86%) · severity: high · mode: suggest_patch
```

Flip `PLANTED_BUG` to `false` in `packs/demo-shop/shopAssist.ts` and the lock
turns green.

## How it works

```
locks (your behavioral invariants)
   │  run() → pass / drift + failed assertions
   ▼
engine
   ├─ signatures      match the failure to a known drift pattern   (pack-supplied)
   ├─ scorer          rank changed files + modules by relevance
   ├─ confidence      structured score + honesty caps + tier-gating
   └─ repairPlan      mode-gated, coding-agent-ready repair prompt
   ▼
DriftAnalysisReport  (cause, ranked files/modules, confidence, repair prompt)
```

## Authoring locks — two ways

### 1. Config-only (JSON, no code) — the fastest start

Define a pack in plain JSON and point each lock at a target command that emits
your AI's output. Slipmark runs the command with your fixture on stdin and
asserts on stdout — it does not care what language your system is in:

```jsonc
{
  "id": "my-product",
  "locks": [{
    "key": "support.latest_intent_wins",
    "scope": "ai",
    "invariants": ["When the user pivots topic, the reply addresses the latest intent."],
    "failureSignatures": ["stale_intent_carryover"],
    "watchedSymbols": ["composeReply"],
    "target": { "command": "node assistant.mjs", "inputFormat": "stdin-json" },
    "fixture": { "turns": [/* ... */] },
    "assertions": [
      { "name": "focuses_on_latest_intent", "type": "matches", "value": "track|delivery" },
      { "name": "no_prior_intent_carryover", "type": "not_matches", "value": "return|refund" }
    ]
  }]
}
```

```bash
slipmark ./drift.pack.json --emit .slipmark
```

Assertion types: `contains`, `not_contains`, `matches`, `not_matches`, `equals`,
`not_equals`. Omit `target.command` for "golden mode" (the fixture itself is the
output). See `packs/demo-shop-declarative/` for a complete working example.

### 2. TypeScript (full power)

For arbitrary verification logic, self-instrumenting execution traces, or
in-process targets, define a `Pack` in TypeScript.

### The `Pack` — the entire extensibility story

The engine imports nothing domain-specific. A `Pack` carries it all:

```ts
import { definePack } from "slipmark";

export const myPack = definePack({
  id: "my-product",
  signatures: [ /* how to recognise your drift patterns */ ],
  signatureToModules: { /* signature → modules it implicates */ },
  baseConstraints: [ /* do-not-break rules injected into every repair prompt */ ],
  scopeConstraints: { /* per-scope extra constraints */ },
  scopeImpact: { /* per-scope business impact copy */ },
  signatureGoals: { /* per-signature repair goal */ },
  signatureImpact: { /* per-signature impact */ },
  diffKeywords: [ /* domain words that align a diff to behaviour */ ],
  systemMap: { modules: [ /* your module responsibilities */ ] },
  locks: [ /* your behavioral invariants */ ],
});
```

Swap the pack, point it at a different product — zero engine changes. That is
the whole point of the standalone extraction.

## CLI

```bash
slipmark init [--dry-run] [--no-workflow] [--no-agents] [--force]
slipmark <pack.js> [--git <git-context.json>] [--prompts] [--emit <dir>]
slipmark attest --by <agent> --verdict <pass|cleared|fail> --subject <file>... [--note "..."] [--out <file>]
slipmark verify [--dir .slipmark/attestations] [--require <file>...] [--json]
slipmark bisect --range <git-range> --command "<probe>"
slipmark dashboard <pack> --history <h.json> --out <file.html>
```

Exits non-zero if any lock drifts or errors, so it gates CI. Pass a git context
(changed files since the last passing run) to lift confidence from "signature
heuristic" to "evidence-backed" and reveal ranked files.

## Bisection — find the culprit commit

The engine ships a real "git-bisect for AI behavior". Point it at a range and a
probe command (exit 0 = the lock passes); it binary-searches the commit that
introduced the regression and restores your working tree afterward:

```bash
slipmark bisect --range "main~30..main" \
  --command "npm run build --silent && node dist/src/cli.js dist/packs/demo-shop/pack.js"
```

```
  ✗ first failing commit: deadbeef…
    last good commit:    00aa11bb…
    probes evaluated:    5          # not 30 — ~log2(n)
```

A bisected culprit is the strongest causal evidence Slipmark has: it lifts the
confidence cap and the precise commit range flows into the repair prompt.

## Local dashboard

Slipmark renders a self-contained HTML dashboard: drift trend over runs, lock
status, confidence bars, and drill-down repair prompts, from a local run-history
JSON file. For a shared, hosted view across repositories, see
[Slipmark Cloud](#slipmark-cloud).

```bash
# Run a pack and append the result to a rolling history, then render the dashboard:
slipmark dashboard ./drift.pack.json --history .slipmark/history.json --out dashboard.html

# Or render an existing history file:
slipmark dashboard --from dashboard/sample-history.json --out dashboard/sample.html
```

The `--history` file accumulates runs over time. See `dashboard/sample.html` for a
rendered example.

## Coding-agent integration

`--emit <dir>` writes, for each failing lock:

- `<lockKey>.repair.md` — the ready-to-run repair prompt
- `index.md` — a summary linking every repair
- `AGENT_RULES.md` — drop into `.cursor/rules/` or `CLAUDE.md` so any coding
  agent treats Slipmark prompts safely (respect investigation mode, never edit
  locks to force a pass, re-run locks after changes)

Hand a prompt to Claude Code headlessly:

```bash
claude -p "$(cat .slipmark/shop.latest_intent_wins.repair.md)"
```

This is the wedge: most tools tell you a metric dropped. Slipmark tells your
agent *what likely broke it* and *how to fix it safely* — and refuses to do so
overconfidently when the evidence isn't there.

## Roadmap to "elite"

1. **Deeper causality — built.** Execution traces, real bisection
   (`bisectFirstFailing`), and changed-watched-symbol analysis now feed an
   earned, three-tier confidence model. ✅
2. **Coding-agent integration — built.** `--emit` writes repair prompts +
   `AGENT_RULES`. ✅
3. **Bisection host adapter — built.** `slipmark bisect` / `runGitBisect`
   checks out real commits, runs a probe, and restores the tree. ✅
4. **Self-serve authoring — built.** Define packs in plain JSON with target
   commands and declarative assertions — no TypeScript required. ✅
5. **Dashboard view — built (static).** Self-contained HTML dashboard with drift
   trend, lock status, and drill-down repair prompts, backed by a run-history
   JSON. ✅
6. **Verdict attestation, built.** `slipmark attest` / `verify` and a
   GitHub Action bind agent verdicts to SHA-256 hashes and refuse on mismatch. ✅
7. **Hosted cloud (open-core), built for attestation.** [Slipmark Cloud](#slipmark-cloud):
   ledger, server-side re-verification, rules, alerts, evidence packs. ✅
8. **Attestation v2** *(next)*: which model gave a verdict, checks Slipmark runs itself, coverage of
   every changed file, quorum on sensitive paths, and formatting-tolerant hash modes.

## Developing Slipmark

```bash
npm install
npm test              # 40 tests
npm run demo:verify   # the attestation gate refusing a stale verdict
npm run demo          # drift diagnosis on the demo pack
```

## Documentation

- [Verdict attestation](./docs/attestation.md): the schema, the statuses, wiring agents in.
- [Coding agents](./docs/agents.md): Claude Code, Cursor, Copilot and Codex setup.
- [MCP server](./docs/mcp.md): `slipmark mcp` for any agent that speaks MCP.
- [Attestation v2](./docs/attestation-v2.md) (draft): richer attestations, coverage, quorum, delta re-attestation, human overrides.
- [Hash modes](./docs/hash-modes.md) (draft): formatting-tolerant hashing, chosen per path by policy.
- [Concepts](./docs/concepts.md) — the mental model (locks, packs, signatures,
  the honesty model, repair prompts).
- [Authoring guide](./docs/authoring.md) — JSON and TypeScript packs, assertion
  types, bisection wiring.
- [Contributing](./CONTRIBUTING.md) — setup, layout, the non-negotiables.
- [Changelog](./CHANGELOG.md).

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE). The reasoning
behind the choice is in [LICENSE-OPTIONS.md](./LICENSE-OPTIONS.md).

---

Slipmark is built by [Reply Intelligence Group](https://www.replyintelligencegroup.co.uk/products/slipmark), Watford, UK. © 2026 Reply Intelligence Group Ltd.
