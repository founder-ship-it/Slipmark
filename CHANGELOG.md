# Changelog

All notable changes to Slipmark (formerly DriftGuard) are documented here.

## [Unreleased]

## [0.7.0] - 2026-11-12

In-toto interoperability: Slipmark verdicts as in-toto Statements, and one
gate over a Bundle that holds them alongside other tools' attestations,
starting with Codapult Guard (#32).

### Added
- **`slipmark verify-bundle`** checks a combined in-toto Bundle against a new
  `bundle` section in the policy: each required predicate type needs at least
  one entry, every entry of a required type must be signed by a listed signer
  and hold against this checkout, and malformed lines refuse. Built-in checks
  for Slipmark verdicts and for [Codapult Guard](https://github.com/codapult/codapult-guard)
  verification receipts (predicate v1), including Guard's scope fingerprint,
  the pull request revisions and every file Guard hashed. Part of #32.
- **`export-intoto --format sigstore`** writes full Sigstore bundles, which keep
  the signer, and **`--include`** adds other tools' lines, for example Guard's
  `.sigstore.jsonl`.
- **`attest --sign-format intoto`** signs an in-toto Statement v1 instead of
  Slipmark's own attestation: the attested files and their SHA-256 as
  `subject`, the verdict as the predicate
  (`https://github.com/founder-ship-it/Slipmark/attestation/v1`). Any in-toto
  tool can read it. `verify` checks it exactly like the default format.
- **`slipmark export-intoto`** writes Statement-signed verdicts as an in-toto
  Bundle (`.intoto.jsonl`), one DSSE envelope per line, so they can sit next to
  other tools' attestations. Part of #32.

### Fixed
- An attestation file with malformed `subjects`, or a signature envelope whose
  `payload` isn't a string, is now refused as `invalid`. Before, one such file
  made `verify` stop with exit 2, so a single committed file could block the
  gate for every pull request. It never let a change through.

## [0.6.2] - 2026-11-02

Follow-ups from the independent review of v0.5 (#14). None of these let a
change through the gate.

### Security
- **`attest --out` and `--dir` stay inside the repository.** They could write
  anywhere, so an agent talked into passing `--out ~/.bashrc` or
  `--out package.json` would overwrite it with JSON. The target must now be a
  `.json` file inside the repository, and anything already there must be an
  attestation. Otherwise `attest` exits 2 and writes nothing.

### Fixed
- **`--note` followed by another flag** (`--note --against b.ts`) recorded the
  flag as the note. A bare flag after `--note` is now a missing value. Notes
  that merely start with `--` still work.
- **On a pull request, a coverage base that is the pull request's own commit**
  (`HEAD~0`, the branch's own name) would cover nothing. `verify` now exits 2
  instead. On a push to main, where base and HEAD are the same, it still runs.

### Changed
- **A folder's own policy replacing the root one is now reported.** Running
  from a subfolder with its own `.slipmark/policy.json` uses that policy only.
  The report now says the root's policy wasn't read, and the docs explain the
  rule. A pull request still can't add a folder policy to escape the root's.
- Two long lines in docs/attestation.md are wrapped.

## [0.6.1] - 2026-10-30

### Added
- **Listed in the official MCP Registry** as
  `io.github.founder-ship-it/slipmark`, so MCP clients and directories can
  find the server. `server.json` describes it, and package.json carries the
  matching `mcpName` the registry checks.
- **Releases publish from GitHub, with provenance.** A GitHub release stages
  the version on npm through trusted publishing, with no npm token anywhere,
  and it goes live once a maintainer approves it with 2FA. See CONTRIBUTING.

## [0.6.0] - 2026-10-30

### Security
- **`slipmark attest` never writes through a link inside the repository.** A
  pull request could commit a link at an attestation's file name, or make
  `.slipmark/` a link, so attesting in that checkout wrote a file outside the
  repository. A link at the file, or at any folder between the top of the
  repository and it, is now refused before anything is created, and the file
  is written to a temporary name then renamed into place. Found in review of
  the MCP server.

### Added
- **`slipmark mcp`**: an MCP server on stdio with two tools, `slipmark_attest`
  and `slipmark_verify`, so Codex, Cursor, Copilot, Claude Code, Gemini CLI and
  any other MCP client can record and check verdicts. Verdicts it records are
  `kind: agent`; it can't record a human approval, run commands or sign. No
  network calls except Sigstore checks of signed verdicts, and no new runtime
  dependencies. Setup in [docs/mcp.md](./docs/mcp.md).

### Changed
- **Claude Code plugin: Claude knows when its instructions changed.** When
  the policy has a `context` section, the plugin's Stop hook now also flags
  verdicts given under a different AGENTS.md, CLAUDE.md, skill, hook or MCP
  config, asks Claude to read the changed instructions before attesting again,
  and to tell the user, since a person has to approve them. It reads only the
  context file list from the working tree's policy; approvals, hidden content
  and coverage stay with the CI gate, which reads the policy from the base
  branch. Update with `/plugin marketplace update slipmark`.
- The npm package now includes this changelog.

## [0.5.0] - 2026-10-25

### Security
- **The policy is read from the base branch** (thanks Kent Bodrov). Before,
  `verify` read `.slipmark/policy.json` from the pull request's own checkout,
  so a PR could loosen the rules it was judged by, for example by dropping a
  required path. Now the policy comes from `--policy-from <ref>`, the coverage
  base, or the pull request's base branch in GitHub Actions (the Action
  fetches it). A branch that changes the policy gets a notice and the change
  applies after merge. Local runs with no base behave as before.
  `--policy-from working-tree` restores the old behaviour. Subfolder runs
  read that folder's policy from the base, as they do from disk. The pull
  request's base is looked up by its full ref name, so a tag can't pose as it.
- Every report records the policy that decided it: `policy.source`,
  `policy.ref` and `policy.sha256`, in `--json` output and in Slipmark Cloud.

### Added
- **Agent context.** A `context` section in the policy binds verdicts to the
  agent's instructions as well as the files it read: AGENTS.md, CLAUDE.md,
  skills, hooks, Cursor rules and MCP configs. `attest` records their hashes.
  A verdict given under instructions that later changed is refused
  (`context_changed`). A context file changed since the base needs an approver's
  verdict, or signed approvals with `approverSigners`
  (`context_unapproved`). Changed context with text hidden from reviewers
  (invisible or smuggling Unicode, HTML comments, Markdown comments, blank
  padding, images) is refused (`hidden_content`). Links in agent context are
  refused unless they point at other context files, and so are submodules.
  Changed agent instructions must be plain Markdown GitHub shows in full: an
  allow-list of constructs (anything unknown is refused, including anything
  GitHub adds later), pattern checks as a second net, and, in GitHub Actions,
  a comparison with GitHub's own Markdown renderer. Approvers can acknowledge
  flagged content with a signed verdict. Covers the patterns behind the
  Ghostcommit, Deadbugz and TrustFall attacks of 2026.
- `require` in `.slipmark/policy.json`: required paths kept with the policy,
  so they are read from the base branch too. The Action's `require` input is
  in the workflow file, which a pull request can still edit.
- The Action's `policy-from` input.
- **Diff coverage.** `slipmark verify --coverage diff --base <ref>` refuses
  any file changed since the base that no current, passing verdict covers
  (new status `uncovered`). `--ignore <glob>` leaves paths out. The Action
  gains `coverage-base` and `coverage-ignore` inputs.
- **`.slipmark/policy.json`** (`slipmark/policy@1`): coverage settings and
  `models.allow`. Read automatically by `verify`, `upload` and the Action;
  `--no-policy` skips it.
- **Attestation v2 fields**, written only when used, so `@1` stays the
  default: `--against <file>` (status `against_changed`), `--run "<cmd>"`
  (Slipmark runs it and records exit code and output hash),
  `--check "<cmd>=<code>"` (a recorded claim), `--model` /
  `SLIPMARK_MODEL`, `--harness`, `--kind`. A passing verdict is refused when
  any check failed. `verify` reads `@1` and `@2`; new statuses
  `check_failed` and `model_not_allowed`.
- `verify` exits 2 when it can't run (malformed policy, coverage base not in
  the checkout) instead of reporting a refusal.
- **Signed verdicts.** `slipmark attest --sign` signs the attestation with the
  job's own identity through Sigstore keyless signing (GitHub Actions with
  `id-token: write`, or `SIGSTORE_ID_TOKEN`). The bundle is stored in the
  attestation's `signature` field and logged in Rekor. `verify` checks every
  signature: one that fails, or an attestation edited after signing, refuses as
  `signature_invalid`. `--require-signed` with `--trusted-signer <identity>`
  (or `signatures` in the policy file, or the Action's `require-signed` and
  `trusted-signers` inputs) counts only verdicts signed by a trusted workflow;
  others refuse as `unsigned` or `signer_not_trusted`. Verified results name
  their signer.

### Changed
- The Claude Code plugin's stop hook also flags verdicts whose `--against`
  files changed, and ignores the policy so a missing coverage base never
  silences it.
- `upload` receives the same `--require` and coverage settings as `verify`, so
  Cloud records the same report as the gate.

## [0.4.0] - 2026-10-23

### Security
- Subject paths are now resolved through symlinks and re-checked against the
  real repository root. A symlink inside the repository that points outside it
  was previously followed and hashed. Found by a Claude Code review of
  `attestation.ts` against `docs/attestation.md`.

### Fixed
- File names that merely start with `..` (for example `..notes.md`) are no
  longer rejected as escaping the repository.

### Added
- Slipmark gates its own code: `.slipmark/attestations/` holds a real review
  verdict, required by CI and recorded in Slipmark Cloud.
- `slipmark upload` and the Action's `cloud` input record runs in Slipmark
  Cloud (app.slipmark.dev) using the GitHub Actions OIDC token.
- **Claude Code plugin** in `claude-plugin/`, installable from this repo as a
  marketplace (`/plugin marketplace add founder-ship-it/Slipmark`). A skill
  that records verdicts, `/slipmark:verify`, `/slipmark:setup`, and a Stop hook
  that asks Claude to re-attest when an attested file has changed. Commands are
  pinned to `slipmark@0.4.0`.

## [0.3.0] - 2026-10-22

### Added
- **`npx slipmark init`** sets up a repository in one command: the
  attestation directory, a GitHub workflow and instructions for coding agents.
  The workflow starts in report-only mode, because a repository with no
  verdicts yet would otherwise fail its first run.
- **Agent instructions** in `AGENTS.md`, and in `CLAUDE.md`, Cursor rules or
  Copilot instructions when the repository already uses them. The block is
  fenced with markers, so re-running `init` updates it in place.
- `slipmark --help` and `slipmark --version`.
- [docs/agents.md](./docs/agents.md): setup for Claude Code, Cursor, Copilot
  and Codex, and how to check agents are attesting.
- Published to npm as `slipmark`.

### Changed
- `verify` with no attestations at all now explains how to record the first
  one instead of telling you to re-run the agent.
- `attest` prints the path it wrote relative to the current directory.

## [0.2.0] - 2026-10-17

### Changed (breaking)
- **Renamed DriftGuard to Slipmark.** A slip mark is the paint line engineers
  draw across a tightened bolt: if the bolt moves, the line breaks. "DriftGuard"
  is a registered trade mark of other companies for related software.
- CLI command `driftguard` is now `slipmark`.
- Default attestation directory `.driftguard/attestations` is now
  `.slipmark/attestations`.
- Attestation schema `driftguard/attestation@1` is now `slipmark/attestation@1`.
- GitHub Action: `uses: founder-ship-it/Slipmark@v0.2.0`.
- New logo, social preview and Marketplace icon.

## [0.1.2] - 2026-10-17

### Changed
- Brand: RIG-style logo and social preview in `assets/`; Marketplace icon is now
  `hash` in `gray-dark` to match.

## [0.1.1] - 2026-10-17

### Added
- Action output `result` (`passed` or `refused`) and a report-only mode,
  `fail-on-refusal: "false"`, for rolling DriftGuard out without blocking builds.

### Changed
- CI demo steps now pass only when DriftGuard refuses the planted problems,
  instead of showing as errors on the Actions page.

## [0.1.0] - 2026-10-17

### Added
- **Verdict attestation gate.** `driftguard attest` records an agent's verdict
  with the SHA-256 of every file it read. `driftguard verify` re-hashes them on
  the current tree and refuses on `hash_mismatch`, `subject_missing`,
  `verdict_not_passing`, `unattested` (`--require`) or `invalid`. An empty gate
  refuses rather than passing. Subject paths outside the repo are rejected.
- **GitHub Action** (`action.yml`): `uses: founder-ship-it/driftguard@v0.1.0`.
- Worked example in `examples/attestation/` with one deliberately stale verdict;
  `npm run demo:verify`.
- 10 tests for the gate, including the wrong-branch scenario.

### Changed
- **License: MIT to Apache-2.0** (explicit patent grant). Added `NOTICE`.
- `package.json`: `bin`, `main` and `types` now point at `dist/src/`, where the
  build actually writes them.
- **Self-serve authoring** — define packs in plain JSON with target commands and
  declarative assertions (`contains`, `not_contains`, `matches`, `not_matches`,
  `equals`, `not_equals`); golden mode for recorded outputs. No TypeScript needed.
- **Git bisection host adapter** — `driftguard bisect` / `runGitBisect` checks out
  real commits, runs a probe, finds the culprit in ~log₂(n) steps, and restores
  the working tree.
- **Earned causal evidence** — execution traces (self-instrumenting locks),
  changed-watched-symbol detection, and a real bisection signal, feeding a
  three-tier honesty cap (no evidence 0.40 → trace-only 0.69 → diff/bisect
  uncapped). Repair prompts gain a "Causal evidence" section.
- **Coding-agent integration** — `--emit` writes per-lock repair prompts, an
  index, and an `AGENT_RULES` doc; Claude Code invocation helper.
- **Domain-agnostic engine + `Pack` model** — signatures, scorer, confidence,
  repair-prompt generator; ships a non-product demo proving generalization.
- Docs: `docs/concepts.md`, `docs/authoring.md`, `CONTRIBUTING.md`.

### Fixed
- CI workflow no longer fails on the demo pack's intentional planted drift
  (informational step).

## [0.0.1]
- Initial scaffold.
