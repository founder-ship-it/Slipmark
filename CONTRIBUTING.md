# Contributing to Slipmark

Thanks for helping protect AI features from silent regressions. This guide gets
you productive fast.

## Setup

```bash
npm install
npm run build      # compile to dist/
npm test           # 18+ tests, all should pass
npm run demo       # run the demo pack with a sample git diff
```

Node 22+ is required (the engine uses Node 22 features such as type stripping in
some scripts).

## Project layout

```
src/
  types.ts            core domain-agnostic types (Lock, Pack, report shapes)
  engine/             the engine — knows NOTHING product-specific
    signatures.ts     failure-pattern matching machinery
    scorer.ts         file / module relevance ranking
    confidence.ts     structured confidence + the three-tier honesty cap
    repairPlan.ts     mode-gated coding-agent repair prompt
    bisect.ts         pure "git-bisect for AI behavior" algorithm
    symbols.ts        changed-symbol extraction
    analyze.ts        orchestration → DriftAnalysisReport
    runner.ts         run a pack's locks
  authoring/
    declarative.ts    JSON pack format + pure compiler
  integrations/
    codingAgent.ts    repair-artifact + AGENT_RULES emitters
    gitBisect.ts      git checkout/restore bisection adapter (Node)
    declarativeLoader.ts  JSON pack loader (Node)
  cli.ts              the `slipmark` CLI
packs/                example packs (demo-shop, demo-shop-declarative)
test/                 node:test suites
```

**Golden rule:** the `engine/` and `authoring/declarative.ts` modules must stay
**pure and domain-agnostic** — no product specifics, no Node-only APIs. Anything
that shells out or reads files lives in `integrations/`.

## Adding a lock

- **JSON (no code):** add a lock to a `*.json` pack — see
  [docs/authoring.md](./docs/authoring.md). Fastest path.
- **TypeScript:** add a `LockDefinition` to a pack's `locks`. A good lock:
  - runs against a synthetic fixture (never real user data),
  - asserts both directions (a correct impl passes; a drifted impl fails),
  - instruments itself with an `ExecutionTrace` when it can,
  - declares `watchedSymbols` / `likelyModules` so diagnosis has something to rank.

## Tests

Every change needs a test. Run `npm test`. New engine behavior should assert the
*honesty* guarantees too (e.g. confidence caps), not just the happy path.

## Style

- TypeScript strict mode; no `any` unless genuinely unavoidable.
- Keep the engine dependency-free. New runtime dependencies need a strong reason.
- Match the surrounding comment density and naming.

## Releasing

1. Open a PR that bumps `version` in package.json, moves the changelog's
   Unreleased section under the new version, and updates the version pins
   (README, Action and plugin skills). Merge it once CI is green.
2. Create a GitHub release with the tag `v<version>` on `main`, with
   "Publish this Action to the GitHub Marketplace" ticked.
3. `.github/workflows/publish.yml` then stages it on npm through trusted
   publishing. No npm token, and nothing is published from a laptop. It
   refuses if the tag doesn't match package.json, and runs the full test suite
   first.
4. Approve the staged version on npmjs.com (Staged Packages tab) or with
   `npm stage approve <id>`, with 2FA. Only then does it go live.

## Non-negotiables (the things that make Slipmark trustworthy)

- Never make the engine present a heuristic as proof — respect the confidence caps.
- Never let analysis fabricate a file/module/commit it didn't observe.
- Never weaken the rule that locks/fixtures must not be edited to force a pass.
