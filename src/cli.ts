#!/usr/bin/env node
/**
 * Minimal Slipmark CLI.
 *
 *   slipmark init [--dry-run] [--no-workflow] [--no-agents] [--force]
 *   slipmark <pack.ts|pack.js> [--git <git-context.json>] [--prompts]
 *   slipmark attest --by <agent> --verdict <pass|fail> --subject <file> [--subject <file>...] [--against <file>...] [--run "<cmd>"...] [--note "..."] [--out <file>]
 *   slipmark verify [--dir .slipmark/attestations] [--require <file>...] [--coverage diff --base <ref>] [--json]
 *
 * Loads a pack module (default export OR a named *Pack export), runs every lock,
 * prints a summary, and (with --prompts) prints the repair prompt for each drift.
 *
 * Exit code is non-zero if any lock drifts or errors — so it gates CI.
 */
import { readFileSync, mkdirSync, writeFileSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { resolve, join, relative } from "node:path";
import { runPack, repairArtifactsFor, repairIndexDoc, agentRulesDoc, claudeCodeCommandFor, runGitBisect, loadDeclarativePack, summariseRun, appendRun, renderDashboardHtml } from "./index.js";
import type { GitContext, Pack } from "./types.js";
import type { VerificationRun } from "./engine/runner.js";
import type { DashboardData } from "./dashboard/data.js";
import { createAttestation, writeAttestation, checkAttestationTarget, defaultAttestationPath, verifyWithSignatures, resolvePolicy, loadPolicy, POLICY_SCHEMA, type Policy, type PolicySource, type VerifyReport, type AttesterKind } from "./attest/attestation.js";
import { signAttestation } from "./attest/signing.js";
import { existsSync } from "node:fs";
import { planInit, applyInit } from "./init.js";
import { uploadRun, summaryMarkdown } from "./cloud/upload.js";
import { appendFileSync } from "node:fs";
import { serveMcp, mcpRoot } from "./mcp.js";

/** Version from the package this CLI ships in (dist/src/cli.js → ../../package.json). */
function version(): string {
  try {
    return (JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")) as { version: string }).version;
  } catch {
    return "unknown";
  }
}

const HELP = `Slipmark: make AI agents prove what they checked.

Usage
  slipmark init                 Wire Slipmark into this repo (workflow + agent instructions)
  slipmark attest ...           Record a verdict bound to the SHA-256 of the files it covers
  slipmark verify               Refuse if any verdict is about different files from these
  slipmark mcp [--root <dir>]   Serve attest and verify as MCP tools on stdio (Codex, Cursor, Copilot, Claude, Gemini)
  slipmark upload               Record this CI run in Slipmark Cloud (GitHub Actions, id-token: write)
  slipmark <pack>               Run drift diagnosis locks
  slipmark bisect ...           Find the commit where a probe started failing
  slipmark dashboard ...        Render a drift history dashboard

attest
  --by <agent> --verdict <pass|cleared|fail|blocked> --subject <file> [--subject <file>...]
  [--against <file>...]      files the verdict was checked against (a spec, a checklist)
  [--run "<command>"...]     run a check now and record its exit code and output hash
  [--check "<command>=<exit code>"...]  record a check the agent says it ran (a claim)
  [--model <name>] [--harness <name>] [--kind agent|tool|human]
  [--note "..."] [--dir .slipmark/attestations] [--out <file>]
  [--sign]                   sign it with this job's identity (GitHub Actions, id-token: write)
  [--acknowledge-hidden]     approver: you've read text in these files that GitHub hides
                             (comments, link definitions, images) and accept it
  [--context | --no-context] record the agent's context (AGENTS.md, CLAUDE.md, skills, MCP
                             configs). On by default for agents when the policy has "context"
  A passing verdict is refused if any --run or --check exited non-zero.

verify
  [--dir .slipmark/attestations] [--require <file>...] [--json]
  [--coverage diff --base <ref> [--ignore <glob>...]]  every changed file needs a verdict
  [--require-signed --trusted-signer <identity>...]  only count verdicts signed by these
  [--policy-from <ref|working-tree>]  where to read .slipmark/policy.json. Default: the
                             coverage base or the pull request's base branch when known,
                             so a branch can't loosen its own rules; else this checkout
  [--no-policy]              ignore .slipmark/policy.json
  Exit 0: every verdict matches the files as they are now. Exit 1: refused.
  Exit 2: could not run (bad input, or the coverage base is missing).

upload
  [--dir .slipmark/attestations] [--require <file>...] [--url <ingest url>] [--strict]
  Never changes the gate result unless --strict is passed.

init
  [--dry-run] [--no-workflow] [--no-agents] [--force]

Docs: https://github.com/founder-ship-it/Slipmark
`;

/**
 * The policy for this run: `.slipmark/policy.json` (unless --no-policy), with
 * `--coverage diff --base <ref> [--ignore <glob>...]` overriding its coverage.
 */
function policyFromArgs(args: string[]): { policy: Policy | null; info: PolicySource } {
  let policy: Policy | null;
  let info: PolicySource;
  const mode = argVal(args, "--coverage");
  try {
    if (args.includes("--no-policy")) {
      policy = null;
      info = { source: "none", notes: ["--no-policy: .slipmark/policy.json was skipped"] };
    } else {
      // In a pull request the policy comes from the branch being merged into, so the
      // PR can't loosen its own rules. Base candidates: --policy-from, then the
      // coverage base, then the pull request's base branch in GitHub Actions.
      const from = argVal(args, "--policy-from") ?? undefined;
      const candidates: string[] = [];
      if (mode) { const b = argVal(args, "--base"); if (b) candidates.push(b); }
      // The full ref name: a tag called origin/main must never stand in for the base branch.
      if (process.env.GITHUB_BASE_REF) candidates.push(`refs/remotes/origin/${process.env.GITHUB_BASE_REF}`);
      ({ policy, info } = resolvePolicy({ root: process.cwd(), from, candidates }));
    }
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  if (mode) {
    if (mode !== "diff") fail(`--coverage only supports "diff", not ${mode}`);
    const base = argVal(args, "--base");
    if (!base) fail("--coverage diff needs --base <ref>, for example --base origin/main");
    policy = { ...(policy ?? { schema: POLICY_SCHEMA }), coverage: { mode: "diff", base: base!, ignore: argVals(args, "--ignore") } };
  }
  const trusted = argVals(args, "--trusted-signer");
  if (args.includes("--require-signed") || trusted.length) {
    if (args.includes("--require-signed") && !trusted.length && !policy?.signatures?.trusted?.length) {
      fail("--require-signed needs --trusted-signer <identity>, for example https://github.com/acme/api/.github/workflows/review.yml@refs/heads/main");
    }
    const sig = { ...(policy?.signatures ?? {}) };
    if (args.includes("--require-signed")) sig.require = true;
    if (trusted.length) sig.trusted = trusted;
    policy = { ...(policy ?? { schema: POLICY_SCHEMA }), signatures: sig };
  }
  return { policy, info: info! };
}

/** The gate, signatures included, with input problems (bad policy, missing base, Sigstore unreachable when required) reported as exit 2. */
async function runVerify(args: string[]): Promise<VerifyReport> {
  try {
    const { policy, info } = policyFromArgs(args);
    return await verifyWithSignatures({ dir: argVal(args, "--dir") ?? undefined, require: argVals(args, "--require"), policy, policySource: info });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
}

/** `slipmark upload [--dir d] [--require f...] [--url u] [--strict]` */
async function uploadMain(args: string[]): Promise<void> {
  const dir = argVal(args, "--dir") ?? ".slipmark/attestations";
  const report = await runVerify(args);
  const result = await uploadRun({
    dir,
    require: argVals(args, "--require"),
    url: argVal(args, "--url") ?? undefined,
    clientVersion: version(),
    report,
  });
  console.log(`\nSlipmark Cloud: ${result.message}\n`);
  if (process.env.GITHUB_STEP_SUMMARY) {
    try { appendFileSync(process.env.GITHUB_STEP_SUMMARY, summaryMarkdown(report, result)); } catch { /* summary is best-effort */ }
  }
  if (process.env.GITHUB_OUTPUT && result.url) {
    try { appendFileSync(process.env.GITHUB_OUTPUT, `proof-url=${result.url}\n`); } catch { /* best-effort */ }
  }
  if (!result.ok && process.env.GITHUB_ACTIONS) console.log(`::warning title=Slipmark Cloud::${result.message}`);
  process.exit(!result.ok && args.includes("--strict") ? 1 : 0);
}

/** `slipmark init [--dry-run] [--no-workflow] [--no-agents] [--force]` */
function initMain(args: string[]): void {
  const root = process.cwd();
  const plan = planInit({
    root,
    actionRef: `v${version()}`,
    workflow: !args.includes("--no-workflow"),
    agents: !args.includes("--no-agents"),
    force: args.includes("--force"),
  });
  const dry = args.includes("--dry-run");
  console.log(`\nSlipmark init${dry ? " (dry run, nothing written)" : ""}\n`);
  for (const f of plan) {
    const mark = f.action === "skip" ? "·" : f.action === "create" ? "+" : "~";
    console.log(`  ${mark} ${f.action.padEnd(6)} ${f.path.padEnd(36)} ${f.reason}`);
  }
  if (dry) return;
  applyInit(root, plan);
  console.log(`
  Next
    1. Commit these files, including .slipmark/attestations/.
    2. Your agents now attest verdicts with: npx slipmark attest --by <role> --verdict pass --subject <file>
    3. Check any time with: npx slipmark verify
    4. The workflow starts in report-only mode. Set fail-on-refusal to "true" to enforce.
`);
}

function fail(msg: string): never {
  console.error(`slipmark: ${msg}`);
  process.exit(2);
}

async function loadPack(modPath: string): Promise<Pack> {
  // Declarative JSON pack → no code required.
  if (modPath.endsWith(".json")) return loadDeclarativePack(modPath);

  const url = pathToFileURL(resolve(modPath)).href;
  const mod = (await import(url)) as Record<string, unknown>;
  const candidate =
    (mod.default as Pack | undefined) ??
    (Object.values(mod).find(
      (v) => v && typeof v === "object" && "id" in (v as object) && "locks" in (v as object),
    ) as Pack | undefined);
  if (!candidate) fail(`no Pack export found in ${modPath}`);
  return candidate;
}

function loadGit(path: string | null): GitContext | null {
  if (!path) return null;
  try {
    return JSON.parse(readFileSync(resolve(path), "utf8")) as GitContext;
  } catch (e) {
    fail(`could not read git context ${path}: ${e instanceof Error ? e.message : String(e)}`);
  }
}

/** A flag's value. A flag given with no value (or followed by another flag) is an error, never ignored. */
function argVal(args: string[], flag: string, opts: { freeText?: boolean } = {}): string | null {
  const i = args.indexOf(flag);
  if (i < 0) return null;
  const v = args[i + 1];
  // Free text may start with "--", but a bare flag ("--note --against b.ts") means the value is missing.
  if (v === undefined || (opts.freeText ? /^--[a-z][a-z-]*$/.test(v) : v.startsWith("--"))) fail(`${flag} needs a value`);
  return v!;
}

/** `slipmark bisect --range <range> --command <cmd> [--cwd <dir>]` */
async function bisectMain(args: string[]): Promise<void> {
  const range = argVal(args, "--range");
  const command = argVal(args, "--command");
  const cwd = argVal(args, "--cwd") ?? process.cwd();
  if (!range || !command) {
    fail('usage: slipmark bisect --range <git-range> --command "<probe cmd, exit 0 = pass>" [--cwd <dir>]');
  }
  console.log(`\nSlipmark bisect — range \`${range}\`\n  probe: ${command}\n`);
  const result = await runGitBisect({ cwd, range: range!, command: command! });
  if (!result.firstFailingCommit) {
    console.log(`  ✓ no regression in this range (newest commit still passes). ${result.evaluated} probes.\n`);
    process.exit(0);
  }
  console.log(`  ✗ first failing commit: ${result.firstFailingCommit}`);
  console.log(`    last good commit:    ${result.lastPassingCommit ?? "(regression predates range)"}`);
  console.log(`    probes evaluated:    ${result.evaluated}\n`);
  process.exit(1);
}

/**
 * `slipmark dashboard <pack> [--git f] [--history h.json] [--project name] --out file.html`
 * or render existing history: `slipmark dashboard --from h.json --out file.html`
 */
async function dashboardMain(args: string[]): Promise<void> {
  const out = argVal(args, "--out") ?? "dashboard.html";
  const from = argVal(args, "--from");
  const project = argVal(args, "--project");

  let data: DashboardData;
  if (from) {
    data = JSON.parse(readFileSync(resolve(from), "utf8")) as DashboardData;
  } else {
    const packPath = args.find((a) => !a.startsWith("--"));
    if (!packPath) fail("usage: slipmark dashboard <pack> [--history h.json] --out f.html  |  slipmark dashboard --from h.json --out f.html");
    const pack = await loadPack(packPath!);
    const run = runPack(pack, loadGit(argVal(args, "--git")));
    const summary = summariseRun(run, { project: project ?? pack.id });

    const historyPath = argVal(args, "--history");
    const prior =
      historyPath && existsSync(resolve(historyPath))
        ? (JSON.parse(readFileSync(resolve(historyPath), "utf8")) as DashboardData)
        : null;
    data = appendRun(prior, summary, project ?? pack.id);
    // Persist the history file — this flat file IS the "backend" today.
    if (historyPath) writeFileSync(resolve(historyPath), JSON.stringify(data, null, 2), "utf8");
  }

  writeFileSync(resolve(out), renderDashboardHtml(data), "utf8");
  console.log(`\n  dashboard written → ${out}  (${data.runs.length} run(s))`);
  console.log(`  open it: file://${resolve(out)}\n`);
}

function argVals(args: string[], flag: string): string[] {
  const out: string[] = [];
  args.forEach((a, i) => {
    if (a !== flag) return;
    const v = args[i + 1];
    if (v === undefined || v.startsWith("--")) fail(`${flag} needs a value`);
    out.push(v!);
  });
  return out;
}

/** `slipmark attest --by <agent> --verdict <v> --subject <file>... [--note t] [--out f] [--dir d] [--sign]` */
async function attestMain(args: string[]): Promise<void> {
  const by = argVal(args, "--by");
  const verdict = argVal(args, "--verdict");
  const subjects = argVals(args, "--subject");
  if (!by || !verdict || subjects.length === 0) {
    fail('usage: slipmark attest --by <agent> --verdict <pass|fail> --subject <file> [--subject <file>...] [--note "..."] [--out <file>]');
  }
  const checks = argVals(args, "--check").map((c) => {
    const m = /^(.*)=(-?\d+)$/.exec(c);
    if (!m || !m[1]!.trim()) fail(`--check takes "<command>=<exit code>", for example --check "npm test=0"`);
    return { command: m![1]!.trim(), exitCode: Number(m![2]) };
  });
  const model = argVal(args, "--model") ?? process.env.SLIPMARK_MODEL ?? undefined;
  const harness = argVal(args, "--harness") ?? undefined;
  const kind = (argVal(args, "--kind") ?? undefined) as AttesterKind | undefined;
  // Record the agent's context (AGENTS.md, skills, MCP configs) when asked, or when the policy checks it.
  let context: boolean | string[] = false;
  if (!args.includes("--no-context")) {
    let ctxPolicy: Policy["context"];
    try {
      ctxPolicy = loadPolicy(process.cwd())?.context;
    } catch {
      ctxPolicy = undefined; // verify reports a malformed policy; attest still records the verdict
    }
    if (args.includes("--context") || (ctxPolicy && (kind ?? "agent") !== "human")) context = ctxPolicy?.files ?? true;
  }
  let att;
  try {
    att = createAttestation({
      by: by!,
      verdict: verdict!,
      subjects,
      note: argVal(args, "--note", { freeText: true }) ?? undefined,
      against: argVals(args, "--against"),
      run: argVals(args, "--run"),
      checks,
      kind,
      agent: model || harness ? { model, harness } : undefined,
      context,
      acknowledgeHidden: args.includes("--acknowledge-hidden"),
    });
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  if (args.includes("--sign")) {
    try {
      att = await signAttestation(att!);
    } catch (e) {
      fail(`couldn't sign: ${e instanceof Error ? e.message : String(e)}`);
    }
  }
  const dir = resolve(argVal(args, "--dir") ?? ".slipmark/attestations");
  const out = argVal(args, "--out") ? resolve(argVal(args, "--out")!) : defaultAttestationPath(dir, att!);
  try {
    checkAttestationTarget(out);
    writeAttestation(out, att!);
  } catch (e) {
    fail(e instanceof Error ? e.message : String(e));
  }
  console.log(`\n  ${att.by} → "${att.verdict}" on ${att.subjects.length} file(s)`);
  for (const s of att.subjects) console.log(`    ${s.sha256.slice(0, 12)}  ${s.path}`);
  for (const a of att.against ?? []) console.log(`    ${a.sha256.slice(0, 12)}  ${a.path} (checked against)`);
  for (const c of att.checks ?? []) console.log(`    ${c.witnessed ? "ran" : "claimed"}: ${c.command} → exit ${c.exitCode}`);
  if (att.context) console.log(`    agent context: ${att.context.length} file(s)${att.context.length ? ` (${att.context.map((c) => c.path).slice(0, 4).join(", ")}${att.context.length > 4 ? ", ..." : ""})` : ""}`);
  if (att!.signature) console.log("    signed: Sigstore bundle with this job's identity, logged in Rekor");
  console.log(`  written → ${relative(process.cwd(), out)}\n`);
}

/** `slipmark verify [--dir d] [--require <file>...] [--json]` */
async function verifyMain(args: string[]): Promise<void> {
  const report = await runVerify(args);
  if (args.includes("--json")) {
    console.log(JSON.stringify(report, null, 2));
    process.exit(report.ok ? 0 : 1);
  }
  const passed = report.results.filter((r) => r.status === "verified").length;
  console.log(`\nSlipmark verify: ${passed} verified · ${report.failures.length} refused\n`);
  for (const r of report.results) {
    const icon = r.status === "verified" ? "✓" : "✗";
    console.log(`  ${icon} ${r.status.padEnd(20)} ${r.message}`);
    if (r.status === "hash_mismatch" || (r.status === "against_changed" && r.expected)) {
      console.log(`      attested: ${r.expected}`);
      console.log(`      now:      ${r.actual}`);
    }
  }
  const p = report.policy;
  if (p) {
    const where = p.source === "base" ? `from ${p.ref}` : p.source === "working-tree" ? "from this checkout" : "none";
    console.log(`\n  Policy: ${where}${p.sha256 ? ` (sha256 ${p.sha256.slice(0, 12)})` : p.source === "base" ? " (no policy file there)" : ""}`);
    for (const n of p.notes ?? []) console.log(`  ! ${n}`);
  }
  for (const n of report.notes ?? []) console.log(`  ! ${n}`);
  if (report.ok) console.log("\n  Every verdict matches the files as they are now.\n");
  else if (report.checked === 0)
    console.log(
      "\n  Gate refused: no verdicts recorded yet, so there is nothing to prove.\n" +
        "  Agents record one with: npx slipmark attest --by <role> --verdict pass --subject <file>\n" +
        "  New here? Run: npx slipmark init\n",
    );
  else console.log("\n  Gate refused. Re-run the agent on the current files, or fix the input.\n");
  process.exit(report.ok ? 0 : 1);
}

async function main() {
  const args = process.argv.slice(2);

  if (args.length === 0 || args[0] === "help" || args[0] === "--help" || args[0] === "-h") {
    console.log(HELP);
    return;
  }
  if (args[0] === "--version" || args[0] === "-v" || args[0] === "version") {
    console.log(version());
    return;
  }
  if (args[0] === "mcp") {
    let root: string;
    try {
      root = mcpRoot(args.slice(1), process.env, process.cwd());
    } catch (e) {
      fail(e instanceof Error ? e.message : String(e));
    }
    await serveMcp(root!, version());
    return;
  }
  if (args[0] === "upload") {
    await uploadMain(args.slice(1));
    return;
  }
  if (args[0] === "init") {
    initMain(args.slice(1));
    return;
  }
  if (args[0] === "bisect") {
    await bisectMain(args.slice(1));
    return;
  }
  if (args[0] === "attest") {
    await attestMain(args.slice(1));
    return;
  }
  if (args[0] === "verify") {
    await verifyMain(args.slice(1));
    return;
  }
  if (args[0] === "dashboard") {
    await dashboardMain(args.slice(1));
    return;
  }

  const packPath = args.find((a) => !a.startsWith("--"));
  if (!packPath) fail("usage: slipmark <pack> [--git <file.json>] [--prompts] [--emit <dir>]  |  slipmark verify  |  slipmark attest ...  |  slipmark bisect --range <r> --command <cmd>");

  const gitIdx = args.indexOf("--git");
  const gitPath = gitIdx >= 0 ? (args[gitIdx + 1] ?? null) : null;
  const showPrompts = args.includes("--prompts");
  const emitIdx = args.indexOf("--emit");
  const emitDir = emitIdx >= 0 ? (args[emitIdx + 1] ?? null) : null;

  const pack = await loadPack(packPath!);
  const run = runPack(pack, loadGit(gitPath));

  console.log(`\nSlipmark — pack \`${run.packId}\``);
  console.log(`  ${run.passed} passed · ${run.drifted} drifted · ${run.errored} errored (of ${run.total})\n`);

  for (const o of run.outcomes) {
    const icon = o.result.status === "pass" ? "✓" : o.result.status === "drift" ? "✗" : "!";
    console.log(`  ${icon} ${o.key} — ${o.result.status}`);
    if (o.analysis) {
      const a = o.analysis;
      console.log(`      cause: ${a.likelyCauseSummary}`);
      console.log(`      confidence: ${a.confidenceTier ?? "n/a"}${typeof a.confidence === "number" ? ` (${(a.confidence * 100).toFixed(0)}%)` : ""} · severity: ${a.severity} · mode: ${a.promptMode}`);
      if (showPrompts && a.repairPrompt) {
        console.log("\n----- repair prompt -----\n");
        console.log(a.repairPrompt);
        console.log("\n----- end prompt -----\n");
      }
    }
  }

  if (emitDir) emitArtifacts(run, emitDir);

  process.exit(run.drifted > 0 || run.errored > 0 ? 1 : 0);
}

/** Write per-lock repair prompts, an index, and the coding-agent rules doc. */
function emitArtifacts(run: VerificationRun, dir: string): void {
  const outDir = resolve(dir);
  mkdirSync(outDir, { recursive: true });
  const artifacts = repairArtifactsFor(run);
  for (const a of artifacts) {
    writeFileSync(join(outDir, a.filename), a.content, "utf8");
  }
  writeFileSync(join(outDir, "index.md"), repairIndexDoc(run, artifacts), "utf8");
  writeFileSync(join(outDir, "AGENT_RULES.md"), agentRulesDoc(), "utf8");

  console.log(`\n  emitted ${artifacts.length} repair prompt(s) to ${outDir}`);
  for (const a of artifacts) {
    console.log(`    → ${join(dir, a.filename)}`);
    console.log(`      hand to Claude Code:  ${claudeCodeCommandFor(join(dir, a.filename))}`);
  }
  console.log(`    → ${join(dir, "AGENT_RULES.md")} (drop into .cursor/rules or CLAUDE.md)\n`);
}

main().catch((e) => fail(e instanceof Error ? e.message : String(e)));
