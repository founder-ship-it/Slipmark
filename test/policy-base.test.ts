// A pull request must not be able to loosen the rules it is judged by.
// Reported by Kent Bodrov: keep every file hash correct, but drop a path from
// `require` (or loosen the policy) in the same change, and the gate used to pass.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  createAttestation,
  writeAttestation,
  defaultAttestationPath,
  verifyAttestations,
  resolvePolicy,
  POLICY_SCHEMA,
} from "../src/attest/attestation.js";

const DIR = ".slipmark/attestations";
const POLICY = ".slipmark/policy.json";
const CLI = resolve("dist/src/cli.js");
const NOW = new Date("2026-10-25T09:00:00Z");

/** A repo whose main branch requires a verdict on src/auth.ts, on a feature branch with one verdict, for src/other.ts only. */
function setup(basePolicy: object | null = { schema: POLICY_SCHEMA, require: ["src/auth.ts"] }): { root: string; git: (...a: string[]) => string } {
  const root = mkdtempSync(join(tmpdir(), "sm-policy-"));
  const git = (...a: string[]) => execFileSync("git", a, { cwd: root, encoding: "utf8", stdio: "pipe" });
  mkdirSync(join(root, "src"), { recursive: true });
  mkdirSync(join(root, ".slipmark"), { recursive: true });
  writeFileSync(join(root, "src/auth.ts"), "export const auth = 1;\n");
  writeFileSync(join(root, "src/other.ts"), "export const other = 1;\n");
  if (basePolicy) writeFileSync(join(root, POLICY), JSON.stringify(basePolicy));
  git("init", "-q", "-b", "main");
  git("config", "user.email", "t@example.com");
  git("config", "user.name", "t");
  git("add", ".");
  git("commit", "-qm", "base");
  git("update-ref", "refs/remotes/origin/main", "main"); // as a CI checkout would have it
  git("checkout", "-qb", "feature");
  const att = createAttestation({ root, by: "reviewer", verdict: "pass", subjects: ["src/other.ts"], now: NOW });
  writeAttestation(defaultAttestationPath(join(root, DIR), att), att);
  return { root, git };
}

/** The PR's move: drop src/auth.ts from require, keeping every hash correct. */
function loosen(root: string): void {
  writeFileSync(join(root, POLICY), JSON.stringify({ schema: POLICY_SCHEMA, require: [] }));
}

const cli = (cwd: string, args: string[], env: Record<string, string> = {}) => {
  const clean = { ...process.env };
  delete clean.GITHUB_BASE_REF;
  return spawnSync("node", [CLI, ...args], { cwd, encoding: "utf8", env: { ...clean, ...env } });
};

test("policy-from base: a PR that drops a required path from the policy is still refused", () => {
  const { root } = setup();
  loosen(root);
  const { policy, info } = resolvePolicy({ root, from: "main" });
  const r = verifyAttestations({ root, policy, policySource: info });
  assert.equal(r.ok, false);
  assert.ok(r.failures.some((f) => f.status === "unattested" && f.subject === "src/auth.ts"));
  assert.equal(r.policy?.source, "base");
  assert.equal(r.policy?.ref, "main");
  assert.equal(r.policy?.changedOnBranch, true);
  assert.match(r.policy!.notes![0]!, /changes .slipmark\/policy.json.*takes effect after merge/);
  // Read from the checkout, the loosened policy would have let it through. That's the hole this closes.
  const wt = resolvePolicy({ root, from: "working-tree" });
  assert.equal(verifyAttestations({ root, policy: wt.policy }).ok, true);
  rmSync(root, { recursive: true, force: true });
});

test("policy-from base: the report records the hash of the policy that made the decision", () => {
  const { root, git } = setup();
  const baseText = git("show", `main:${POLICY}`);
  loosen(root);
  const { info } = resolvePolicy({ root, from: "main" });
  assert.equal(info.sha256, createHash("sha256").update(baseText).digest("hex"));
  rmSync(root, { recursive: true, force: true });
});

test("cli: in a GitHub pull request the base branch's policy applies automatically", () => {
  const { root } = setup();
  loosen(root);
  const r = cli(root, ["verify", "--json"], { GITHUB_BASE_REF: "main" });
  assert.equal(r.status, 1, r.stderr);
  const report = JSON.parse(r.stdout);
  assert.equal(report.policy.source, "base");
  assert.equal(report.policy.ref, "refs/remotes/origin/main");
  assert.equal(report.policy.changedOnBranch, true);
  assert.ok(report.failures.some((f: { subject?: string }) => f.subject === "src/auth.ts"));
  const text = cli(root, ["verify"], { GITHUB_BASE_REF: "main" });
  assert.match(text.stdout, /Policy: from refs\/remotes\/origin\/main \(sha256 [0-9a-f]{12}\)/);
  assert.match(text.stdout, /takes effect after merge/);
  rmSync(root, { recursive: true, force: true });
});

test("cli: the coverage base is also used as the policy base", () => {
  const { root } = setup();
  loosen(root);
  const r = cli(root, ["verify", "--json", "--coverage", "diff", "--base", "main"]);
  const report = JSON.parse(r.stdout);
  assert.equal(report.policy.source, "base");
  assert.equal(report.policy.ref, "main");
  assert.ok(report.failures.some((f: { status: string; subject?: string }) => f.status === "unattested" && f.subject === "src/auth.ts"));
  rmSync(root, { recursive: true, force: true });
});

test("cli: no base known (a local run) reads the checkout's policy, as in v0.4", () => {
  const { root } = setup();
  loosen(root);
  const r = cli(root, ["verify", "--json"]);
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.equal(JSON.parse(r.stdout).policy.source, "working-tree");
  rmSync(root, { recursive: true, force: true });
});

test("cli: a PR base missing from the checkout falls back to the checkout and says so", () => {
  const { root } = setup();
  const r = cli(root, ["verify", "--json"], { GITHUB_BASE_REF: "release" });
  const report = JSON.parse(r.stdout);
  assert.equal(report.policy.source, "working-tree");
  assert.match(report.policy.notes[0], /origin\/release.*isn't in this checkout.*a pull request can edit/);
  rmSync(root, { recursive: true, force: true });
});

test("cli: an explicit --policy-from that isn't in the checkout can't run (exit 2), never a silent fallback", () => {
  const { root } = setup();
  const r = cli(root, ["verify", "--policy-from", "origin/nope"]);
  assert.equal(r.status, 2);
  assert.match(r.stderr + r.stdout, /can't find "origin\/nope"/);
  assert.equal(cli(root, ["verify", "--policy-from", "--x"]).status, 2);
  rmSync(root, { recursive: true, force: true });
});

test("policy-from base: a branch that adds a policy doesn't apply it until merge", () => {
  const { root } = setup(null);
  writeFileSync(join(root, POLICY), JSON.stringify({ schema: POLICY_SCHEMA, require: ["src/auth.ts"] }));
  const { policy, info } = resolvePolicy({ root, from: "main" });
  assert.equal(policy, null);
  assert.equal(info.source, "base");
  assert.equal(info.sha256, undefined);
  assert.match(info.notes![0]!, /adds .slipmark\/policy.json/);
  rmSync(root, { recursive: true, force: true });
});

test("policy-from base: a branch that deletes the policy is still judged by it", () => {
  const { root } = setup();
  rmSync(join(root, POLICY));
  const { policy, info } = resolvePolicy({ root, from: "main" });
  assert.deepEqual(policy?.require, ["src/auth.ts"]);
  assert.match(info.notes![0]!, /deletes/);
  rmSync(root, { recursive: true, force: true });
});

test("policy-from base: an unchanged policy has no notice", () => {
  const { root } = setup();
  const { info } = resolvePolicy({ root, from: "main" });
  assert.equal(info.changedOnBranch, undefined);
  assert.equal(info.notes, undefined);
  rmSync(root, { recursive: true, force: true });
});

test("policy: a malformed policy on the base is an error naming the ref; require must be paths", () => {
  const { root } = setup({ schema: POLICY_SCHEMA, require: "src/auth.ts" });
  assert.throws(() => resolvePolicy({ root, from: "main" }), /policy.json at main: require must be a list of file paths/);
  const r = cli(root, ["verify", "--policy-from", "main"]);
  assert.equal(r.status, 2);
  rmSync(root, { recursive: true, force: true });
});

test("policy: require in the policy file works like --require", () => {
  const { root } = setup();
  const r = verifyAttestations({ root });
  assert.equal(r.ok, false);
  assert.ok(r.failures.some((f) => f.status === "unattested" && f.subject === "src/auth.ts"));
  rmSync(root, { recursive: true, force: true });
});

test("cli: --no-policy is recorded on the report", () => {
  const { root } = setup();
  const report = JSON.parse(cli(root, ["verify", "--json", "--no-policy"]).stdout);
  assert.equal(report.policy.source, "none");
  rmSync(root, { recursive: true, force: true });
});

test("cli: a policy with uncommitted edits counts as changed on the branch", () => {
  const { root } = setup();
  const policy = JSON.parse(readFileSync(join(root, POLICY), "utf8")) as { require: string[] };
  policy.require.push("src/other.ts");
  writeFileSync(join(root, POLICY), JSON.stringify(policy));
  const report = JSON.parse(cli(root, ["verify", "--json", "--policy-from", "main"]).stdout);
  assert.equal(report.policy.changedOnBranch, true);
  rmSync(root, { recursive: true, force: true });
});

// From the independent review of this change.

test("cli: in a pull request, running from a subfolder reads that folder's policy from the base (monorepos keep working)", () => {
  const { root, git } = setup(null);
  git("checkout", "-q", "main");
  mkdirSync(join(root, "pkg/.slipmark"), { recursive: true });
  writeFileSync(join(root, "pkg/a.ts"), "export const a = 1;\n");
  writeFileSync(join(root, "pkg/.slipmark/policy.json"), JSON.stringify({ schema: POLICY_SCHEMA, require: ["a.ts"] }));
  git("add", ".");
  git("commit", "-qm", "pkg");
  git("update-ref", "refs/remotes/origin/main", "main");
  git("checkout", "-q", "-B", "feature");
  writeFileSync(join(root, "pkg/.slipmark/policy.json"), JSON.stringify({ schema: POLICY_SCHEMA, require: [] }));
  const pkg = join(root, "pkg");
  const att = createAttestation({ root: pkg, by: "reviewer", verdict: "pass", subjects: ["a.ts"], now: NOW });
  writeAttestation(defaultAttestationPath(join(pkg, DIR), att), att);
  const r = cli(pkg, ["verify", "--json"], { GITHUB_BASE_REF: "main" });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  const report = JSON.parse(r.stdout);
  assert.equal(report.policy.source, "base");
  assert.equal(report.policy.changedOnBranch, true);
  // no policy in the subfolder at all: still runs, as in v0.4
  rmSync(join(root, "pkg/.slipmark/policy.json"));
  assert.notEqual(cli(pkg, ["verify", "--json"], { GITHUB_BASE_REF: "main" }).status, 2);
  rmSync(root, { recursive: true, force: true });
});

test("policy-from base: a subfolder run never skips a policy kept at the repository root", () => {
  const { root } = setup();
  mkdirSync(join(root, "pkg"));
  assert.throws(() => resolvePolicy({ root: join(root, "pkg"), from: "main" }), /at the repository root on main/);
  rmSync(root, { recursive: true, force: true });
});

test("cli: a tag named origin/main can't stand in for the base branch", () => {
  const { root, git } = setup();
  loosen(root);
  git("add", ".");
  git("commit", "-qm", "loosen");
  git("tag", "origin/main"); // a loosened policy commit, tagged to look like the base
  const r = cli(root, ["verify", "--json"], { GITHUB_BASE_REF: "main" });
  assert.equal(r.status, 1, r.stdout);
  assert.ok(JSON.parse(r.stdout).failures.some((f: { subject?: string }) => f.subject === "src/auth.ts"));
  rmSync(root, { recursive: true, force: true });
});

test("policy-from base: a policy on the base that is a link is an error, never treated as no policy", () => {
  const { root, git } = setup(null);
  git("checkout", "-q", "main");
  execFileSync("ln", ["-s", "../somewhere.json", join(root, POLICY)]);
  git("add", ".");
  git("commit", "-qm", "link");
  git("checkout", "-q", "-B", "feature");
  assert.throws(() => resolvePolicy({ root, from: "main" }), /isn't a regular file/);
  rmSync(root, { recursive: true, force: true });
});

test("policy-from base: line endings alone don't count as a policy change", () => {
  const { root, git } = setup();
  const text = git("show", `main:${POLICY}`);
  writeFileSync(join(root, POLICY), text.replace(/\n/g, "\r\n") + (text.includes("\n") ? "" : ""));
  const { info } = resolvePolicy({ root, from: "main" });
  assert.equal(info.changedOnBranch, undefined);
  rmSync(root, { recursive: true, force: true });
});

test("errors name the policy base, not the coverage base", () => {
  const { root } = setup();
  assert.throws(() => resolvePolicy({ root, from: "--x" }), /policy base must be a git ref/);
  rmSync(root, { recursive: true, force: true });
});

test("policy-from base: a linked .slipmark folder on the base is an error, never treated as no policy", () => {
  const { root, git } = setup(null);
  git("checkout", "-q", "main");
  mkdirSync(join(root, "real"));
  writeFileSync(join(root, "real/policy.json"), JSON.stringify({ schema: POLICY_SCHEMA, require: ["src/auth.ts"] }));
  rmSync(join(root, ".slipmark"), { recursive: true, force: true });
  execFileSync("ln", ["-s", "real", join(root, ".slipmark")]);
  git("add", "-A");
  git("commit", "-qm", "linked slipmark folder");
  git("update-ref", "refs/remotes/origin/main", "main");
  git("checkout", "-q", "-B", "feature");
  assert.throws(() => resolvePolicy({ root, from: "main" }), /.slipmark on main isn't a folder/);
  const r = cli(root, ["verify"], { GITHUB_BASE_REF: "main" });
  assert.equal(r.status, 2, r.stdout + r.stderr);
  rmSync(root, { recursive: true, force: true });
});

test("cli: with the base branch ref missing, a tag of the same full name doesn't stand in for it", () => {
  const { root, git } = setup();
  loosen(root);
  git("add", ".");
  git("commit", "-qm", "loosen");
  git("update-ref", "-d", "refs/remotes/origin/main");
  git("tag", "refs/remotes/origin/main");
  const report = JSON.parse(cli(root, ["verify", "--json"], { GITHUB_BASE_REF: "main" }).stdout);
  assert.equal(report.policy.source, "working-tree");
  assert.match(report.policy.notes[0], /isn't in this checkout/);
  rmSync(root, { recursive: true, force: true });
});

test("errors: HEAD as a policy base is explained as the branch itself", () => {
  const { root } = setup();
  assert.throws(() => resolvePolicy({ root, from: "HEAD" }), /policy base "HEAD" is this branch itself/);
  rmSync(root, { recursive: true, force: true });
});
