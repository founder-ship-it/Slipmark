// Follow-ups from the independent review of v0.5 (issue #14).
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync, readFileSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFileSync, spawnSync } from "node:child_process";
import { POLICY_SCHEMA } from "../src/attest/attestation.js";

const CLI = resolve("dist/src/cli.js");
const DIR = ".slipmark/attestations";

function gitRepo(): string {
  const root = mkdtempSync(join(tmpdir(), "sm-follow-"));
  const git = (...a: string[]) => execFileSync("git", a, { cwd: root, stdio: "pipe" });
  mkdirSync(join(root, "src"), { recursive: true });
  writeFileSync(join(root, "src/a.ts"), "export const a = 1;\n");
  git("init", "-q", "-b", "main");
  git("config", "user.email", "t@example.com");
  git("config", "user.name", "t");
  git("add", ".");
  git("commit", "-qm", "base");
  git("checkout", "-qb", "feature");
  return root;
}

const cli = (cwd: string, args: string[], env: Record<string, string> = {}) => {
  const clean = { ...process.env };
  delete clean.GITHUB_BASE_REF;
  delete clean.GITHUB_EVENT_NAME;
  return spawnSync("node", [CLI, ...args], { cwd, encoding: "utf8", env: { ...clean, ...env } });
};

const attest = ["attest", "--by", "reviewer", "--verdict", "pass", "--subject", "src/a.ts"];

test("attest: a bare flag after --note is a missing note, not the note", () => {
  const root = gitRepo();
  const r = cli(root, [...attest, "--note", "--against", "src/a.ts"]);
  assert.equal(r.status, 2, r.stdout + r.stderr);
  assert.match(r.stderr, /--note needs a value/);
  // Free text that starts with "--" is still a note.
  const ok = cli(root, [...attest, "--note", "--force was not used"]);
  assert.equal(ok.status, 0, ok.stderr);
  const att = JSON.parse(readFileSync(join(root, DIR, "reviewer--src_a.ts.json"), "utf8"));
  assert.equal(att.note, "--force was not used");
  rmSync(root, { recursive: true, force: true });
});

test("attest: --out and --dir can't write outside the repository", () => {
  const root = gitRepo();
  const outside = mkdtempSync(join(tmpdir(), "sm-outside-"));
  const out = cli(root, [...attest, "--out", join(outside, "x.json")]);
  assert.equal(out.status, 2, out.stdout + out.stderr);
  assert.match(out.stderr, /outside the repository/);
  const dir = cli(root, [...attest, "--dir", join(outside, "atts")]);
  assert.equal(dir.status, 2, dir.stdout + dir.stderr);
  assert.match(dir.stderr, /outside the repository/);
  assert.equal(existsSync(join(outside, "x.json")), false);
  assert.equal(existsSync(join(outside, "atts")), false);
  // ../ from inside the repository is outside too
  assert.equal(cli(root, [...attest, "--out", "../escaped.json"]).status, 2);
  rmSync(outside, { recursive: true, force: true });
  rmSync(root, { recursive: true, force: true });
});

test("attest: --out never overwrites a file that isn't an attestation", () => {
  const root = gitRepo();
  writeFileSync(join(root, "package.json"), '{ "name": "app" }\n');
  const r = cli(root, [...attest, "--out", "package.json"]);
  assert.equal(r.status, 2, r.stdout + r.stderr);
  assert.match(r.stderr, /isn't an attestation/);
  assert.equal(readFileSync(join(root, "package.json"), "utf8"), '{ "name": "app" }\n');
  const notJson = cli(root, [...attest, "--out", "src/a.ts"]);
  assert.equal(notJson.status, 2);
  assert.match(notJson.stderr, /must end in \.json/);
  assert.equal(readFileSync(join(root, "src/a.ts"), "utf8"), "export const a = 1;\n");
  // Replacing an earlier attestation is fine.
  assert.equal(cli(root, [...attest, "--out", "review.json"]).status, 0);
  assert.equal(cli(root, [...attest, "--out", "review.json"]).status, 0);
  rmSync(root, { recursive: true, force: true });
});

test("coverage: on a pull request, a base that is the pull request's own commit can't run", () => {
  const root = gitRepo();
  assert.equal(cli(root, [...attest]).status, 0);
  // HEAD~0 and the branch's own name are other spellings of HEAD.
  for (const base of ["HEAD~0", "feature", "main"]) {
    const pr = cli(root, ["verify", "--coverage", "diff", "--base", base], { GITHUB_EVENT_NAME: "pull_request" });
    assert.equal(pr.status, 2, `${base}: ${pr.stdout}${pr.stderr}`);
    assert.match(pr.stderr, /own commit, so nothing would be covered/);
  }
  // On a push to main, base == HEAD is expected and still runs.
  assert.equal(cli(root, ["verify", "--coverage", "diff", "--base", "main"], { GITHUB_EVENT_NAME: "push" }).status, 0);
  // Once the branch has its own commit, the base is a real base again.
  execFileSync("git", ["commit", "-qam", "x", "--allow-empty"], { cwd: root, stdio: "pipe" });
  const real = cli(root, ["verify", "--coverage", "diff", "--base", "main"], { GITHUB_EVENT_NAME: "pull_request" });
  assert.notEqual(real.status, 2, real.stdout + real.stderr);
  rmSync(root, { recursive: true, force: true });
});

test("policy: a subfolder's own policy says in the report that the root one wasn't read", () => {
  const root = gitRepo();
  mkdirSync(join(root, ".slipmark"), { recursive: true });
  writeFileSync(join(root, ".slipmark/policy.json"), JSON.stringify({ schema: POLICY_SCHEMA, require: ["src/a.ts"] }));
  mkdirSync(join(root, "pkg/.slipmark"), { recursive: true });
  writeFileSync(join(root, "pkg/b.ts"), "export const b = 1;\n");
  writeFileSync(join(root, "pkg/.slipmark/policy.json"), JSON.stringify({ schema: POLICY_SCHEMA }));
  const r = cli(join(root, "pkg"), ["verify", "--json"]);
  const report = JSON.parse(r.stdout);
  assert.ok(
    (report.policy.notes ?? []).some((n: string) => /pkg\/\.slipmark\/policy\.json was used\. The repository root's/.test(n)),
    JSON.stringify(report.policy),
  );
  // From the root, no such note.
  const top = JSON.parse(cli(root, ["verify", "--json"]).stdout);
  assert.ok(!(top.policy.notes ?? []).some((n: string) => /was used\. The repository root's/.test(n)));
  rmSync(root, { recursive: true, force: true });
});

test("policy: a branch that deletes the root policy can't hide the note when the policy comes from the base", () => {
  const root = gitRepo();
  const git = (...a: string[]) => execFileSync("git", a, { cwd: root, stdio: "pipe" });
  git("checkout", "-q", "main");
  mkdirSync(join(root, ".slipmark"), { recursive: true });
  writeFileSync(join(root, ".slipmark/policy.json"), JSON.stringify({ schema: POLICY_SCHEMA, require: ["src/a.ts"] }));
  mkdirSync(join(root, "pkg/.slipmark"), { recursive: true });
  writeFileSync(join(root, "pkg/b.ts"), "export const b = 1;\n");
  writeFileSync(join(root, "pkg/.slipmark/policy.json"), JSON.stringify({ schema: POLICY_SCHEMA }));
  git("add", ".");
  git("commit", "-qm", "policies");
  git("checkout", "-qB", "feature");
  git("rm", "-q", ".slipmark/policy.json");
  git("commit", "-qm", "drop root policy on the branch");
  const notes = (cwd: string) => JSON.parse(cli(cwd, ["verify", "--json", "--policy-from", "main"]).stdout).policy.notes ?? [];
  assert.ok(notes(join(root, "pkg")).some((n: string) => /was used\. The repository root's/.test(n)));
  // And a root policy only this branch adds isn't reported as one that main has.
  git("checkout", "-q", "main");
  git("rm", "-q", ".slipmark/policy.json");
  git("commit", "-qm", "drop root policy");
  git("checkout", "-qB", "other");
  mkdirSync(join(root, ".slipmark"), { recursive: true });
  writeFileSync(join(root, ".slipmark/policy.json"), JSON.stringify({ schema: POLICY_SCHEMA }));
  assert.ok(!notes(join(root, "pkg")).some((n: string) => /was used\. The repository root's/.test(n)));
  rmSync(root, { recursive: true, force: true });
});
