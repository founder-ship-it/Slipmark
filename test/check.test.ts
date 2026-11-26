import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { execFileSync } from "node:child_process";
import { agentOf, checkRepo, renderCheck, type CommitInfo } from "../src/check.js";
import { createAttestation, writeAttestation, defaultAttestationPath } from "../src/attest/attestation.js";

const human = { authorName: "Ada", authorEmail: "ada@example.com", committerName: "Ada", committerEmail: "ada@example.com" };
const commit = (over: Partial<CommitInfo>): CommitInfo => ({ hash: "x", message: "change\n", files: [], ...human, ...over });

test("check: agent marks are recognised from trailers, bot identities and generated-with lines", () => {
  assert.equal(agentOf(commit({ message: "fix\n\nCo-authored-by: Claude <noreply@anthropic.com>\n" })), "Claude Code");
  assert.equal(agentOf(commit({ message: "fix\n\n🤖 Generated with [Claude Code](https://claude.com/claude-code)\n" })), "Claude Code");
  assert.equal(agentOf(commit({ authorName: "Copilot", authorEmail: "198982749+Copilot@users.noreply.github.com" })), "GitHub Copilot");
  assert.equal(agentOf(commit({ authorName: "copilot-swe-agent[bot]", authorEmail: "x" })), "GitHub Copilot");
  assert.equal(agentOf(commit({ message: "x\n\nCo-authored-by: Cursor Agent <cursoragent@cursor.com>\n" })), "Cursor");
  assert.equal(agentOf(commit({ committerName: "devin-ai-integration[bot]", committerEmail: "158243242+devin-ai-integration[bot]@users.noreply.github.com" })), "Devin");
  assert.equal(agentOf(commit({ authorName: "Ada (aider)" })), "Aider");
});

test("check: ordinary commits, and names that merely look like an agent, aren't counted", () => {
  assert.equal(agentOf(commit({})), null);
  assert.equal(agentOf(commit({ authorName: "Claude Monet", authorEmail: "claude@example.com" })), null, "a person called Claude is not Claude Code");
  assert.equal(agentOf(commit({ message: "Talked to Copilot about it\n\nCo-authored-by: Bob <bob@example.com>\n" })), null);
  assert.equal(agentOf(commit({ message: "mention co-authored-by: Claude <noreply@anthropic.com> inline" })), null, "a trailer must be its own line");
});

function repo(): string {
  const root = mkdtempSync(join(tmpdir(), "sm-check-"));
  execFileSync("git", ["init", "-q"], { cwd: root });
  return root;
}
function commitAll(root: string, message: string, author = "Ada <ada@example.com>"): void {
  execFileSync("git", ["add", "-A"], { cwd: root });
  execFileSync("git", ["-c", "user.name=Ada", "-c", "user.email=ada@example.com", "commit", "-q", "--author", author, "-m", message], { cwd: root });
}

test("check: counts agent commits, the files they touched that remain, and which have a current verdict", () => {
  const root = repo();
  mkdirSync(join(root, "src"));
  writeFileSync(join(root, "README.md"), "hello\n");
  commitAll(root, "human start");
  writeFileSync(join(root, "src/pay.ts"), "export const pay = 1;\n");
  writeFileSync(join(root, "src/odd name.ts"), "export const odd = 1;\n");
  commitAll(root, "add pay\n\nCo-authored-by: Claude <noreply@anthropic.com>");
  writeFileSync(join(root, "src/gone.ts"), "x\n");
  commitAll(root, "temp", "Cursor Agent <cursoragent@cursor.com>");
  rmSync(join(root, "src/gone.ts"));
  commitAll(root, "remove temp");

  let r = checkRepo({ root });
  assert.equal(r.commits, 4);
  assert.equal(r.agentCommits, 2);
  assert.deepEqual(r.byAgent, [{ agent: "Claude Code", commits: 1 }, { agent: "Cursor", commits: 1 }]);
  assert.deepEqual(r.agentFiles, ["src/odd name.ts", "src/pay.ts"], "deleted files drop out; names with spaces survive");
  assert.deepEqual(r.covered, []);
  assert.match(renderCheck(r), /2 agent-touched files have nothing recording what was checked/);

  const att = createAttestation({ root, by: "reviewer", verdict: "pass", subjects: ["src/pay.ts"] });
  writeAttestation(defaultAttestationPath(join(root, ".slipmark/attestations"), att), att);
  r = checkRepo({ root });
  assert.deepEqual(r.covered, ["src/pay.ts"]);
  assert.deepEqual(checkRepo({ root: join(root, "src") }).covered, ["src/pay.ts"], "run from a subfolder, paths still line up");

  writeFileSync(join(root, "src/pay.ts"), "export const pay = 2;\n");
  r = checkRepo({ root });
  assert.deepEqual(r.covered, [], "a verdict about different bytes doesn't count");
});

test("check: a repo with no agent commits says so, and a repo with no commits is an error", () => {
  const root = repo();
  writeFileSync(join(root, "a.txt"), "a\n");
  commitAll(root, "one");
  const r = checkRepo({ root });
  assert.equal(r.agentCommits, 0);
  assert.match(renderCheck(r), /No commit here says a coding agent wrote it/);
  assert.throws(() => checkRepo({ root: repo() }), /at least one commit/);
});
