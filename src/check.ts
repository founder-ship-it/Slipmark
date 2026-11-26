/**
 * `slipmark check`: a read-only look at how much of a repository coding agents
 * wrote recently, and how much of that carries a verdict Slipmark can check.
 *
 * Needs no setup. It reads `git log` and any attestations already in the repo,
 * runs nothing and calls nothing over the network.
 *
 * A commit counts as agent-written only when it says so: the author or committer
 * is a known coding-agent identity, a `Co-authored-by` trailer names one, or the
 * message carries a tool's own "generated with" line. Agents that leave no mark
 * aren't counted, so the numbers are a floor, never a guess.
 */
import { execFileSync } from "node:child_process";
import { existsSync, statSync } from "node:fs";
import { join, resolve } from "node:path";
import { verifyAttestations } from "./attest/attestation.js";

export interface CommitInfo {
  hash: string;
  authorName: string;
  authorEmail: string;
  committerName: string;
  committerEmail: string;
  message: string;
  files: string[];
}

interface Identity {
  name: string;
  email: string;
}

interface AgentRule {
  agent: string;
  /** Matches an author, committer or co-author identity. */
  identity?: (who: Identity) => boolean;
  /** Matches the commit message. */
  message?: RegExp;
}

const lc = (s: string) => s.toLowerCase();
const isBot = (who: Identity, login: string) => lc(who.name) === `${login}[bot]` || lc(who.email).includes(`+${login}[bot]@users.noreply.github.com`);

/** Marks coding agents leave on commits. Each rule matches only a mark the tool itself writes. */
export const AGENT_RULES: AgentRule[] = [
  {
    agent: "Claude Code",
    identity: (w) => lc(w.email) === "noreply@anthropic.com" || isBot(w, "claude"),
    message: /generated with \[?claude code\]?/i,
  },
  {
    agent: "GitHub Copilot",
    identity: (w) => isBot(w, "copilot-swe-agent") || /^\d+\+copilot@users\.noreply\.github\.com$/.test(lc(w.email)),
  },
  { agent: "Cursor", identity: (w) => lc(w.email) === "cursoragent@cursor.com" || isBot(w, "cursor") },
  { agent: "OpenAI Codex", identity: (w) => isBot(w, "chatgpt-codex-connector") || lc(w.email) === "codex@openai.com" },
  { agent: "Devin", identity: (w) => isBot(w, "devin-ai-integration") },
  { agent: "Jules", identity: (w) => isBot(w, "google-labs-jules") },
  { agent: "Gemini", identity: (w) => isBot(w, "gemini-code-assist") },
  { agent: "Amazon Q", identity: (w) => isBot(w, "amazon-q-developer") },
  { agent: "OpenHands", identity: (w) => lc(w.email) === "openhands@all-hands.dev" },
  { agent: "Aider", identity: (w) => / \(aider\)$/i.test(w.name) || lc(w.email) === "noreply@aider.chat" },
];

const TRAILER = /^co-authored-by:\s*(.+?)\s*<([^>]*)>\s*$/gim;

/** The coding agent a commit says wrote it, or null. */
export function agentOf(c: CommitInfo): string | null {
  const people: Identity[] = [
    { name: c.authorName, email: c.authorEmail },
    { name: c.committerName, email: c.committerEmail },
  ];
  for (const m of c.message.matchAll(TRAILER)) people.push({ name: m[1]!, email: m[2]! });
  for (const rule of AGENT_RULES) {
    if (rule.identity && people.some(rule.identity)) return rule.agent;
    if (rule.message && rule.message.test(c.message)) return rule.agent;
  }
  return null;
}

const RS = "\x1e";
const US = "\x1f";

function git(root: string, args: string[]): string {
  return execFileSync("git", args, { cwd: root, encoding: "utf8", maxBuffer: 256 * 1024 * 1024, stdio: ["ignore", "pipe", "pipe"] });
}

/** Non-merge commits reachable from HEAD since `since` (any date git accepts), newest first. */
export function readCommits(root: string, since: string): CommitInfo[] {
  // -z ends each commit with NUL, which git never allows inside a commit message.
  const head = git(root, ["log", `--since=${since}`, "--no-merges", "-z", `--format=%H${US}%an${US}%ae${US}%cn${US}%ce${US}%B`]);
  const names = git(root, ["log", `--since=${since}`, "--no-merges", "-z", `--format=${RS}%H`, "--name-only"]);
  const files = new Map<string, string[]>();
  for (const rec of names.split(RS).slice(1)) {
    // Each record is "<hash>\0\n<file>\0<file>\0...". File names may hold spaces, so split on NUL only.
    const [hash, ...rest] = rec.split("\0");
    files.set(hash!.trim(), rest.map((f) => f.replace(/^\n/, "")).filter(Boolean));
  }
  return head
    .split("\0")
    .filter((rec) => rec.trim() !== "")
    .map((rec) => {
      const [hash, authorName, authorEmail, committerName, committerEmail, ...msg] = rec.split(US);
      const h = hash!.trim();
      return {
        hash: h,
        authorName: authorName ?? "",
        authorEmail: authorEmail ?? "",
        committerName: committerName ?? "",
        committerEmail: committerEmail ?? "",
        message: msg.join(US),
        files: files.get(h) ?? [],
      };
    });
}

export interface CheckReport {
  since: string;
  commits: number;
  agentCommits: number;
  byAgent: { agent: string; commits: number }[];
  /** Files agent commits touched that still exist, sorted. */
  agentFiles: string[];
  /** Of those, the ones with a current, passing verdict bound to their bytes. */
  covered: string[];
  /** Attestations exist but couldn't be read as a whole (for example a policy problem); coverage is then unknown. */
  coverageError?: string;
}

export function checkRepo(opts: { root?: string; since?: string; dir?: string }): CheckReport {
  const since = opts.since ?? "90 days ago";
  let root: string;
  try {
    // git names files from the top of the repository, so work from there even when run in a subfolder.
    const start = resolve(opts.root ?? process.cwd());
    git(start, ["rev-parse", "--verify", "HEAD"]);
    root = git(start, ["rev-parse", "--show-toplevel"]).trim();
  } catch {
    throw new Error("slipmark check needs a git repository with at least one commit");
  }
  const commits = readCommits(root, since);
  const counts = new Map<string, number>();
  const touched = new Set<string>();
  let agentCommits = 0;
  for (const c of commits) {
    const agent = agentOf(c);
    if (!agent) continue;
    agentCommits++;
    counts.set(agent, (counts.get(agent) ?? 0) + 1);
    for (const f of c.files) touched.add(f);
  }
  const agentFiles = [...touched].filter((f) => {
    const abs = join(root, f);
    return existsSync(abs) && statSync(abs).isFile();
  }).sort();

  let covered: string[] = [];
  let coverageError: string | undefined;
  try {
    const report = verifyAttestations({ root, dir: opts.dir, policy: null });
    const ok = new Set(report.results.filter((r) => r.status === "verified" && r.subject).map((r) => r.subject!.replace(/\\/g, "/").replace(/^\.\//, "")));
    covered = agentFiles.filter((f) => ok.has(f));
  } catch (e) {
    coverageError = e instanceof Error ? e.message : String(e);
  }

  return {
    since,
    commits: commits.length,
    agentCommits,
    byAgent: [...counts].map(([agent, n]) => ({ agent, commits: n })).sort((a, b) => b.commits - a.commits || a.agent.localeCompare(b.agent)),
    agentFiles,
    covered,
    ...(coverageError ? { coverageError } : {}),
  };
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

export function renderCheck(r: CheckReport): string {
  const out: string[] = [];
  out.push(`Slipmark check: commits since ${r.since}`, "");
  if (r.commits === 0) {
    out.push("  No commits in that window. Try --since \"1 year ago\".");
    return out.join("\n");
  }
  out.push(`  ${plural(r.commits, "commit")} · ${r.agentCommits} marked as written with a coding agent`);
  const width = Math.max(0, ...r.byAgent.map((a) => a.agent.length));
  for (const a of r.byAgent) out.push(`    ${a.agent.padEnd(width)}  ${a.commits}`);
  if (r.agentCommits === 0) {
    out.push("", "  No commit here says a coding agent wrote it. Agents that leave no mark aren't counted.");
    return out.join("\n");
  }
  out.push("");
  out.push(`  Files those commits touched that are still here: ${r.agentFiles.length}`);
  if (r.coverageError) {
    out.push(`  Couldn't read the attestations here: ${r.coverageError}`);
    return out.join("\n");
  }
  out.push(`  With a current, passing verdict bound to their bytes: ${r.covered.length}`);
  out.push("");
  const gap = r.agentFiles.length - r.covered.length;
  if (gap === 0) {
    out.push("  Every agent-touched file has a verdict that still matches it.");
  } else {
    out.push(`  ${plural(gap, "agent-touched file")} ${gap === 1 ? "has" : "have"} nothing recording what was checked, or a verdict about different bytes.`);
    out.push("  Start recording verdicts:  npx slipmark init");
  }
  out.push("", "  Counted from commit authors, Co-authored-by trailers and tools' own \"generated with\" lines. Agents that leave no mark aren't counted.");
  return out.join("\n");
}
