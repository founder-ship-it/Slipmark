/**
 * Verdict attestation: make agents prove what they checked.
 *
 * An agent that reviews, audits or tests something writes an attestation: its
 * verdict, plus the SHA-256 of every file it actually read. Before anything
 * ships, `verifyAttestations` re-hashes those files on the tree as it stands
 * now and refuses if anything moved.
 *
 * Why: a verdict on its own proves nothing. An agent (or a CI job checking the
 * wrong branch) can report "passed" about a file that has since changed, or that
 * it never looked at. Binding the verdict to a content hash turns "trust me"
 * into something a gate can check deterministically, with no model calls.
 *
 * Everything here is pure Node: `node:crypto`, `node:fs`, `node:path`.
 */
import { createHash } from "node:crypto";
import { checkSignature, type AttestationSignature, type SignatureCheck, type SignaturePolicy } from "./signing.js";
import { DEFAULT_CONTEXT_FILES, MAX_SCAN, isMarkdownish, scanHiddenContent, type HiddenFinding } from "./context.js";
import { compareWithGitHub, githubRenderer, type RenderFn } from "./githubRender.js";
import { identityMatches } from "./signing.js";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, lstatSync, readFileSync, readdirSync, readlinkSync, realpathSync, renameSync, statSync, unlinkSync, writeFileSync, mkdirSync } from "node:fs";
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from "node:path";

export const ATTESTATION_SCHEMA = "slipmark/attestation@1";
/**
 * v2 adds what the verdict was checked against, checks Slipmark ran itself, and
 * which model gave it. `attest` only writes @2 when one of those is used, so
 * older verifiers keep reading plain attestations.
 */
export const ATTESTATION_SCHEMA_V2 = "slipmark/attestation@2";
export const POLICY_SCHEMA = "slipmark/policy@1";
export const POLICY_FILE = ".slipmark/policy.json";

/** Always left out of coverage: the attestations themselves change with every verdict. */
export const COVERAGE_ALWAYS_IGNORED = [".slipmark/**"];

/** Verdicts that clear the gate. Anything else blocks. */
export const PASSING_VERDICTS = ["pass", "cleared"] as const;
export type Verdict = "pass" | "cleared" | "fail" | "blocked" | (string & {});

export interface AttestedSubject {
  /** Path relative to the repo root, forward slashes. */
  path: string;
  /** Lowercase hex SHA-256 of the file's bytes at the moment of the verdict. */
  sha256: string;
}

/**
 * A check behind the verdict. `witnessed: true` means Slipmark ran the command
 * itself (`attest --run`). `witnessed: false` is the attester's claim
 * (`attest --check`) and is reported as such, never trusted.
 */
export interface AttestedCheck {
  command: string;
  exitCode: number;
  /** SHA-256 of stdout followed by stderr. Witnessed checks only. */
  outputSha256?: string;
  durationMs?: number;
  witnessed: boolean;
}

/** Who gave the verdict. Claimed, used only to match policies. */
export interface AgentInfo {
  model?: string;
  harness?: string;
  harnessVersion?: string;
}

export type AttesterKind = "agent" | "tool" | "human";

export interface Attestation {
  schema: typeof ATTESTATION_SCHEMA | typeof ATTESTATION_SCHEMA_V2;
  /** Who gave the verdict, e.g. "security-audit-agent". */
  by: string;
  verdict: Verdict;
  /** ISO timestamp. Informational. */
  at: string;
  subjects: AttestedSubject[];
  /** Optional free text from the agent. Informational. */
  note?: string;
  /** v2. Claimed. Defaults to "agent". */
  kind?: AttesterKind;
  /** v2. Claimed. */
  agent?: AgentInfo;
  /** v2. Witnessed. Files the verdict was checked against (a spec, a checklist). Gated like subjects. */
  against?: AttestedSubject[];
  /** v2. Checks behind the verdict. */
  checks?: AttestedCheck[];
  /**
   * v2. The agent context the verdict was given under: instruction files, skills,
   * hooks and MCP configs, with their hashes as they were on disk when the verdict
   * was recorded. If any of them changes, the verdict stops counting.
   */
  context?: AttestedSubject[];
  /**
   * v2. The approver has seen text in these exact files that GitHub doesn't
   * display (comments, link definitions, images) and accepts it. Lets a context
   * change with such content through when given by an allowed approver.
   */
  acknowledgedHidden?: true;
  /** Sigstore signature over the rest of the attestation, made where the verdict was given. See signing.ts. */
  signature?: AttestationSignature;
}

/** `.slipmark/policy.json`. Optional: without it, verify behaves exactly as before. */
export interface Policy {
  schema: typeof POLICY_SCHEMA;
  coverage?: { mode: "diff"; base: string; ignore?: string[] };
  models?: { allow: string[] };
  /** Signed verdicts: who may sign, and whether unsigned verdicts count. */
  signatures?: SignaturePolicy;
  /**
   * Files that must have a current, passing verdict, like `--require`. Kept here
   * rather than in the workflow so it is read from the base branch, where a pull
   * request can't loosen it.
   */
  require?: string[];
  /** Agent context rules. See docs/attestation.md, "Agent context". */
  context?: ContextPolicy;
  /** What `slipmark verify-bundle` requires in an in-toto Bundle. See docs/attestation.md, "Checking a combined Bundle". */
  bundle?: BundlePolicy;
}

/** `.slipmark/policy.json` → `bundle`. */
export interface BundlePolicy {
  /** Each entry: at least one valid attestation of this predicate type, signed by one of these signers. */
  require: { predicateType: string; signers: string[] }[];
  /** OIDC issuer the signing certificates must come from. Default: GitHub Actions. */
  issuer?: string;
}

export interface ContextPolicy {
  /** Globs for agent context files. Default: DEFAULT_CONTEXT_FILES. */
  files?: string[];
  /** Who may approve a change to a context file: verdicts of these kinds covering it. Default ["human"]. */
  approvers?: AttesterKind[];
  /**
   * Signer identities whose signed verdicts can approve a context change, for
   * example a workflow that only runs after a CODEOWNERS review. `*` matches
   * anything. When set, an approval counts only if signed by one of these.
   * Without it, the approver's `kind` is a claim anyone can write.
   */
  approverSigners?: string[];
  /** Agent verdicts must record their context (`slipmark attest` does this when the policy has a context section). Default true. */
  requireRecorded?: boolean;
  /** Changed context files with text hidden from human reviewers: "refuse" (default) or "allow". */
  hiddenContent?: "refuse" | "allow";
  /**
   * Also check changed context files against GitHub's own renderer. "auto"
   * (default): in GitHub Actions, with a token. "require": refuse when it can't
   * run. "off": never.
   */
  githubRender?: "auto" | "require" | "off";
}

/**
 * Where this run's policy came from, so a report says which rules made the
 * decision. A pull request must not be able to loosen the rules it is judged
 * by, so in CI the policy is read from the base branch, not the checkout.
 */
export interface PolicySource {
  /** `base`: read from `ref`. `working-tree`: the checkout as it is. `none`: no policy applied. */
  source: "base" | "working-tree" | "none";
  ref?: string;
  /** SHA-256 of the policy file that was applied. Absent when there was none. */
  sha256?: string;
  /** The checkout's policy differs from the one applied (read from base). It takes effect after merge. */
  changedOnBranch?: boolean;
  /** Plain-language notes for the report, for example why the base couldn't be used. */
  notes?: string[];
  /** A base was expected (a pull request, a coverage base) but isn't in the checkout. */
  baseMissing?: string;
}

export type CheckStatus =
  | "verified"
  | "hash_mismatch"
  | "subject_missing"
  | "verdict_not_passing"
  | "unattested"
  | "invalid"
  | "uncovered"
  | "against_changed"
  | "check_failed"
  | "model_not_allowed"
  | "unsigned"
  | "signature_invalid"
  | "signer_not_trusted"
  | "context_changed"
  | "context_unapproved"
  | "hidden_content";

export interface CheckResult {
  status: CheckStatus;
  /** The attestation file, relative to root (absent for `unattested`). */
  attestation?: string;
  /** The subject path this result is about, when there is one. */
  subject?: string;
  by?: string;
  verdict?: string;
  expected?: string;
  actual?: string;
  /** Who signed the verdict, when it carries a valid signature: for GitHub Actions, the workflow and ref. */
  signer?: string;
  message: string;
}

export interface VerifyReport {
  ok: boolean;
  checked: number;
  results: CheckResult[];
  failures: CheckResult[];
  /** Which policy file made the decision. */
  policy?: PolicySource;
  /** Things the reader should know that didn't refuse the gate. */
  notes?: string[];
}

export function sha256File(filePath: string): string {
  return createHash("sha256").update(readFileSync(filePath)).digest("hex");
}

/** True when `rel` (a path relative to some root) points outside that root. */
function escapes(rel: string): boolean {
  return rel === ".." || rel.startsWith(`..${sep}`) || isAbsolute(rel);
}

/**
 * Resolve a subject path against the root and refuse anything that escapes it.
 * Attestations are untrusted input: "../../etc/passwd" must never be hashed,
 * and neither may a symlink inside the repo that points outside it.
 */
export function resolveSubject(root: string, subject: string): string | null {
  if (!subject || isAbsolute(subject)) return null;
  const base = resolve(root);
  const abs = resolve(base, subject);
  const rel = relative(base, abs);
  if (rel === "" || escapes(rel)) return null;
  // Follow symlinks (in the file or any parent folder) and check again against the real root.
  if (existsSync(abs)) {
    try {
      const realRel = relative(realpathSync(base), realpathSync(abs));
      if (realRel === "" || escapes(realRel)) return null;
    } catch {
      return null;
    }
  }
  return abs;
}

function toPosix(p: string): string {
  return p.split(sep).join("/");
}

/** Run a check from the repo root and record what happened. */
export function runCheck(root: string, command: string): AttestedCheck {
  const started = Date.now();
  const r = spawnSync(command, { cwd: root, shell: true, maxBuffer: 256 * 1024 * 1024 });
  const exitCode = r.error ? 127 : (r.status ?? 128);
  const output = Buffer.concat([r.stdout ?? Buffer.alloc(0), r.stderr ?? Buffer.alloc(0)]);
  return {
    command,
    exitCode,
    outputSha256: createHash("sha256").update(output).digest("hex"),
    durationMs: Date.now() - started,
    witnessed: true,
  };
}

function hashFiles(root: string, paths: string[], label: string): AttestedSubject[] {
  return paths.map((s) => {
    const abs = resolveSubject(root, s);
    if (!abs) throw new Error(`${label} must be a path inside the repo: ${s}`);
    if (!existsSync(abs) || !statSync(abs).isFile()) throw new Error(`${label} not found: ${s}`);
    return { path: toPosix(relative(root, abs)), sha256: sha256File(abs) };
  });
}

export function isPassingVerdict(verdict: string): boolean {
  return (PASSING_VERDICTS as readonly string[]).includes(verdict);
}

/**
 * Build an attestation for the given subjects as they are on disk now.
 *
 * `run` commands are executed here, before anything is written. A passing
 * verdict is refused if any of them (or any claimed check) exited non-zero.
 */
export function createAttestation(opts: {
  root?: string;
  subjects: string[];
  verdict: Verdict;
  by: string;
  note?: string;
  now?: Date;
  /** Files the verdict was checked against. */
  against?: string[];
  /** Commands Slipmark runs and records (witnessed). */
  run?: string[];
  /** Checks the attester says it ran (claimed). */
  checks?: { command: string; exitCode: number }[];
  kind?: AttesterKind;
  agent?: AgentInfo;
  /** Record the agent context: true for the default context files, or a list of globs. */
  context?: boolean | string[];
  /** The attester has read the hidden content in these files and accepts it. */
  acknowledgeHidden?: boolean;
  /** Test hook: replaces runCheck. */
  runner?: (root: string, command: string) => AttestedCheck;
}): Attestation {
  const root = resolve(opts.root ?? process.cwd());
  if (!opts.by) throw new Error("attestation needs --by (who gave the verdict)");
  if (!opts.verdict) throw new Error("attestation needs --verdict");
  if (opts.subjects.length === 0) throw new Error("attestation needs at least one --subject");
  if (opts.kind && !["agent", "tool", "human"].includes(opts.kind)) throw new Error(`--kind must be agent, tool or human, not ${opts.kind}`);

  const subjects = hashFiles(root, opts.subjects, "subject");
  const against = hashFiles(root, opts.against ?? [], "--against file");

  const runner = opts.runner ?? runCheck;
  const checks: AttestedCheck[] = [
    ...(opts.run ?? []).map((c) => runner(root, c)),
    ...(opts.checks ?? []).map((c) => ({ command: c.command, exitCode: c.exitCode, witnessed: false })),
  ];
  const failed = checks.filter((c) => c.exitCode !== 0);
  if (failed.length > 0 && isPassingVerdict(opts.verdict)) {
    const what = failed.map((c) => `"${c.command}" exited ${c.exitCode}`).join(", ");
    throw new Error(`refusing to record "${opts.verdict}": ${what}. Record --verdict fail instead, or fix it and attest again.`);
  }

  const agent: AgentInfo = {};
  if (opts.agent?.model) agent.model = opts.agent.model;
  if (opts.agent?.harness) agent.harness = opts.agent.harness;
  if (opts.agent?.harnessVersion) agent.harnessVersion = opts.agent.harnessVersion;
  const context = opts.context ? contextDigests(root, opts.context === true ? DEFAULT_CONTEXT_FILES : opts.context) : undefined;
  const v2 = against.length > 0 || checks.length > 0 || Object.keys(agent).length > 0 || opts.kind !== undefined || context !== undefined || !!opts.acknowledgeHidden;

  const att: Attestation = {
    schema: v2 ? ATTESTATION_SCHEMA_V2 : ATTESTATION_SCHEMA,
    by: opts.by,
    verdict: opts.verdict,
    at: (opts.now ?? new Date()).toISOString(),
    subjects,
  };
  if (opts.kind) att.kind = opts.kind;
  if (Object.keys(agent).length > 0) att.agent = agent;
  if (against.length > 0) att.against = against;
  if (checks.length > 0) att.checks = checks;
  if (context !== undefined) att.context = context;
  if (opts.acknowledgeHidden) att.acknowledgedHidden = true;
  if (opts.note) att.note = opts.note;
  return att;
}

/**
 * Glob test for agent context. At the repository root and inside dot-folders
 * (.claude, .cursor, ...) case is ignored: agents on macOS and Windows open
 * claude.md as CLAUDE.md. Deeper in the tree it isn't, so ordinary docs such as
 * docs/providers/claude.md don't count as agent instructions.
 */
function contextMatch(path: string, globs: string[]): boolean {
  const ignoreCase = !path.includes("/") || path.startsWith(".");
  return globs.some((g) => (ignoreCase ? new RegExp(globToRegExp(g).source, "i") : globToRegExp(g)).test(path));
}

/** A link (or anything that isn't a regular file) where agent context would be. */
export interface ContextProblem {
  path: string;
  message: string;
}

/**
 * Agent context in the repo: tracked and untracked files (git ignores excluded)
 * matching `globs`, case-insensitively. Outside git, a walk of the tree that
 * skips .git and node_modules. .slipmark/ is never context.
 *
 * A link is allowed only when it points at another context file in the repo
 * (CLAUDE.md -> AGENTS.md is common); its content is hashed through the link.
 * Any other link, including a linked folder such as .claude -> tools/cfg, is a
 * problem: it would put instructions outside what the gate watches.
 */
export function scanContext(root: string, globs: string[]): { files: string[]; problems: ContextProblem[] } {
  root = resolve(root);
  let all: string[];
  try {
    all = git(root, ["ls-files", "-co", "--exclude-standard", "-z"]).split("\0").filter(Boolean);
  } catch {
    all = [];
    const walk = (rel: string) => {
      for (const e of readdirSync(join(root, rel), { withFileTypes: true })) {
        const p = rel ? `${rel}/${e.name}` : e.name;
        if (e.isDirectory()) {
          if (e.name !== ".git" && e.name !== "node_modules") walk(p);
        } else all.push(p);
      }
    };
    walk("");
  }
  const files: string[] = [];
  const problems: ContextProblem[] = [];
  // A path is context if it matches, or if it is a folder some glob reaches into (a linked .claude, say).
  const reachesInto = (p: string) =>
    globs.some((g) => {
      const fixed = g.split(/[*?]/)[0]!; // the literal start of the glob, like ".claude/" or ".github/instructions/"
      return fixed.toLowerCase().startsWith(p.toLowerCase() + "/") || contextMatch(`${p}/x`, globs);
    });
  // Submodules (gitlinks): their content is another repository the gate can't hash. At a context path, refused like a link.
  let gitlinks: string[] = [];
  try {
    gitlinks = git(root, ["ls-files", "-s", "-z"])
      .split("\0")
      .filter((e) => e.startsWith("160000 "))
      .map((e) => toPosix(e.slice(e.indexOf("\t") + 1)));
  } catch {
    gitlinks = [];
  }
  for (const g of gitlinks) {
    if (contextMatch(g, globs) || reachesInto(g)) {
      problems.push({ path: g, message: `${g} is a submodule. Agent context must be real files in this repository, so every instruction is watched.` });
    }
  }
  const skip = new Set(gitlinks);
  for (const p of [...new Set(all.map(toPosix))].sort()) {
    if (p.startsWith(".slipmark/") || skip.has(p)) continue;
    const abs = join(root, p);
    let st;
    try {
      st = lstatSync(abs);
    } catch {
      continue; // listed by git but gone from disk
    }
    const isContext = contextMatch(p, globs);
    if (st.isSymbolicLink()) {
      if (!isContext && !reachesInto(p)) continue;
      let target: string | null = null;
      try {
        target = toPosix(relative(realpathSync(root), realpathSync(abs)));
      } catch {
        target = null;
      }
      const ok =
        isContext &&
        target !== null &&
        !target.startsWith("..") &&
        !isAbsolute(target) &&
        contextMatch(target, globs) &&
        statSync(abs).isFile();
      if (ok) files.push(p);
      else problems.push({ path: p, message: `${p} is a link${target ? ` to ${target}` : ""}. Agent context must be real files in the repo, or links to other context files, so every instruction is watched.` });
      continue;
    }
    if (isContext && st.isFile()) files.push(p);
  }
  return { files, problems };
}

/** Agent context files in the repo matching `globs`. See scanContext. */
export function listContextFiles(root: string, globs: string[]): string[] {
  return scanContext(root, globs).files;
}

/** Hashes of the agent context, as recorded on an attestation. Must run from the repository root. */
export function contextDigests(root: string, globs: string[]): AttestedSubject[] {
  root = resolve(root);
  requireRepoRoot(root, "agent context");
  const { files, problems } = scanContext(root, globs);
  const linkHash = (p: string) => createHash("sha256").update(`link:${(() => { try { return readlinkSync(join(root, p)); } catch { return ""; } })()}`).digest("hex");
  return [
    ...files.map((p) => ({ path: p, sha256: sha256File(join(root, p)) })),
    ...problems.map((x) => ({ path: x.path, sha256: linkHash(x.path) })),
  ].sort((a, b) => a.path.localeCompare(b.path));
}

/** Context is about the whole repository: a subfolder run would miss the root's AGENTS.md. In a git repo, `root` must be its top. */
function requireRepoRoot(root: string, what: string): void {
  let top: string;
  try {
    top = git(root, ["rev-parse", "--show-toplevel"]).trim();
  } catch {
    return; // not a git repository: the folder is the whole tree
  }
  if (realpathSync(top) !== realpathSync(root)) {
    throw new Error(`${what}: run from the repository root (${top}), not a subfolder. Agents in a subfolder still read the root's instructions, so the check covers the whole repository.`);
  }
}

/** Default file name for an attestation: one per agent per first subject. */
export function defaultAttestationPath(dir: string, att: Attestation): string {
  const first = att.subjects[0]?.path ?? "subject";
  const slug = `${att.by}--${first}`.replace(/[^A-Za-z0-9._-]+/g, "_").slice(0, 160);
  return join(dir, `${slug}.json`);
}

/**
 * Where `slipmark attest --out/--dir` may write. An agent can be talked into
 * passing these flags, so the target must be a .json file inside the repository
 * (the working folder outside one), and anything already there must be an
 * attestation: never a source file, a config file or something in a home folder.
 */
export function checkAttestationTarget(filePath: string): void {
  const file = resolve(filePath);
  const cwd = resolve(process.cwd());
  if (!file.endsWith(".json")) throw new Error(`${relative(cwd, file) || file}: an attestation file must end in .json`);
  let realTop: string;
  try {
    realTop = realpathSync(git(cwd, ["rev-parse", "--show-toplevel"]).trim());
  } catch {
    realTop = realpathSync(cwd);
  }
  // Check the nearest folder that exists, through any links (writeAttestation refuses links inside).
  let a = dirname(file);
  while (!existsSync(a) && dirname(a) !== a) a = dirname(a);
  const real = realpathSync(a);
  if (real !== realTop && !real.startsWith(realTop + sep)) {
    throw new Error(`${file} is outside the repository (${realTop}): refusing to write an attestation there`);
  }
  let existing: ReturnType<typeof lstatSync> | undefined;
  try {
    existing = lstatSync(file);
  } catch {
    return; // nothing there yet
  }
  let schema: unknown;
  try {
    schema = existing.isFile() ? (JSON.parse(readFileSync(file, "utf8")) as { schema?: unknown })?.schema : undefined;
  } catch {
    schema = undefined;
  }
  if (schema !== ATTESTATION_SCHEMA && schema !== ATTESTATION_SCHEMA_V2) {
    throw new Error(`${relative(cwd, file)} already exists and isn't an attestation: refusing to overwrite it`);
  }
}

/**
 * Writes an attestation without following links. A pull request can commit a
 * link at an attestation's predictable name, or link `.slipmark/` elsewhere;
 * writing through either would put the file (or overwrite one) outside the
 * repository when someone attests in that checkout. So: refuse a link at the
 * file or at any folder on its way down from the top of the repository (checked
 * before anything is created), and write
 * a temporary file then rename it over the name, which replaces a link rather
 * than writing to its target.
 */
export function writeAttestation(filePath: string, att: Attestation): void {
  const file = resolve(filePath);
  const dir = dirname(file);
  const cwd = resolve(process.cwd());
  // Check from the top of the repository, so a linked .slipmark is caught when
  // attesting from a subfolder too. Outside a repository, from the working folder.
  let realTop: string;
  try {
    realTop = realpathSync(git(cwd, ["rev-parse", "--show-toplevel"]).trim());
  } catch {
    realTop = realpathSync(cwd);
  }
  // The same folder can be spelled two ways (macOS: /var/... is /private/var/...).
  // Find the outermost ancestor of the target that is inside the repository,
  // whatever its spelling (an alias may point at a subfolder); everything below
  // it is checked level by level.
  let top: string | null = null;
  const ancestors: string[] = [];
  for (let a = dir; ; a = dirname(a)) {
    ancestors.unshift(a);
    if (dirname(a) === a) break;
  }
  for (const a of ancestors) {
    try {
      const r = realpathSync(a);
      if (r === realTop || r.startsWith(realTop + sep)) {
        top = a;
        break;
      }
    } catch {
      break; // doesn't exist yet, so nothing below it does either
    }
  }
  if (top !== null) {
    // Inside the repository: check each level before creating anything, so a
    // linked folder can't even get an empty directory made at its target.
    let d = top;
    for (const part of relative(top, dir).split(sep).filter(Boolean)) {
      d = join(d, part);
      let st: ReturnType<typeof lstatSync> | undefined;
      try {
        st = lstatSync(d);
      } catch {
        st = undefined;
      }
      if (!st) mkdirSync(d);
      else if (st.isSymbolicLink()) throw new Error(`${relative(cwd, d) || d} is a link: refusing to write an attestation through it`);
      else if (!st.isDirectory()) throw new Error(`${relative(cwd, d) || d} is not a folder`);
    }
  } else {
    mkdirSync(dir, { recursive: true }); // a folder the user chose outside the repository
  }
  let existing: ReturnType<typeof lstatSync> | undefined;
  try {
    existing = lstatSync(file);
  } catch {
    existing = undefined; // doesn't exist yet
  }
  if (existing && !existing.isFile()) {
    throw new Error(`${relative(cwd, file)} is ${existing.isSymbolicLink() ? "a link" : "not a regular file"}: refusing to write an attestation through it`);
  }
  const tmp = join(dir, `.${basename(file)}.${process.pid}.${createHash("sha256").update(`${Date.now()}${Math.random()}`).digest("hex").slice(0, 8)}.tmp`);
  writeFileSync(tmp, JSON.stringify(att, null, 2) + "\n", { encoding: "utf8", flag: "wx" });
  try {
    renameSync(tmp, file);
  } catch (e) {
    try { unlinkSync(tmp); } catch { /* already gone */ }
    throw e;
  }
}

function isSubjectList(v: unknown, allowEmpty: boolean): boolean {
  return (
    Array.isArray(v) &&
    (allowEmpty || v.length > 0) &&
    v.every(
      (s) =>
        s &&
        typeof s === "object" &&
        typeof (s as AttestedSubject).path === "string" &&
        typeof (s as AttestedSubject).sha256 === "string" &&
        /^[0-9a-f]{64}$/.test((s as AttestedSubject).sha256),
    )
  );
}

function isCheckList(v: unknown): boolean {
  return (
    Array.isArray(v) &&
    v.every(
      (c) =>
        c &&
        typeof c === "object" &&
        typeof (c as AttestedCheck).command === "string" &&
        Number.isInteger((c as AttestedCheck).exitCode) &&
        typeof (c as AttestedCheck).witnessed === "boolean",
    )
  );
}

function isAttestation(v: unknown): v is Attestation {
  if (!v || typeof v !== "object") return false;
  const a = v as Record<string, unknown>;
  const base =
    typeof a.by === "string" && typeof a.verdict === "string" && isSubjectList(a.subjects, false);
  if (a.signature !== undefined && !(a.signature && typeof a.signature === "object" && (a.signature as { bundle?: unknown }).bundle && typeof (a.signature as { bundle?: unknown }).bundle === "object")) return false;
  if (a.schema === ATTESTATION_SCHEMA) return base;
  if (a.schema !== ATTESTATION_SCHEMA_V2 || !base) return false;
  if (a.against !== undefined && !isSubjectList(a.against, true)) return false;
  if (a.checks !== undefined && !isCheckList(a.checks)) return false;
  if (a.context !== undefined && !isSubjectList(a.context, true)) return false;
  if (a.acknowledgedHidden !== undefined && a.acknowledgedHidden !== true) return false;
  if (a.kind !== undefined && !["agent", "tool", "human"].includes(a.kind as string)) return false;
  if (a.agent !== undefined) {
    if (!a.agent || typeof a.agent !== "object") return false;
    const model = (a.agent as AgentInfo).model;
    if (model !== undefined && typeof model !== "string") return false;
  }
  return true;
}

/** Glob to RegExp. Supports `**`, `*` and `?`, matched against the whole repo-relative path. */
export function globToRegExp(glob: string): RegExp {
  let re = "";
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]!;
    if (c === "*") {
      if (glob[i + 1] === "*") {
        i++;
        if (glob[i + 1] === "/") {
          i++;
          re += "(?:.*/)?";
        } else re += ".*";
      } else re += "[^/]*";
    } else if (c === "?") re += "[^/]";
    else re += c.replace(/[.+^${}()|[\]\\]/g, "\\$&");
  }
  return new RegExp(`^${re}$`);
}

export function matchesAny(path: string, globs: string[]): boolean {
  return globs.some((g) => globToRegExp(g).test(path));
}

/** Read and check `.slipmark/policy.json`. Returns null when there is none. Throws when it is malformed. */
export function loadPolicy(root: string): Policy | null {
  const file = join(resolve(root), POLICY_FILE);
  if (!existsSync(file)) {
    // Run from a subfolder, the repository's own policy would be missed and its rules silently dropped. Refuse instead.
    let top: string | null = null;
    try {
      top = execFileSync("git", ["rev-parse", "--show-toplevel"], { cwd: resolve(root), encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
    } catch {
      top = null; // not a git repository: nothing above to miss
    }
    if (top && realpathSync(top) !== realpathSync(resolve(root)) && existsSync(join(top, POLICY_FILE))) {
      throw new Error(`${POLICY_FILE} is at the repository root (${top}). Run from there, or pass --no-policy to skip it on purpose.`);
    }
    return null;
  }
  return parsePolicy(readFileSync(file, "utf8"));
}

/** Parse and check the text of a policy file. `label` names where it came from in errors. */
export function parsePolicy(text: string, label: string = POLICY_FILE): Policy {
  const POLICY_FILE = label; // error messages below name the file as read
  let p: unknown;
  try {
    p = JSON.parse(text);
  } catch (e) {
    throw new Error(`${POLICY_FILE} is not valid JSON: ${e instanceof Error ? e.message : String(e)}`);
  }
  const policy = p as Policy;
  if (!policy || typeof policy !== "object" || Array.isArray(policy) || policy.schema !== POLICY_SCHEMA) {
    throw new Error(`${POLICY_FILE} must have "schema": "${POLICY_SCHEMA}"`);
  }
  const cov = policy.coverage;
  if (cov !== undefined) {
    if (!cov || typeof cov !== "object" || cov.mode !== "diff" || typeof cov.base !== "string" || !cov.base) {
      throw new Error(`${POLICY_FILE}: coverage needs "mode": "diff" and a "base" ref`);
    }
    checkBase(cov.base);
    if (cov.ignore !== undefined && !(Array.isArray(cov.ignore) && cov.ignore.every((g) => typeof g === "string"))) {
      throw new Error(`${POLICY_FILE}: coverage.ignore must be a list of globs`);
    }
  }
  const models = policy.models;
  if (models !== undefined && !(models && typeof models === "object" && Array.isArray(models.allow) && models.allow.every((m) => typeof m === "string"))) {
    throw new Error(`${POLICY_FILE}: models.allow must be a list of model names`);
  }
  const sig = policy.signatures;
  if (sig !== undefined) {
    if (!sig || typeof sig !== "object" || Array.isArray(sig)) throw new Error(`${POLICY_FILE}: signatures must be an object`);
    if (sig.require !== undefined && typeof sig.require !== "boolean") throw new Error(`${POLICY_FILE}: signatures.require must be true or false`);
    if (sig.trusted !== undefined && !(Array.isArray(sig.trusted) && sig.trusted.every((t) => typeof t === "string" && t.length > 0))) {
      throw new Error(`${POLICY_FILE}: signatures.trusted must be a list of signer identities`);
    }
    if (sig.issuer !== undefined && !(typeof sig.issuer === "string" && /^https:\/\//.test(sig.issuer))) throw new Error(`${POLICY_FILE}: signatures.issuer must be an https URL`);
    if (sig.require && !sig.trusted?.length) {
      throw new Error(`${POLICY_FILE}: signatures.require needs a "trusted" list, for example the workflow that runs your review agent at refs/heads/main`);
    }
  }
  const ctx = policy.context;
  if (ctx !== undefined) {
    if (!ctx || typeof ctx !== "object" || Array.isArray(ctx)) throw new Error(`${POLICY_FILE}: context must be an object`);
    if (ctx.files !== undefined && !(Array.isArray(ctx.files) && ctx.files.length > 0 && ctx.files.every((g) => typeof g === "string" && g.length > 0))) {
      throw new Error(`${POLICY_FILE}: context.files must be a list of globs`);
    }
    if (ctx.approvers !== undefined && !(Array.isArray(ctx.approvers) && ctx.approvers.length > 0 && ctx.approvers.every((k) => ["agent", "tool", "human"].includes(k)))) {
      throw new Error(`${POLICY_FILE}: context.approvers must list agent, tool or human`);
    }
    if (ctx.approverSigners !== undefined && !(Array.isArray(ctx.approverSigners) && ctx.approverSigners.length > 0 && ctx.approverSigners.every((x) => typeof x === "string" && x.length > 0))) {
      throw new Error(`${POLICY_FILE}: context.approverSigners must be a list of signer identities`);
    }
    if (ctx.requireRecorded !== undefined && typeof ctx.requireRecorded !== "boolean") throw new Error(`${POLICY_FILE}: context.requireRecorded must be true or false`);
    if (ctx.githubRender !== undefined && !["auto", "require", "off"].includes(ctx.githubRender)) throw new Error(`${POLICY_FILE}: context.githubRender must be "auto", "require" or "off"`);
    if (ctx.hiddenContent !== undefined && !["refuse", "allow"].includes(ctx.hiddenContent)) throw new Error(`${POLICY_FILE}: context.hiddenContent must be "refuse" or "allow"`);
  }
  const bundle = policy.bundle;
  if (bundle !== undefined) {
    if (!bundle || typeof bundle !== "object" || Array.isArray(bundle)) throw new Error(`${POLICY_FILE}: bundle must be an object`);
    const reqs = bundle.require;
    if (!Array.isArray(reqs) || reqs.length === 0) throw new Error(`${POLICY_FILE}: bundle.require must list at least one { "predicateType", "signers" }`);
    const seen = new Set<string>();
    for (const r of reqs) {
      if (!r || typeof r !== "object" || Array.isArray(r) || typeof r.predicateType !== "string" || !/^https:\/\/\S+$/.test(r.predicateType)) {
        throw new Error(`${POLICY_FILE}: each bundle.require entry needs a "predicateType" URI`);
      }
      if (!(Array.isArray(r.signers) && r.signers.length > 0 && r.signers.every((x) => typeof x === "string" && x.length > 0))) {
        throw new Error(`${POLICY_FILE}: bundle.require for ${r.predicateType} needs a "signers" list, for example the workflow that signs it at refs/heads/main`);
      }
      if (seen.has(r.predicateType)) throw new Error(`${POLICY_FILE}: bundle.require lists ${r.predicateType} twice`);
      seen.add(r.predicateType);
    }
    if (bundle.issuer !== undefined && !(typeof bundle.issuer === "string" && /^https:\/\//.test(bundle.issuer))) throw new Error(`${POLICY_FILE}: bundle.issuer must be an https URL`);
  }
  const req = policy.require;
  if (req !== undefined && !(Array.isArray(req) && req.every((r) => typeof r === "string" && r.length > 0))) {
    throw new Error(`${POLICY_FILE}: require must be a list of file paths`);
  }
  return policy;
}

/** The policy file's text at `ref`: null when the ref has no policy file. Throws when the ref isn't in this checkout. */
export function policyTextAt(root: string, ref: string): string | null {
  checkBase(ref, "policy base");
  // Run from a subfolder (a monorepo package), read that folder's policy at the ref, as loadPolicy does on disk.
  let prefix: string;
  try {
    prefix = git(root, ["rev-parse", "--show-prefix"]).trim();
  } catch {
    throw new Error("policy: this folder is not inside a git repository, so the policy can't be read from a branch");
  }
  let commit: string;
  try {
    if (!refExists(root, ref)) throw new Error("missing");
    commit = git(root, ["rev-parse", "--verify", "--quiet", `${ref}^{commit}`]).trim();
  } catch {
    throw new Error(`policy: can't find "${ref}" in this checkout, so the base branch's policy can't be read. Fetch it first (git fetch origin <branch>), or use actions/checkout with fetch-depth: 0.`);
  }
  // ls-tree, not cat-file -e: "not there" is null, anything odd (a link, a folder, a git error) is an error, never "no policy".
  const entryAt = (path: string): string[] | null => {
    const entry = git(root, ["ls-tree", "-z", "--full-tree", commit, "--", path]).split("\0")[0];
    return entry ? entry.split("\t")[0]!.split(" ") : null;
  };
  const read = (path: string): string | null => {
    const entry = entryAt(path);
    if (!entry) {
      // Missing only if every folder on the way is a real folder. A linked .slipmark would hide the policy, so it's an error.
      const parts = path.split("/");
      for (let i = 1; i < parts.length; i++) {
        const dir = parts.slice(0, i).join("/");
        const e = entryAt(dir);
        if (!e) return null;
        if (e[1] !== "tree") throw new Error(`policy: ${dir} on ${ref} isn't a folder (a link, for example), so the policy in it can't be trusted`);
      }
      return null;
    }
    const [mode, type, object] = entry;
    if (type !== "blob" || mode === "120000") throw new Error(`policy: ${path} on ${ref} isn't a regular file, so it can't be trusted as the policy`);
    return git(root, ["cat-file", "blob", object!]);
  };
  const own = read(`${prefix}${POLICY_FILE}`);
  if (own !== null || !prefix) return own;
  if (read(POLICY_FILE) !== null) {
    throw new Error(`${POLICY_FILE} is at the repository root on ${ref}. Run from the root, or pass --no-policy to skip it on purpose.`);
  }
  return null;
}

/**
 * Whether `ref` names something in this checkout. A full name (refs/...) must
 * exist exactly: when refs/remotes/origin/main is missing, git would otherwise
 * fall back to a tag of that name, which anyone who can push tags controls.
 */
function refExists(root: string, ref: string): boolean {
  if (ref.startsWith("refs/")) return spawnSync("git", ["show-ref", "--verify", "--quiet", ref], { cwd: root, stdio: "ignore" }).status === 0;
  return spawnSync("git", ["rev-parse", "--verify", "--quiet", `${ref}^{commit}`], { cwd: root, stdio: "ignore" }).status === 0;
}

const sha256Text = (t: string): string => createHash("sha256").update(t).digest("hex");

/**
 * Decide which policy file applies, and record where it came from.
 *
 * - `from: "<ref>"`: read the policy from that ref. The ref must be in the checkout.
 * - `from: "working-tree"`: read it from the checkout (the v0.4 behaviour).
 * - otherwise the first of `candidates` found in the checkout is used, and when
 *   there are candidates but none can be found, the checkout is used and the
 *   report says why.
 *
 * A pull request can edit `.slipmark/policy.json`. Read from the base branch,
 * those edits only take effect after merge, so a PR can't loosen its own rules.
 */
export function resolvePolicy(opts: { root?: string; from?: string; candidates?: string[] }): { policy: Policy | null; info: PolicySource } {
  const root = resolve(opts.root ?? process.cwd());
  const wtFile = join(root, POLICY_FILE);
  const wtText = existsSync(wtFile) ? readFileSync(wtFile, "utf8") : null;

  const fromWorkingTree = (notes?: string[]): { policy: Policy | null; info: PolicySource } => {
    const policy = loadPolicy(root);
    const info: PolicySource = { source: policy ? "working-tree" : "none" };
    if (policy && wtText !== null) info.sha256 = sha256Text(wtText);
    if (notes?.length) info.notes = notes;
    return { policy, info };
  };

  const fromRef = (ref: string): { policy: Policy | null; info: PolicySource } => {
    const text = policyTextAt(root, ref);
    const policy = text === null ? null : parsePolicy(text, `${POLICY_FILE} at ${ref}`);
    const info: PolicySource = { source: "base", ref };
    if (text !== null) info.sha256 = sha256Text(text);
    const norm = (t: string | null) => (t === null ? null : t.replace(/\r\n/g, "\n"));
    if (norm(text) !== norm(wtText)) {
      info.changedOnBranch = true;
      info.notes = [
        text === null
          ? `This branch adds ${POLICY_FILE}. It isn't applied until it is merged into ${ref}.`
          : wtText === null
            ? `This branch deletes ${POLICY_FILE}. The policy on ${ref} still applies until the deletion is merged.`
            : `This branch changes ${POLICY_FILE}. The policy on ${ref} was applied; the new one takes effect after merge.`,
      ];
    }
    return { policy, info };
  };

  // A folder's own policy replaces the root one rather than adding to it. That's for
  // deliberate setups (a monorepo package), so say so in the report whenever it happens.
  const noteShadowedRoot = (r: { policy: Policy | null; info: PolicySource }): { policy: Policy | null; info: PolicySource } => {
    if (!r.policy) return r;
    let top: string;
    try {
      top = git(root, ["rev-parse", "--show-toplevel"]).trim();
    } catch {
      return r;
    }
    if (realpathSync(top) === realpathSync(root)) return r;
    // Look where the policy came from: a branch that deletes the root policy must not hide this note.
    const rootHasPolicy =
      r.info.source === "base" && r.info.ref
        ? spawnSync("git", ["cat-file", "-e", `${git(root, ["rev-parse", "--verify", "--quiet", `${r.info.ref}^{commit}`]).trim()}:${POLICY_FILE}`], { cwd: root, stdio: "ignore" }).status === 0
        : existsSync(join(top, POLICY_FILE));
    if (!rootHasPolicy) return r;
    const here = toPosix(relative(top, root));
    r.info.notes = [
      ...(r.info.notes ?? []),
      `The policy in ${here}/${POLICY_FILE} was used. The repository root's ${POLICY_FILE} was not read: a folder's own policy replaces the root one, it doesn't add to it.`,
    ];
    return r;
  };
  return noteShadowedRoot(pickPolicy());

  function pickPolicy(): { policy: Policy | null; info: PolicySource } {
    if (opts.from === "working-tree") return fromWorkingTree();
    if (opts.from) return fromRef(opts.from);

    const candidates = (opts.candidates ?? []).filter(Boolean);
    for (const ref of candidates) {
      let found = false;
      try {
        checkBase(ref, "policy base");
        found = refExists(root, ref);
      } catch {
        found = false;
      }
      if (found) return fromRef(ref);
    }
    if (candidates.length) {
      const r = fromWorkingTree([
        `The base branch (${candidates.join(" or ")}) isn't in this checkout, so the policy was read from this branch, which a pull request can edit. Fetch the base, or pass --policy-from <ref>.`,
      ]);
      r.info.baseMissing = candidates.join(" or ");
      return r;
    }
    return fromWorkingTree();
  }
}

/** A coverage base is a ref, never an option. `--independent` would silently make the merge base HEAD. */
export function checkBase(base: string, what: string = "coverage base"): void {
  if (!base || base.startsWith("-") || /[\0\s]/.test(base)) {
    throw new Error(`${what} must be a git ref such as origin/main, not "${base}"`);
  }
  if (base === "HEAD" || base === "@") {
    if (what !== "coverage base" && what !== "agent context base") throw new Error(`${what} "${base}" is this branch itself. Use the branch you merge into, such as origin/main`);
    throw new Error(`${what} "${base}" would compare the branch with itself and cover nothing. Use the branch you merge into, such as origin/main`);
  }
}

function git(root: string, args: string[]): string {
  return execFileSync("git", args, { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
}

/**
 * Files changed since the merge base with `base`, as the tree is now: committed,
 * staged, unstaged and untracked. Deleted files are left out (there is nothing
 * left to attest). Paths are relative to `root`.
 */
export function changedFiles(root: string, base: string, what: string = "coverage"): string[] {
  checkBase(base, `${what} base`);
  // Coverage must see the whole repository. Run from a subfolder, git would only report that folder.
  let top: string;
  try {
    top = git(root, ["rev-parse", "--show-toplevel"]).trim();
  } catch {
    throw new Error(`${what}: this folder is not inside a git repository`);
  }
  if (realpathSync(top) !== realpathSync(root)) {
    throw new Error(`${what}: run from the repository root (${top}), not a subfolder. From a subfolder it would miss changes elsewhere in the repo.`);
  }
  let mergeBase: string;
  try {
    const commit = git(root, ["rev-parse", "--verify", "--quiet", `${base}^{commit}`]).trim();
    mergeBase = git(root, ["merge-base", commit, "HEAD"]).trim();
  } catch {
    throw new Error(
      `${what}: can't find the base "${base}" in this checkout. ` +
        `In GitHub Actions, use actions/checkout with fetch-depth: 0.`,
    );
  }
  // HEAD~0 or the branch's own name is another way of writing HEAD. On a push to main
  // that's expected (base == HEAD), but on a pull request it would cover nothing.
  const event = process.env.GITHUB_EVENT_NAME;
  if ((event === "pull_request" || event === "pull_request_target") && mergeBase === git(root, ["rev-parse", "HEAD"]).trim()) {
    throw new Error(
      `${what}: the base "${base}" is this pull request's own commit, so nothing would be covered. ` +
        `Use the branch it merges into, such as origin/main.`,
    );
  }
  const split = (out: string) => out.split("\0").filter(Boolean);
  const changed = split(git(root, ["diff", "--name-only", "-z", "--relative", "--diff-filter=d", mergeBase, "--"]));
  const untracked = split(git(root, ["ls-files", "--others", "--exclude-standard", "-z"]));
  return [...new Set([...changed, ...untracked])].sort();
}

/** List *.json files in the attestation directory (non-recursive, sorted). */
export function listAttestationFiles(dir: string): string[] {
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith(".json"))
    .sort()
    .map((f) => join(dir, f));
}

/**
 * The gate. Re-hashes every attested subject on the tree as it is now.
 *
 * Fails on: a subject whose bytes changed since the verdict (hash_mismatch), a
 * subject that no longer exists, a verdict that isn't passing, a malformed
 * attestation, or a `require`d subject that no attestation covers.
 *
 * Pure apart from reading files under `root`.
 */
export function verifyAttestations(opts: {
  root?: string;
  dir?: string;
  require?: string[];
  /** Policy to apply. Omitted: read `.slipmark/policy.json` if present. `null`: no policy. */
  policy?: Policy | null;
  /** Signature checks by attestation file (repo-relative), from checkSignatures. Signed attestations without one count as unsigned. */
  signatures?: Map<string, SignatureCheck>;
  /** Where the policy came from, recorded on the report. */
  policySource?: PolicySource;
  /** Base ref for agent context checks. Default: the ref the policy was read from, else the coverage base. */
  base?: string;
  /** Findings from GitHub's renderer, by path (see verifyWithSignatures), and notes about that check. */
  renderFindings?: Map<string, HiddenFinding[]>;
  renderNotes?: string[];
}): VerifyReport {
  const base = opts.base ?? (opts.policySource?.source === "base" ? opts.policySource.ref : undefined);
  const policy = opts.policy === undefined ? loadPolicy(resolve(opts.root ?? process.cwd())) : opts.policy;
  if (policy?.context && opts.policySource?.baseMissing && !base) {
    throw new Error(`agent context: the base branch (${opts.policySource.baseMissing}) isn't in this checkout, so changes to agent instructions can't be checked. Fetch it, or use actions/checkout with fetch-depth: 0.`);
  }
  const report = verifyCore({ ...opts, policy, base });
  return opts.policySource ? { ...report, policy: opts.policySource } : report;
}

function verifyCore(opts: {
  root?: string;
  dir?: string;
  require?: string[];
  policy?: Policy | null;
  signatures?: Map<string, SignatureCheck>;
  base?: string;
  renderFindings?: Map<string, HiddenFinding[]>;
  renderNotes?: string[];
}): VerifyReport {
  const root = resolve(opts.root ?? process.cwd());
  const dir = resolve(root, opts.dir ?? ".slipmark/attestations");
  const policy = opts.policy === undefined ? loadPolicy(root) : opts.policy;
  const notes: string[] = [...(opts.renderNotes ?? [])];
  const ctxPolicy = policy?.context;
  const ctxGlobs = ctxPolicy?.files ?? DEFAULT_CONTEXT_FILES;
  const currentContext = ctxPolicy ? new Map(contextDigests(root, ctxGlobs).map((c) => [c.path, c.sha256])) : null;
  const contextProblems = ctxPolicy ? scanContext(root, ctxGlobs).problems : [];
  /** Who gave a current, passing verdict on each path: its claimed kind, and its signer when the signature is valid. */
  const coveredBy = new Map<string, { kind: AttesterKind; signedBy?: string; by: string; ackHidden: boolean }[]>();
  const required = [...new Set([...(opts.require ?? []), ...(policy?.require ?? [])])];
  const results: CheckResult[] = [];
  const covered = new Set<string>();
  const files = listAttestationFiles(dir);

  for (const file of files) {
    const attRel = toPosix(relative(root, file));
    let parsed: unknown;
    try {
      parsed = JSON.parse(readFileSync(file, "utf8"));
    } catch (e) {
      results.push({ status: "invalid", attestation: attRel, message: `not valid JSON: ${e instanceof Error ? e.message : String(e)}` });
      continue;
    }
    if (!isAttestation(parsed)) {
      results.push({ status: "invalid", attestation: attRel, message: `not a ${ATTESTATION_SCHEMA} attestation` });
      continue;
    }
    // A v1 attestation is judged on v1 fields only. Anything else in it is ignored.
    const att: Attestation =
      parsed.schema === ATTESTATION_SCHEMA
        ? { schema: parsed.schema, by: parsed.by, verdict: parsed.verdict, at: parsed.at, subjects: parsed.subjects, note: parsed.note }
        : parsed;
    const passing = isPassingVerdict(att.verdict);
    const sigPolicy = policy?.signatures;
    const sigCheck = (parsed as { signature?: unknown }).signature !== undefined ? opts.signatures?.get(attRel) : undefined;
    const signer = sigCheck?.state === "valid" && sigCheck.trusted ? sigCheck.identity : undefined;

    // Conditions on the attestation as a whole. Any of these and none of its
    // subjects count, so --require and coverage report them as not covered too.
    const attFailures: CheckResult[] = [];
    const who = { attestation: attRel, by: att.by, verdict: att.verdict };
    for (const a of att.against ?? []) {
      const abs = resolveSubject(root, a.path);
      if (!abs) {
        attFailures.push({ ...who, subject: a.path, status: "invalid", message: `against path escapes the repo: ${a.path}` });
      } else if (!existsSync(abs) || !statSync(abs).isFile()) {
        attFailures.push({ ...who, subject: a.path, status: "against_changed", message: `${att.by} checked against ${a.path}, which no longer exists` });
      } else {
        const actual = sha256File(abs);
        if (actual !== a.sha256) {
          attFailures.push({
            ...who,
            subject: a.path,
            status: "against_changed",
            expected: a.sha256,
            actual,
            message: `${att.by} gave "${att.verdict}" against a different version of ${a.path}. It changed after the verdict.`,
          });
        }
      }
    }
    // Any failed check blocks, claimed or witnessed: a claim of failure can only make the gate stricter.
    for (const c of att.checks ?? []) {
      if (c.exitCode !== 0) {
        const how = c.witnessed ? "exited" : "was reported as exiting";
        attFailures.push({ ...who, status: "check_failed", message: `${att.by}: "${c.command}" ${how} ${c.exitCode} when the verdict was recorded` });
      }
    }
    // The verdict was given under agent instructions that have since changed, or it didn't record them.
    if (currentContext && (att.kind ?? "agent") !== "human") {
      if (att.context) {
        const recorded = new Map(att.context.map((c) => [c.path, c.sha256]));
        for (const [path, sha] of recorded) {
          const now = currentContext.get(path);
          if (now !== sha) {
            attFailures.push({
              ...who,
              subject: path,
              status: "context_changed",
              expected: sha,
              ...(now ? { actual: now } : {}),
              message: now
                ? `${att.by} gave "${att.verdict}" under a different version of ${path}. The agent's instructions changed after the verdict.`
                : `${att.by} gave "${att.verdict}" under ${path}, which is no longer there. The agent's instructions changed after the verdict.`,
            });
          }
        }
        for (const path of currentContext.keys()) {
          if (!recorded.has(path)) {
            attFailures.push({ ...who, subject: path, status: "context_changed", message: `${path} was added to the agent's context after ${att.by} gave "${att.verdict}"` });
          }
        }
      } else if (ctxPolicy?.requireRecorded !== false) {
        attFailures.push({ ...who, status: "context_changed", message: `${att.by}: verdict records no agent context, so there's no telling what the agent was told. Attest again with a current Slipmark (it records context when the policy has a context section).` });
      }
    }
    const allow = policy?.models?.allow;
    if (allow && !(att.agent?.model && allow.includes(att.agent.model))) {
      const model = att.agent?.model ? `model ${att.agent.model}` : "no model recorded";
      attFailures.push({ ...who, status: "model_not_allowed", message: `${att.by}: ${model}. Policy allows: ${allow.join(", ") || "no models"}` });
    }
    // A broken signature always refuses: something was changed after signing. Missing or untrusted ones refuse only when the policy requires signatures.
    if (sigCheck?.state === "invalid") {
      attFailures.push({ ...who, status: "signature_invalid", message: `${att.by}: ${sigCheck.reason}` });
    } else if (sigPolicy?.require) {
      if (!sigCheck || sigCheck.state === "unchecked") {
        attFailures.push({ ...who, status: "unsigned", message: `${att.by}: verdict isn't signed. Policy requires a signature from ${sigPolicy.trusted?.join(" or ")}` });
      } else if (sigCheck.state === "valid" && !sigCheck.trusted) {
        attFailures.push({ ...who, status: "signer_not_trusted", message: `${att.by}: signed by ${sigCheck.identity}, which the policy doesn't trust` });
      }
    }
    if (attFailures.length > 0) {
      results.push(...attFailures);
      continue;
    }

    for (const s of att.subjects) {
      const abs = resolveSubject(root, s.path);
      const base = { attestation: attRel, subject: s.path, by: att.by, verdict: att.verdict };
      if (!abs) {
        results.push({ ...base, status: "invalid", message: `subject path escapes the repo: ${s.path}` });
        continue;
      }
      const relKey = toPosix(relative(root, abs));
      if (!existsSync(abs) || !statSync(abs).isFile()) {
        results.push({ ...base, status: "subject_missing", message: `${att.by} attested ${s.path}, which no longer exists` });
        continue;
      }
      const actual = sha256File(abs);
      if (actual !== s.sha256) {
        results.push({
          ...base,
          status: "hash_mismatch",
          expected: s.sha256,
          actual,
          message: `${att.by} gave "${att.verdict}" for a different version of ${s.path}. The file changed after the verdict.`,
        });
        continue;
      }
      if (!passing) {
        results.push({ ...base, status: "verdict_not_passing", message: `${att.by} gave "${att.verdict}" for ${s.path}` });
        continue;
      }
      covered.add(relKey);
      if (!coveredBy.has(relKey)) coveredBy.set(relKey, []);
      coveredBy.get(relKey)!.push({ kind: att.kind ?? "agent", by: att.by, ackHidden: att.acknowledgedHidden === true, ...(sigCheck?.state === "valid" ? { signedBy: sigCheck.identity } : {}) });
      results.push({ ...base, status: "verified", ...(signer ? { signer } : {}), message: `${att.by} verified ${s.path}${signer ? ` (signed by ${signer})` : ""}` });
    }
  }

  const reported = new Set<string>();
  for (const req of required) {
    const abs = resolveSubject(root, req);
    const key = abs ? toPosix(relative(root, abs)) : req;
    if (!abs || !covered.has(key)) {
      reported.add(key);
      results.push({ status: "unattested", subject: req, message: `no passing, current attestation covers ${req}` });
    }
  }

  const cov = policy?.coverage;
  if (cov) {
    const ignore = [...COVERAGE_ALWAYS_IGNORED, ...(cov.ignore ?? [])];
    for (const f of changedFiles(root, cov.base)) {
      const path = toPosix(f);
      if (covered.has(path) || reported.has(path) || matchesAny(path, ignore)) continue;
      // Only a real directory (a submodule, its own repository) is skipped. lstat, so a link is never mistaken for one.
      let entry;
      try {
        entry = lstatSync(join(root, path));
      } catch {
        entry = null;
      }
      if (entry?.isDirectory()) continue;
      const abs = resolveSubject(root, path);
      if (!abs || !existsSync(abs) || !statSync(abs).isFile()) {
        // A link out of the repo, a broken link, or anything else that can't be hashed. Never dropped silently.
        results.push({ status: "invalid", subject: path, message: `${path} changed since ${cov.base} but can't be verified: it is a link to a folder, outside the repo, or to nothing` });
        continue;
      }
      results.push({ status: "uncovered", subject: path, message: `${path} changed since ${cov.base} and no passing, current verdict covers it` });
    }
  }

  // Links in agent context point instructions somewhere the gate doesn't watch. Always refused.
  for (const p of contextProblems) results.push({ status: "context_unapproved", subject: p.path, message: p.message });

  // A change to the agent's context needs approval from someone it allows (by default a human verdict),
  // and must not hide text from the people reviewing it.
  if (ctxPolicy) {
    const ctxBase = opts.base ?? policy?.coverage?.base;
    if (!ctxBase) {
      notes.push("Agent context changes weren't checked: no base branch is known. In a pull request the Action supplies it; locally, pass --policy-from <ref> or --coverage diff --base <ref>.");
    } else {
      const approvers = ctxPolicy.approvers ?? ["human"];
      const signers = ctxPolicy.approverSigners;
      const approvals = (path: string) =>
        (coveredBy.get(path) ?? []).filter(
          (v) => approvers.includes(v.kind) && (!signers || (v.signedBy !== undefined && signers.some((p) => identityMatches(v.signedBy!, p)))),
        );
      const approved = (path: string) => approvals(path).length > 0;
      const problemPaths = new Set(contextProblems.map((p) => p.path));
      const scanStarted = Date.now();
      for (const f of changedFiles(root, ctxBase, "agent context")) {
        const path = toPosix(f);
        if (!currentContext!.has(path) || problemPaths.has(path)) continue;
        if (!approved(path)) {
          const who = `${approvers.join(" or ")}${signers ? `, signed by ${signers.join(" or ")}` : ""}`;
          results.push({
            status: "context_unapproved",
            subject: path,
            message: `${path} is agent context and changed since ${ctxBase}. It needs a passing verdict from: ${who}. Read it as an agent would, then: slipmark attest --kind ${approvers[0]} --by <you> --verdict pass --subject ${path}`,
          });
        }
        if (ctxPolicy.hiddenContent !== "allow" && Date.now() - scanStarted > 60_000) {
          // Each file has its own time limit; this caps them all together, so many files can't add up to a stall.
          results.push({ status: "hidden_content", subject: path, message: `${path} wasn't checked: the agent context checks ran out of time (a minute in all). Split the change, or simplify these files.` });
        } else if (ctxPolicy.hiddenContent !== "allow") {
          let text: string | null;
          try {
            text = new TextDecoder("utf-8", { fatal: true }).decode(readFileSync(join(root, path)));
          } catch {
            text = null; // UTF-16 or binary: the scan can't read it, so neither can a reviewer be sure what it says
          }
          const findings: HiddenFinding[] = [
            ...(text === null
              ? [{ path, line: 1, kind: "invisible_characters" as const, detail: "not valid UTF-8, so its text can't be checked" }]
              : scanHiddenContent(path, text)),
            ...(opts.renderFindings?.get(path) ?? []),
          ];
          if (findings.length) {
            const list = findings.slice(0, 5).map((h) => `line ${h.line}: ${h.detail}`).join("; ");
            // An acknowledgement is only as strong as its signature: unsigned, anyone opening the PR could write one.
            const ack = signers ? approvals(path).find((v) => v.ackHidden) : undefined;
            if (!signers && approvals(path).some((v) => v.ackHidden)) {
              notes.push(`${path}: an acknowledgement of hidden content was recorded but doesn't count: set context.approverSigners so acknowledgements must be signed`);
            }
            if (ack) {
              notes.push(`${path}: ${findings.length} piece(s) of hidden content acknowledged by ${ack.by}: ${findings.slice(0, 3).map((h) => `line ${h.line}`).join(", ")}`);
              continue;
            }
            results.push({
              status: "hidden_content",
              subject: path,
              message: `${path} is agent context with text a reviewer may not see (${list}${findings.length > 5 ? `, and ${findings.length - 5} more` : ""}). ${signers ? `Remove it, or, if you've read it and accept it, sign an acknowledgement: slipmark attest --kind ${(ctxPolicy.approvers ?? ["human"])[0]} --by <you> --verdict pass --acknowledge-hidden --sign --subject ${path}` : `Remove it. To accept content like this after reading it, set context.approverSigners on the base branch and sign an acknowledgement, or set context.hiddenContent to "allow".`}`,
            });
          }
        }
      }
    }
  }

  const failures = results.filter((r) => r.status !== "verified");
  const checked = results.length;
  // An empty run is not a pass: a gate with nothing to check proves nothing.
  const ok = failures.length === 0 && checked > 0;
  if (checked === 0) {
    const empty: CheckResult = { status: "unattested", message: `no attestations found in ${toPosix(relative(root, dir)) || "."}` };
    return { ok: false, checked: 0, results: [empty], failures: [empty], ...(notes.length ? { notes } : {}) };
  }
  return { ok, checked, results, failures, ...(notes.length ? { notes } : {}) };
}

/**
 * Check the signature on every signed attestation in `dir`. Sigstore needs the network,
 * so this is the async step before verifyAttestations. When the policy requires
 * signatures and one can't be checked, it throws: that's "couldn't run", not a pass.
 */
export async function checkSignatures(opts: {
  root?: string;
  dir?: string;
  policy?: Policy | null;
  verify?: Parameters<typeof checkSignature>[2];
}): Promise<Map<string, SignatureCheck>> {
  const root = resolve(opts.root ?? process.cwd());
  const dir = resolve(root, opts.dir ?? ".slipmark/attestations");
  const sigPolicy = opts.policy?.signatures;
  const out = new Map<string, SignatureCheck>();
  for (const file of listAttestationFiles(dir)) {
    let raw: unknown;
    try {
      raw = JSON.parse(readFileSync(file, "utf8"));
    } catch {
      continue; // reported as invalid by verifyAttestations
    }
    if (!raw || typeof raw !== "object" || (raw as { signature?: unknown }).signature === undefined) continue;
    const check = await checkSignature(raw as Record<string, unknown>, sigPolicy, opts.verify);
    if (check.state === "unchecked" && sigPolicy?.require) throw new Error(`couldn't check signatures: ${check.reason}`);
    out.set(toPosix(relative(root, file)), check);
  }
  return out;
}

/** The whole gate, signatures included. */
export async function verifyWithSignatures(opts: {
  root?: string;
  dir?: string;
  require?: string[];
  policy?: Policy | null;
  policySource?: PolicySource;
  verify?: Parameters<typeof checkSignature>[2];
  /** GitHub's renderer. Omitted: from the environment (GitHub Actions with a token). null: don't use it. */
  render?: RenderFn | null;
}): Promise<VerifyReport> {
  const root = resolve(opts.root ?? process.cwd());
  const policy = opts.policy === undefined ? loadPolicy(root) : opts.policy;
  const signatures = await checkSignatures({ root, dir: opts.dir, policy, verify: opts.verify });
  const rendered = await renderCheck(root, policy, opts.policySource, opts.render);
  return verifyAttestations({ root, dir: opts.dir, require: opts.require, policy, signatures, policySource: opts.policySource, ...rendered });
}

/** Most time the renderer check may take in all, across files, before the rest are refused. */
const RENDER_BUDGET_MS = 60_000;

/** The renderer from the environment: GitHub Actions with SLIPMARK_GITHUB_TOKEN or GITHUB_TOKEN set. */
function rendererFromEnv(): RenderFn | null {
  const token = process.env.SLIPMARK_GITHUB_TOKEN || process.env.GITHUB_TOKEN;
  if (process.env.GITHUB_ACTIONS !== "true" || !token) return null;
  return githubRenderer({ token, repo: process.env.GITHUB_REPOSITORY, apiUrl: process.env.GITHUB_API_URL });
}

/**
 * Ask GitHub to render each changed agent context file that passed the
 * allow-list, and compare. Files the allow-list refuses are refused already.
 */
async function renderCheck(
  root: string,
  policy: Policy | null,
  source: PolicySource | undefined,
  given: RenderFn | null | undefined,
): Promise<{ renderFindings?: Map<string, HiddenFinding[]>; renderNotes?: string[] }> {
  const ctx = policy?.context;
  if (!ctx || ctx.hiddenContent === "allow" || ctx.githubRender === "off") return {};
  const base = (source?.source === "base" ? source.ref : undefined) ?? policy?.coverage?.base;
  if (!base) return {}; // verify says context changes weren't checked
  let changed: string[];
  try {
    const context = new Set(scanContext(root, ctx.files ?? DEFAULT_CONTEXT_FILES).files);
    changed = changedFiles(root, base, "agent context").map(toPosix).filter((p) => context.has(p) && isMarkdownish(p));
  } catch {
    return {}; // verify reports the same problem
  }
  if (!changed.length) return {};
  const findings = new Map<string, HiddenFinding[]>();
  const started = Date.now();
  const render = given === undefined ? rendererFromEnv() : given;
  if (!render) {
    // Inside GitHub Actions the check is expected to run: without a token it refuses, rather than quietly skipping.
    if (ctx.githubRender === "require" || (given === undefined && process.env.GITHUB_ACTIONS === "true")) {
      for (const path of changed) {
        findings.set(path, [{ path, line: 1, kind: "not_plain_markdown", detail: "GitHub's renderer check couldn't run: it needs GitHub Actions and a token (the Slipmark Action passes one; set SLIPMARK_GITHUB_TOKEN when running the CLI)" }]);
      }
      return { renderFindings: findings };
    }
    return { renderNotes: ["GitHub's renderer check didn't run: it needs GitHub Actions and a token (the Slipmark Action passes one). The allow-list still applied."] };
  }
  for (const path of changed) {
    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true }).decode(readFileSync(join(root, path)));
    } catch {
      continue; // refused by the scan as not UTF-8
    }
    if (Buffer.byteLength(text, "utf8") > MAX_SCAN) continue; // refused by the scan as too large
    if (Date.now() - started > RENDER_BUDGET_MS) {
      findings.set(path, [{ path, line: 1, kind: "not_plain_markdown", detail: "ran out of time checking against GitHub's renderer" }]);
      continue;
    }
    const f = await compareWithGitHub(path, text, render);
    if (f.length) findings.set(path, f);
  }
  return { renderFindings: findings, renderNotes: [`Checked ${changed.length} changed agent context file(s) against GitHub's renderer.`] };
}
