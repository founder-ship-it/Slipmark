/**
 * The gate for a combined in-toto Bundle: one JSON Lines file holding Sigstore
 * bundles from different tools. `.slipmark/policy.json` → `bundle.require` names
 * the predicate types that must be there and who may sign each. Every entry of a
 * required type must check out, and each required type needs at least one.
 *
 * The Bundle itself isn't signed as a whole, so each entry is judged on its own:
 * its Sigstore signature, its signer, and what it claims against this checkout.
 * Entries of other types (SLSA provenance, say) are listed and ignored.
 *
 * Built-in checks exist for two predicate types:
 *  - Slipmark verdicts: the full verify pipeline, as for an attestation file.
 *  - Codapult Guard verification receipts (predicate v1): the consumer checks in
 *    Guard's spec, the scope fingerprint recomputed, the source bound to the
 *    expected repository and pull request revisions, and every file Guard
 *    hashed checked against this checkout.
 * A required type with no built-in check is refused: a signature alone says who
 * made a claim, not that the claim holds here.
 */
import { createHash } from "node:crypto";
import { existsSync, lstatSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve, sep } from "node:path";
import {
  resolveSubject,
  sha256File,
  verifyAttestations,
  type BundlePolicy,
  type CheckResult,
  type Policy,
  type PolicySource,
} from "./attestation.js";
import {
  GITHUB_ACTIONS_ISSUER,
  INTOTO_PAYLOAD_TYPE,
  PREDICATE_TYPE,
  STATEMENT_TYPE,
  bundleIdentity,
  checkSignature,
  identityMatches,
  sigstoreVerify,
  type SigstoreBundle,
  type Verify,
} from "./signing.js";

export const GUARD_PREDICATE_TYPE = "https://github.com/codapult/codapult-guard/blob/main/docs/attestations/guard-verification-v1.md";
export const SLIPMARK_PREDICATE_TYPE = PREDICATE_TYPE;

/** Guard v1 stages, from Guard's spec. A required stage outside this list is unsupported. */
const GUARD_STAGES = new Set(["runtime", "project-checks", "adapters", "architecture-policy", "policy-surface", "ci-integrity", "verification-scope"]);

/** What the Guard entry must be bound to. From the pull request event in GitHub Actions, or flags. */
export interface ExpectedSource {
  repository?: string;
  head?: string;
  base?: string;
}

export type EntryStatus = "verified" | "refused" | "ignored" | "malformed";

export interface BundleEntryResult {
  /** 1-based line number in the Bundle file. */
  line: number;
  status: EntryStatus;
  predicateType?: string;
  signer?: string;
  /** Why it was refused, or what it verified. */
  message: string;
  /** For Slipmark verdicts: the per-subject results from the verify pipeline. */
  details?: CheckResult[];
}

export interface BundleReport {
  ok: boolean;
  entries: BundleEntryResult[];
  /** Required predicate types with no verified entry. */
  missing: string[];
  policy?: PolicySource;
  notes: string[];
}

const isRecord = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);
const isSha1 = (v: unknown): v is string => typeof v === "string" && /^[a-f0-9]{40}$/.test(v);
const isSha256 = (v: unknown): v is string => typeof v === "string" && /^[a-f0-9]{64}$/.test(v);

/** The scope fingerprint as Guard's spec defines it: compact JSON in a fixed property order, UTF-8, SHA-256. */
export function guardFingerprint(receipt: Record<string, unknown>): string {
  const scope = receipt.verificationScope as Record<string, unknown>;
  const source = scope.source as Record<string, unknown>;
  const policy = receipt.policy as Record<string, unknown>;
  const tool = receipt.tool as Record<string, unknown>;
  const files = (scope.files as Record<string, unknown>[]).map((f) =>
    f.status === "present" ? { path: f.path, status: f.status, sha256: f.sha256 } : { path: f.path, status: f.status },
  );
  const input = {
    algorithm: "sha256",
    policyFingerprint: policy.fingerprint,
    tool: { name: tool.name, version: tool.version },
    files,
    source: {
      repository: source.repository ?? null,
      commit: source.commit ?? null,
      headSha: source.headSha ?? null,
      baseSha: source.baseSha ?? null,
      baseCommit: source.baseCommit ?? null,
    },
  };
  return createHash("sha256").update(JSON.stringify(input), "utf8").digest("hex");
}

/**
 * Check a Guard Statement against Guard's spec and this checkout. Returns the
 * problems found, in plain language; empty means it holds. The signature and
 * signer are checked separately.
 */
export function checkGuardStatement(statement: Record<string, unknown>, root: string, expected: ExpectedSource): string[] {
  const receipt = isRecord(statement.predicate) ? statement.predicate.receipt : undefined;
  if (!isRecord(receipt) || receipt.version !== 1 || receipt.kind !== "verification-receipt") return ["not a Guard v1 verification receipt"];
  if (receipt.outcome !== "pass") return [`Guard's outcome was ${JSON.stringify(receipt.outcome)}, not pass`];
  if (typeof receipt.runId !== "string" || receipt.runId.length === 0) return ["the receipt names no Guard run"];
  const req = receipt.requiredStages;
  const stages = receipt.stages;
  if (
    !Array.isArray(req) ||
    !req.includes("verification-scope") ||
    new Set(req).size !== req.length ||
    !req.every((s) => typeof s === "string" && GUARD_STAGES.has(s)) ||
    !isRecord(stages) ||
    !req.every((s) => stages[s as string] === "ok") ||
    !Array.isArray(receipt.incompleteStages) ||
    receipt.incompleteStages.length > 0
  ) {
    return ["Guard's required stages didn't all pass, or include stages this version doesn't know"];
  }
  const scope = receipt.verificationScope;
  const policy = receipt.policy;
  const tool = receipt.tool;
  if (
    !isRecord(scope) ||
    scope.algorithm !== "sha256" ||
    scope.complete !== true ||
    scope.stable !== true ||
    !isSha256(scope.fingerprint) ||
    !Array.isArray(scope.files) ||
    !isRecord(scope.source) ||
    !isSha1(scope.source.commit) ||
    !isRecord(policy) ||
    !isSha256(policy.fingerprint) ||
    !isRecord(tool) ||
    tool.name !== "@codapult/guard" ||
    typeof tool.version !== "string" ||
    tool.version.length === 0
  ) {
    return ["Guard's verification scope is incomplete, unstable or malformed"];
  }

  // Files: valid, uniquely sorted, and the subjects are exactly the aggregate then one per present file, in order.
  const expectedSubjects: { name: string; sha256: string }[] = [{ name: "codapult-guard:verification-context", sha256: scope.fingerprint }];
  let prev: string | undefined;
  for (const f of scope.files as unknown[]) {
    if (
      !isRecord(f) ||
      typeof f.path !== "string" ||
      f.path.length === 0 ||
      f.path.includes("\\") ||
      f.path.startsWith("/") ||
      /^[a-z]:\//i.test(f.path) ||
      f.path.split("/").includes("..") ||
      !(f.status === "present" ? isSha256(f.sha256) : f.status === "deleted" && f.sha256 === undefined)
    ) {
      return ["Guard's file list has an invalid path, status or hash"];
    }
    if (prev !== undefined && f.path <= prev) return ["Guard's file list isn't uniquely sorted by path"];
    prev = f.path;
    if (f.status === "present") expectedSubjects.push({ name: `file:${f.path}`, sha256: f.sha256 as string });
  }
  if (guardFingerprint(receipt) !== scope.fingerprint) return ["Guard's scope fingerprint doesn't match its policy, tool, files and source"];
  const subjects = statement.subject;
  if (
    !Array.isArray(subjects) ||
    subjects.length !== expectedSubjects.length ||
    !expectedSubjects.every((e, i) => {
      const s = subjects[i];
      return isRecord(s) && s.name === e.name && isRecord(s.digest) && s.digest.sha256 === e.sha256;
    })
  ) {
    return ["the Statement's subjects don't match Guard's verification scope"];
  }

  // Bound to the expected revisions. The receipt's own subject must agree with its scope.
  const src = scope.source;
  const subj = receipt.subject;
  const problems: string[] = [];
  if (expected.repository === undefined) {
    problems.push("no expected repository was given, so the receipt can't be bound to this one");
  } else if (typeof src.repository !== "string" || src.repository.toLowerCase() !== expected.repository.toLowerCase()) {
    problems.push(`Guard checked ${String(src.repository)}, not ${expected.repository}`);
  }
  if (expected.head === undefined || expected.base === undefined) {
    problems.push("the pull request head and base weren't given, so the receipt can't be bound to them");
  }
  if (expected.head !== undefined && (src.commit !== expected.head || src.headSha !== expected.head)) {
    problems.push(`Guard checked commit ${String(src.commit).slice(0, 12)}, not the pull request head ${expected.head.slice(0, 12)}`);
  }
  if (expected.base !== undefined && (src.baseSha !== expected.base || src.baseCommit !== expected.base)) {
    problems.push(`Guard's base was ${String(src.baseSha).slice(0, 12)}, not ${expected.base.slice(0, 12)}`);
  }
  if (
    !isRecord(subj) ||
    (subj.repository ?? null) !== (src.repository ?? null) ||
    subj.commit !== src.commit ||
    (subj.headSha ?? null) !== (src.headSha ?? null) ||
    (subj.baseSha ?? null) !== (src.baseSha ?? null) ||
    (subj.baseCommit ?? null) !== (src.baseCommit ?? null)
  ) {
    problems.push("the receipt's subject and its verification scope name different revisions");
  }

  // Content, not names: every file Guard hashed must be the same here, and every file it saw deleted must be absent.
  let changed = 0;
  const examples: string[] = [];
  for (const f of scope.files as Record<string, unknown>[]) {
    const abs = resolveSubject(root, f.path as string);
    let ok: boolean;
    if (!abs) ok = false;
    else if (f.status === "deleted") ok = !existsSync(abs);
    else ok = existsSync(abs) && lstatSync(abs).isFile() && sha256File(abs) === f.sha256;
    if (!ok) {
      changed++;
      if (examples.length < 3) examples.push(f.path as string);
    }
  }
  if (changed) problems.push(`${changed} file(s) differ from what Guard checked, for example ${examples.join(", ")}`);
  return problems;
}

/** Where the pull request revisions come from in GitHub Actions: the event payload. */
export function expectedFromEnv(env: NodeJS.ProcessEnv, readEvent: (path: string) => string): ExpectedSource {
  const out: ExpectedSource = {};
  if (env.GITHUB_REPOSITORY) out.repository = env.GITHUB_REPOSITORY;
  if (env.GITHUB_EVENT_PATH) {
    try {
      const ev = JSON.parse(readEvent(env.GITHUB_EVENT_PATH)) as { pull_request?: { head?: { sha?: unknown }; base?: { sha?: unknown } } };
      if (isSha1(ev.pull_request?.head?.sha)) out.head = ev.pull_request.head.sha;
      if (isSha1(ev.pull_request?.base?.sha)) out.base = ev.pull_request.base.sha;
    } catch {
      // no readable event: the caller passes --head and --base, or the Guard check refuses
    }
  }
  return out;
}

/**
 * Check every line of a Bundle against the policy's `bundle` section.
 * Throws for problems with the run itself (no bundle policy, Sigstore unreachable),
 * which the CLI reports as "could not run", never as a pass.
 */
export async function verifyBundle(opts: {
  root?: string;
  text: string;
  policy: Policy;
  policySource?: PolicySource;
  expected?: ExpectedSource;
  verify?: Verify;
}): Promise<BundleReport> {
  const root = resolve(opts.root ?? process.cwd());
  const bp: BundlePolicy | undefined = opts.policy.bundle;
  if (!bp?.require?.length) throw new Error('the policy has no "bundle" section, so nothing says which entries are required. See docs/attestation.md, "Checking a combined Bundle".');
  const issuer = bp.issuer ?? GITHUB_ACTIONS_ISSUER;
  const verify = opts.verify ?? sigstoreVerify;
  const expected = opts.expected ?? {};
  const required = new Map(bp.require.map((r) => [r.predicateType, r.signers]));
  const notes: string[] = [];
  const entries: BundleEntryResult[] = [];

  if (required.has(GUARD_PREDICATE_TYPE) && (expected.repository === undefined || expected.head === undefined || expected.base === undefined)) {
    throw new Error("a Guard entry is required, but the repository, pull request head and base aren't all known. In GitHub Actions they come from the environment and the pull_request event; otherwise pass --repo <owner/name> --head <sha> --base <sha>.");
  }

  const lines = opts.text.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i]!.trim();
    if (!raw) continue;
    const line = i + 1;
    let bundle: unknown;
    try {
      bundle = JSON.parse(raw);
    } catch {
      entries.push({ line, status: "malformed", message: "not valid JSON" });
      continue;
    }
    const env = isRecord(bundle) ? bundle.dsseEnvelope : undefined;
    if (!isRecord(env) || typeof env.payload !== "string" || !Array.isArray(env.signatures)) {
      entries.push({ line, status: "malformed", message: "not a Sigstore bundle with a DSSE envelope. Use the .sigstore.jsonl form: a bare envelope names no signer." });
      continue;
    }
    if (env.payloadType !== INTOTO_PAYLOAD_TYPE) {
      entries.push({ line, status: "malformed", message: `payload type is ${String(env.payloadType)}, not an in-toto Statement` });
      continue;
    }
    let statement: unknown;
    try {
      statement = JSON.parse(Buffer.from(env.payload, "base64").toString("utf8"));
    } catch {
      entries.push({ line, status: "malformed", message: "the payload isn't JSON" });
      continue;
    }
    if (!isRecord(statement) || statement._type !== STATEMENT_TYPE || typeof statement.predicateType !== "string") {
      entries.push({ line, status: "malformed", message: `not an in-toto Statement v1` });
      continue;
    }
    const predicateType = statement.predicateType;
    const signers = required.get(predicateType);
    if (!signers) {
      entries.push({ line, status: "ignored", predicateType, message: "not a required type, so not checked" });
      continue;
    }

    if (predicateType === SLIPMARK_PREDICATE_TYPE) {
      entries.push(await checkSlipmarkEntry({ root, line, bundle: bundle as SigstoreBundle, statement, signers, issuer, verify, policy: opts.policy, policySource: opts.policySource }));
      continue;
    }

    // Any other required type: the signature and signer first.
    const sig = await checkSigner(bundle as SigstoreBundle, signers, issuer, verify);
    if (!sig.ok) {
      entries.push({ line, status: "refused", predicateType, signer: sig.signer, message: sig.message });
      continue;
    }
    if (predicateType === GUARD_PREDICATE_TYPE) {
      const problems = checkGuardStatement(statement, root, expected);
      entries.push(
        problems.length
          ? { line, status: "refused", predicateType, signer: sig.signer, message: `Guard: ${problems.join("; ")}` }
          : { line, status: "verified", predicateType, signer: sig.signer, message: "Guard passed for this repository, these revisions and these exact files" },
      );
      continue;
    }
    entries.push({ line, status: "refused", predicateType, signer: sig.signer, message: "signed by a trusted signer, but Slipmark has no check for this predicate type, so its claim can't be tested here" });
  }

  const verifiedTypes = new Set(entries.filter((e) => e.status === "verified").map((e) => e.predicateType));
  const missing = [...required.keys()].filter((t) => !verifiedTypes.has(t));
  const bad = entries.some((e) => e.status === "refused" || e.status === "malformed");
  if (!entries.length) notes.push("the Bundle is empty");
  return { ok: !bad && missing.length === 0 && entries.length > 0, entries, missing, policy: opts.policySource, notes };
}

/** Verify the Sigstore bundle and that its signer is one of `signers`. */
async function checkSigner(bundle: SigstoreBundle, signers: string[], issuer: string, verify: Verify): Promise<{ ok: true; signer: string } | { ok: false; signer?: string; message: string }> {
  try {
    await verify(bundle, issuer);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (/TUF|fetch|ENOTFOUND|ECONNREFUSED|ETIMEDOUT|EAI_AGAIN|network|socket/i.test(`${(e as { name?: string })?.name ?? ""} ${msg}`)) {
      throw new Error(`couldn't reach Sigstore to check signatures: ${msg}`);
    }
    return { ok: false, message: `signature didn't verify: ${msg}` };
  }
  const identity = bundleIdentity(bundle);
  if (!identity) return { ok: false, message: "signing certificate names no identity" };
  if (!signers.some((p) => identityMatches(identity, p))) return { ok: false, signer: identity, message: `signed by ${identity}, which isn't a trusted signer for this type` };
  return { ok: true, signer: identity };
}

/**
 * A Slipmark verdict from a Bundle: rebuild the attestation from the predicate,
 * attach the bundle as its signature, and run it through the same gate as an
 * attestation file. The signature must cover exactly the Statement Slipmark
 * would make from that attestation.
 */
async function checkSlipmarkEntry(o: {
  root: string;
  line: number;
  bundle: SigstoreBundle;
  statement: Record<string, unknown>;
  signers: string[];
  issuer: string;
  verify: Verify;
  policy: Policy;
  policySource?: PolicySource;
}): Promise<BundleEntryResult> {
  const predicateType = SLIPMARK_PREDICATE_TYPE;
  if (!isRecord(o.statement.predicate)) return { line: o.line, status: "refused", predicateType, message: "the predicate isn't a Slipmark attestation" };
  const att: Record<string, unknown> = { ...o.statement.predicate, signature: { bundle: o.bundle } };
  let sig;
  try {
    sig = await checkSignature(att, { trusted: o.signers, issuer: o.issuer }, o.verify);
  } catch (e) {
    return { line: o.line, status: "refused", predicateType, message: `signature check failed: ${e instanceof Error ? e.message : String(e)}` };
  }
  if (sig.state === "unchecked") throw new Error(sig.reason);
  if (sig.state === "invalid") return { line: o.line, status: "refused", predicateType, message: sig.reason };
  if (!sig.trusted) return { line: o.line, status: "refused", predicateType, signer: sig.identity, message: `signed by ${sig.identity}, which isn't a trusted signer for this type` };

  // The verify pipeline reads attestation files, so hand it this one from a scratch folder.
  // Only this verdict is judged: the repo's require and coverage lists belong to `slipmark verify`.
  const dir = mkdtempSync(join(tmpdir(), "slipmark-bundle-"));
  try {
    const file = join(dir, `line-${o.line}.json`);
    writeFileSync(file, JSON.stringify(att));
    const key = relative(o.root, file).split(sep).join("/");
    const policy: Policy = { ...o.policy, require: undefined, coverage: undefined, signatures: { require: true, trusted: o.signers, issuer: o.issuer } };
    const report = verifyAttestations({ root: o.root, dir, policy, signatures: new Map([[key, sig]]), policySource: o.policySource });
    const fails = report.results.filter((r) => r.status !== "verified");
    if (!report.results.length) return { line: o.line, status: "refused", predicateType, signer: sig.identity, message: "the verdict covers nothing" };
    const by = typeof att.by === "string" ? att.by : "verdict";
    return fails.length
      ? { line: o.line, status: "refused", predicateType, signer: sig.identity, message: `${by}: ${fails.map((f) => f.message).join("; ")}`, details: report.results }
      : { line: o.line, status: "verified", predicateType, signer: sig.identity, message: `${by} gave "${String(att.verdict)}" for these exact files`, details: report.results };
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
