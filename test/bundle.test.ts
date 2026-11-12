import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, writeFileSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createAttestation, parsePolicy, POLICY_SCHEMA, type Policy } from "../src/attest/attestation.js";
import { INTOTO_PAYLOAD_TYPE, STATEMENT_TYPE, intotoBundleLines, sigstoreVerify, statementPayload, type SigstoreBundle } from "../src/attest/signing.js";
import { GUARD_PREDICATE_TYPE, SLIPMARK_PREDICATE_TYPE, checkGuardStatement, expectedFromEnv, guardFingerprint, verifyBundle } from "../src/attest/bundle.js";

// A self-signed certificate whose identity is WORKFLOW. Only the signature bytes in these bundles are fake.
const CERT = "MIIB3zCCAYagAwIBAgIUSPpWcekJELfhZH8iwkTATDkRd6cwCgYIKoZIzj0EAwIwFzEVMBMGA1UECgwMc2lnc3RvcmUuZGV2MB4XDTI2MTAyMzExNDgxOFoXDTM2MTAyMDExNDgxOFowFzEVMBMGA1UECgwMc2lnc3RvcmUuZGV2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEctevYiqooE/4lI3dsRVR+L1Bi08svreWTmW9UG/LKGx7owo1wFlC50vsKnt7+gh0aYjAkwTir/RN2b4VeTAWiqOBrzCBrDAdBgNVHQ4EFgQUsEyxTSpdrOqZkLAsZXrjzZATpYcwHwYDVR0jBBgwFoAUsEyxTSpdrOqZkLAsZXrjzZATpYcwDwYDVR0TAQH/BAUwAwEB/zBZBgNVHREEUjBQhk5odHRwczovL2dpdGh1Yi5jb20vYWNtZS9hcGkvLmdpdGh1Yi93b3JrZmxvd3MvYWdlbnQtcmV2aWV3LnltbEByZWZzL2hlYWRzL21haW4wCgYIKoZIzj0EAwIDRwAwRAIgeyDaMlv9QSLmSS9MhtFHYrl4LtUVV2iHlrAEb4PQDvgCIB6T2m7z3cGDui1u9scVyj2L1e0Oo6zA+JtAd1R2gIj0";
const WORKFLOW = "https://github.com/acme/api/.github/workflows/agent-review.yml@refs/heads/main";
const HEAD = "a".repeat(40);
const BASE = "b".repeat(40);
const EXPECTED = { repository: "acme/api", head: HEAD, base: BASE };
const ok = async () => undefined;
const sha = (s: string) => createHash("sha256").update(s).digest("hex");

function repo() {
  const root = mkdtempSync(join(tmpdir(), "sm-bundle-"));
  mkdirSync(join(root, "src"), { recursive: true });
  writeFileSync(join(root, "src/pay.ts"), "export const fee = 2;\n");
  writeFileSync(join(root, "src/util.ts"), "export const x = 1;\n");
  return root;
}

function wrap(statementBytes: Buffer): SigstoreBundle {
  return {
    mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
    verificationMaterial: { certificate: { rawBytes: CERT } },
    dsseEnvelope: { payload: statementBytes.toString("base64"), payloadType: INTOTO_PAYLOAD_TYPE, signatures: [{ sig: "c2ln" }] },
  };
}

/** A Guard receipt as Guard v1 makes it, over the given files, then its Statement. `edit` changes the receipt before the fingerprint is taken. */
function guardStatement(root: string, opts: { edit?: (r: any) => void; deleted?: string[]; afterFingerprint?: (st: any) => void } = {}) {
  const files: any[] = ["src/pay.ts", "src/util.ts"].map((p) => ({ path: p, status: "present", sha256: sha(readFileSync(join(root, p), "utf8")) }));
  for (const d of opts.deleted ?? []) files.push({ path: d, status: "deleted" });
  files.sort((a, b) => (a.path < b.path ? -1 : 1));
  const source = { repository: "acme/api", commit: HEAD, headSha: HEAD, baseSha: BASE, baseCommit: BASE };
  const receipt: any = {
    version: 1,
    kind: "verification-receipt",
    runId: "run-1",
    outcome: "pass",
    subject: { ...source },
    policy: { fingerprint: "e".repeat(64) },
    verificationScope: { algorithm: "sha256", complete: true, stable: true, source, files },
    requiredStages: ["architecture-policy", "verification-scope"],
    incompleteStages: [],
    stages: { "architecture-policy": "ok", "verification-scope": "ok" },
    tool: { name: "@codapult/guard", version: "0.14.0" },
  };
  opts.edit?.(receipt);
  receipt.verificationScope.fingerprint = guardFingerprint(receipt);
  const statement: any = {
    _type: STATEMENT_TYPE,
    subject: [
      { name: "codapult-guard:verification-context", digest: { sha256: receipt.verificationScope.fingerprint } },
      ...receipt.verificationScope.files.filter((f: any) => f.status === "present").map((f: any) => ({ name: `file:${f.path}`, digest: { sha256: f.sha256 } })),
    ],
    predicateType: GUARD_PREDICATE_TYPE,
    predicate: { receipt },
  };
  opts.afterFingerprint?.(statement);
  return statement;
}

const guardLine = (st: unknown) => JSON.stringify(wrap(Buffer.from(JSON.stringify(st))));

function slipmarkLine(root: string, edit?: (att: any) => void) {
  const att: any = createAttestation({ root, by: "security-reviewer", verdict: "pass", subjects: ["src/pay.ts"], now: new Date("2026-11-12T10:00:00Z") });
  edit?.(att);
  return JSON.stringify(wrap(statementPayload(att)));
}

const both = (signers = [WORKFLOW]): Policy => ({
  schema: POLICY_SCHEMA,
  bundle: { require: [{ predicateType: GUARD_PREDICATE_TYPE, signers }, { predicateType: SLIPMARK_PREDICATE_TYPE, signers }] },
});

const run = (root: string, lines: string[], policy: Policy = both(), extra: Partial<Parameters<typeof verifyBundle>[0]> = {}) =>
  verifyBundle({ root, text: lines.join("\n") + "\n", policy, expected: EXPECTED, verify: ok, ...extra });

test("bundle: a Guard receipt and a Slipmark verdict, both current and trusted, are accepted", async () => {
  const root = repo();
  const r = await run(root, [guardLine(guardStatement(root)), slipmarkLine(root)]);
  assert.equal(r.ok, true, JSON.stringify(r.entries));
  assert.deepEqual(r.entries.map((e) => e.status), ["verified", "verified"]);
  assert.equal(r.entries[0]!.signer, WORKFLOW);
});

test("bundle: each required type must be there", async () => {
  const root = repo();
  const r = await run(root, [slipmarkLine(root)]);
  assert.equal(r.ok, false);
  assert.deepEqual(r.missing, [GUARD_PREDICATE_TYPE]);
  const r2 = await run(root, [guardLine(guardStatement(root))]);
  assert.deepEqual(r2.missing, [SLIPMARK_PREDICATE_TYPE]);
});

test("bundle: a file edited after both verdicts refuses both entries", async () => {
  const root = repo();
  const lines = [guardLine(guardStatement(root)), slipmarkLine(root)];
  writeFileSync(join(root, "src/pay.ts"), "export const fee = 3;\n");
  const r = await run(root, lines);
  assert.equal(r.ok, false);
  assert.deepEqual(r.entries.map((e) => e.status), ["refused", "refused"]);
  assert.match(r.entries[0]!.message, /differ from what Guard checked.*src\/pay\.ts/);
});

test("bundle: a file outside the Slipmark verdict but inside Guard's scope still refuses the Guard entry", async () => {
  const root = repo();
  const lines = [guardLine(guardStatement(root)), slipmarkLine(root)];
  writeFileSync(join(root, "src/util.ts"), "export const x = 2;\n");
  const r = await run(root, lines);
  assert.deepEqual(r.entries.map((e) => e.status), ["refused", "verified"]);
});

test("bundle: Guard must be bound to the expected repository, head and base", async () => {
  const root = repo();
  const lines = [guardLine(guardStatement(root)), slipmarkLine(root)];
  for (const expected of [{ ...EXPECTED, head: "c".repeat(40) }, { ...EXPECTED, base: "c".repeat(40) }, { ...EXPECTED, repository: "evil/api" }]) {
    const r = await run(root, lines, both(), { expected });
    assert.equal(r.entries[0]!.status, "refused", JSON.stringify(expected));
  }
});

test("bundle: a Guard entry is required but the revisions aren't known, so the gate can't run", async () => {
  const root = repo();
  for (const expected of [{ repository: "acme/api" }, { head: HEAD, base: BASE }, { repository: "acme/api", head: HEAD }]) {
    await assert.rejects(run(root, [slipmarkLine(root)], both(), { expected }), /aren't all known/, JSON.stringify(expected));
  }
});

test("bundle: Guard's own conditions: pass, all required stages ok, complete and stable scope", async () => {
  const root = repo();
  const edits: ((r: any) => void)[] = [
    (r) => { r.outcome = "fail"; },
    (r) => { r.stages["architecture-policy"] = "failed"; },
    (r) => { r.incompleteStages = ["runtime"]; },
    (r) => { r.requiredStages = ["architecture-policy"]; },
    (r) => { r.requiredStages = ["verification-scope", "made-up-stage"]; r.stages["made-up-stage"] = "ok"; },
    (r) => { r.verificationScope.stable = false; },
    (r) => { r.verificationScope.complete = false; },
    (r) => { r.tool.name = "not-guard"; },
    (r) => { delete r.runId; },
    (r) => { r.runId = ""; },
  ];
  for (const edit of edits) {
    const r = await run(root, [guardLine(guardStatement(root, { edit })), slipmarkLine(root)]);
    assert.equal(r.entries[0]!.status, "refused", edit.toString());
  }
});

test("bundle: Guard's fingerprint is recomputed, not trusted", async () => {
  const root = repo();
  const st = guardStatement(root, { afterFingerprint: (s) => { s.predicate.receipt.policy.fingerprint = "f".repeat(64); } });
  const r = await run(root, [guardLine(st), slipmarkLine(root)]);
  assert.equal(r.entries[0]!.status, "refused");
  assert.match(r.entries[0]!.message, /fingerprint/);
});

test("bundle: Guard's subjects must be exactly the aggregate, then one per present file, in order", async () => {
  const root = repo();
  const variants: ((s: any) => void)[] = [
    (s) => { s.subject.reverse(); },
    (s) => { s.subject.pop(); },
    (s) => { s.subject.push({ name: "file:src/extra.ts", digest: { sha256: "0".repeat(64) } }); },
    (s) => { s.subject[1].digest.sha256 = "0".repeat(64); },
  ];
  for (const v of variants) {
    const r = await run(root, [guardLine(guardStatement(root, { afterFingerprint: v })), slipmarkLine(root)]);
    assert.equal(r.entries[0]!.status, "refused", v.toString());
  }
});

test("bundle: a file Guard saw as deleted must be absent", async () => {
  const root = repo();
  const lines = [guardLine(guardStatement(root, { deleted: ["src/old.ts"] })), slipmarkLine(root)];
  assert.equal((await run(root, lines)).ok, true);
  writeFileSync(join(root, "src/old.ts"), "back again\n");
  assert.equal((await run(root, lines)).entries[0]!.status, "refused");
});

test("bundle: Guard paths that escape the repo are refused", async () => {
  const root = repo();
  const st = guardStatement(root, { edit: (r) => { r.verificationScope.files.unshift({ path: "../outside.ts", status: "deleted" }); } });
  assert.equal((await run(root, [guardLine(st), slipmarkLine(root)])).entries[0]!.status, "refused");
});

test("bundle: signers must be on the list for that type, and signatures must verify", async () => {
  const root = repo();
  const lines = [guardLine(guardStatement(root)), slipmarkLine(root)];
  const r = await run(root, lines, both(["https://github.com/someone/else/.github/workflows/x.yml@refs/heads/main"]));
  assert.deepEqual(r.entries.map((e) => e.status), ["refused", "refused"]);
  const bad = await run(root, lines, both(), { verify: async () => { throw new Error("signature verification failed"); } });
  assert.deepEqual(bad.entries.map((e) => e.status), ["refused", "refused"]);
});

test("bundle: Sigstore being unreachable stops the run, never passes it", async () => {
  const root = repo();
  const offline = async () => { const e = new Error("getaddrinfo ENOTFOUND tuf-repo-cdn.sigstore.dev"); e.name = "TUFError"; throw e; };
  await assert.rejects(run(root, [guardLine(guardStatement(root)), slipmarkLine(root)], both(), { verify: offline }), /couldn't reach Sigstore/);
});

test("bundle: a Slipmark entry must be the Statement Slipmark would make from its own predicate", async () => {
  const root = repo();
  const att: any = createAttestation({ root, by: "r", verdict: "pass", subjects: ["src/pay.ts"], now: new Date("2026-11-12T10:00:00Z") });
  const st = JSON.parse(statementPayload(att).toString("utf8"));
  st.predicate.verdict = "fail";
  st.subject[0].digest.sha256 = "0".repeat(64);
  const r = await run(root, [guardLine(guardStatement(root)), JSON.stringify(wrap(Buffer.from(JSON.stringify(st))))]);
  assert.equal(r.entries[1]!.status, "refused");
});

test("bundle: a failing Slipmark verdict is refused", async () => {
  const root = repo();
  const r = await run(root, [guardLine(guardStatement(root)), slipmarkLine(root, (a) => { a.verdict = "fail"; })]);
  assert.equal(r.entries[1]!.status, "refused");
});

test("bundle: malformed lines and bare envelopes refuse the gate; other types are ignored", async () => {
  const root = repo();
  const good = [guardLine(guardStatement(root)), slipmarkLine(root)];
  const slsa = JSON.stringify(wrap(Buffer.from(JSON.stringify({ _type: STATEMENT_TYPE, subject: [], predicateType: "https://slsa.dev/provenance/v1", predicate: {} }))));
  const withSlsa = await run(root, [...good, slsa]);
  assert.equal(withSlsa.ok, true);
  assert.equal(withSlsa.entries[2]!.status, "ignored");
  const bare = JSON.stringify(wrap(statementPayload(createAttestation({ root, by: "r", verdict: "pass", subjects: ["src/pay.ts"] }))).dsseEnvelope);
  for (const junk of ["not json", "null", "[]", "{}", bare, JSON.stringify({ dsseEnvelope: { payload: 5, payloadType: INTOTO_PAYLOAD_TYPE, signatures: [] } })]) {
    const r = await run(root, [...good, junk]);
    assert.equal(r.ok, false, junk.slice(0, 40));
    assert.equal(r.entries[2]!.status, "malformed");
  }
});

test("bundle: a required type Slipmark has no check for is refused, even when signed by a trusted signer", async () => {
  const root = repo();
  const other = "https://example.com/attestation/v1";
  const line = JSON.stringify(wrap(Buffer.from(JSON.stringify({ _type: STATEMENT_TYPE, subject: [], predicateType: other, predicate: {} }))));
  const r = await run(root, [line], { schema: POLICY_SCHEMA, bundle: { require: [{ predicateType: other, signers: [WORKFLOW] }] } });
  assert.equal(r.ok, false);
  assert.match(r.entries[0]!.message, /no check for this predicate type/);
});

test("bundle: an empty Bundle is refused, and a policy without a bundle section can't run", async () => {
  const root = repo();
  assert.equal((await verifyBundle({ root, text: "\n", policy: both(), expected: EXPECTED, verify: ok })).ok, false);
  await assert.rejects(verifyBundle({ root, text: "", policy: { schema: POLICY_SCHEMA }, expected: EXPECTED, verify: ok }), /no "bundle" section/);
});

test("policy: the bundle section is checked when the policy is read", () => {
  const p = (bundle: unknown) => JSON.stringify({ schema: POLICY_SCHEMA, bundle });
  assert.equal(parsePolicy(p({ require: [{ predicateType: GUARD_PREDICATE_TYPE, signers: [WORKFLOW] }] })).bundle?.require.length, 1);
  for (const bad of [
    [],
    { require: [] },
    { require: [{ predicateType: "not a uri", signers: [WORKFLOW] }] },
    { require: [{ predicateType: GUARD_PREDICATE_TYPE, signers: [] }] },
    { require: [{ predicateType: GUARD_PREDICATE_TYPE, signers: [WORKFLOW] }, { predicateType: GUARD_PREDICATE_TYPE, signers: [WORKFLOW] }] },
    { require: [{ predicateType: GUARD_PREDICATE_TYPE, signers: [WORKFLOW] }], issuer: "http://insecure" },
  ]) {
    assert.throws(() => parsePolicy(p(bad)), Error, JSON.stringify(bad));
  }
});

test("Guard's fingerprint matches the test vector in Guard's spec", () => {
  const receipt = {
    policy: { fingerprint: "a".repeat(64) },
    tool: { name: "@codapult/guard", version: "1.2.3" },
    verificationScope: {
      files: [{ path: "src/deleted.ts", status: "deleted" }, { path: "src/main.ts", status: "present", sha256: "c".repeat(64) }],
      source: { repository: "example/project", commit: "1".repeat(40), headSha: null, baseSha: null, baseCommit: null },
    },
  };
  assert.equal(guardFingerprint(receipt), "cfce79d9ad299eb4f24139bcaaac30a606a7bb672d3a026e14722bf11ce0fced");
});

const GUARD_FIXTURE = new URL("../../test/fixtures/guard/guard-verification.sigstore.jsonl", import.meta.url);

test("Guard's real signed example reads exactly as its spec says: only the file contents differ here", () => {
  const first = JSON.parse(readFileSync(GUARD_FIXTURE, "utf8").split("\n")[0]!);
  const statement = JSON.parse(Buffer.from(first.dsseEnvelope.payload, "base64").toString("utf8"));
  const src = statement.predicate.receipt.verificationScope.source;
  const empty = mkdtempSync(join(tmpdir(), "sm-guard-real-"));
  try {
    const problems = checkGuardStatement(statement, empty, { repository: src.repository, head: src.headSha, base: src.baseSha });
    // Everything up to the content check holds; this checkout just isn't js-toolkit/changesets-guard-validate.
    assert.equal(problems.length, 1, problems.join(" | "));
    assert.match(problems[0]!, /^344 file\(s\) differ from what Guard checked/);
  } finally {
    rmSync(empty, { recursive: true, force: true });
  }
});

test("Guard's real signature verifies through Sigstore", async (t) => {
  const first = JSON.parse(readFileSync(GUARD_FIXTURE, "utf8").split("\n")[0]!);
  try {
    await sigstoreVerify(first, "https://token.actions.githubusercontent.com");
  } catch (e) {
    const msg = `${(e as Error).name} ${(e as Error).message}`;
    if (/TUF|fetch|ENOTFOUND|ECONNREFUSED|ETIMEDOUT|EAI_AGAIN|network|socket/i.test(msg)) return t.skip("Sigstore unreachable from here");
    throw e;
  }
});

test("pull request revisions come from the GitHub event", () => {
  const ev = JSON.stringify({ pull_request: { head: { sha: HEAD }, base: { sha: BASE } } });
  assert.deepEqual(expectedFromEnv({ GITHUB_REPOSITORY: "acme/api", GITHUB_EVENT_PATH: "/e" }, () => ev), EXPECTED);
  assert.deepEqual(expectedFromEnv({ GITHUB_EVENT_PATH: "/e" }, () => "not json"), {});
  assert.deepEqual(expectedFromEnv({}, () => ev), {});
});

test("export: --format sigstore writes the full bundle, so the signer survives", () => {
  const root = repo();
  const att: any = createAttestation({ root, by: "r", verdict: "pass", subjects: ["src/pay.ts"] });
  att.signature = { bundle: wrap(statementPayload(att)) };
  const { lines } = intotoBundleLines([{ file: "a.json", att }], "sigstore");
  assert.deepEqual(JSON.parse(lines[0]!), att.signature.bundle);
  const dsse = intotoBundleLines([{ file: "a.json", att }]);
  assert.equal(JSON.parse(dsse.lines[0]!).verificationMaterial, undefined);
});

test("bundle: Guard's repository must be present and match, even when the caller forgot to say which", async () => {
  const root = repo();
  const missing = guardStatement(root, { edit: (r) => { delete r.verificationScope.source.repository; delete r.subject.repository; } });
  assert.equal((await run(root, [guardLine(missing), slipmarkLine(root)])).entries[0]!.status, "refused");
  const fork = guardStatement(root, { edit: (r) => { r.verificationScope.source.repository = "evil/fork"; r.subject.repository = "evil/fork"; } });
  assert.equal((await run(root, [guardLine(fork), slipmarkLine(root)])).entries[0]!.status, "refused");
  // checkGuardStatement on its own refuses rather than skipping the binding.
  const st = guardStatement(root);
  assert.match(checkGuardStatement(st, root, { head: HEAD, base: BASE }).join(" "), /no expected repository/);
  assert.match(checkGuardStatement(st, root, { repository: "acme/api" }).join(" "), /head and base weren't given/);
});
