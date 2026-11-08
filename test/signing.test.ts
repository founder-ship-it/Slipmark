import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createAttestation, writeAttestation, verifyAttestations, verifyWithSignatures, loadPolicy, POLICY_SCHEMA, type Attestation, type Policy } from "../src/attest/attestation.js";
import { canonicalJson, signedPayload, identityMatches, bundleIdentity, checkSignature, PAYLOAD_TYPE, INTOTO_PAYLOAD_TYPE, STATEMENT_TYPE, PREDICATE_TYPE, toStatement, statementPayload, intotoBundleLines, type SigstoreBundle } from "../src/attest/signing.js";

// A self-signed test certificate whose identity is a GitHub Actions workflow, like a Fulcio one.
const CERT = "MIIB3zCCAYagAwIBAgIUSPpWcekJELfhZH8iwkTATDkRd6cwCgYIKoZIzj0EAwIwFzEVMBMGA1UECgwMc2lnc3RvcmUuZGV2MB4XDTI2MTAyMzExNDgxOFoXDTM2MTAyMDExNDgxOFowFzEVMBMGA1UECgwMc2lnc3RvcmUuZGV2MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEctevYiqooE/4lI3dsRVR+L1Bi08svreWTmW9UG/LKGx7owo1wFlC50vsKnt7+gh0aYjAkwTir/RN2b4VeTAWiqOBrzCBrDAdBgNVHQ4EFgQUsEyxTSpdrOqZkLAsZXrjzZATpYcwHwYDVR0jBBgwFoAUsEyxTSpdrOqZkLAsZXrjzZATpYcwDwYDVR0TAQH/BAUwAwEB/zBZBgNVHREEUjBQhk5odHRwczovL2dpdGh1Yi5jb20vYWNtZS9hcGkvLmdpdGh1Yi93b3JrZmxvd3MvYWdlbnQtcmV2aWV3LnltbEByZWZzL2hlYWRzL21haW4wCgYIKoZIzj0EAwIDRwAwRAIgeyDaMlv9QSLmSS9MhtFHYrl4LtUVV2iHlrAEb4PQDvgCIB6T2m7z3cGDui1u9scVyj2L1e0Oo6zA+JtAd1R2gIj0";
const WORKFLOW = "https://github.com/acme/api/.github/workflows/agent-review.yml@refs/heads/main";
const DIR = ".slipmark/attestations";
const ok = async () => undefined;
const bad = async () => { throw new Error("signature verification failed: bad signature"); };
const offline = async () => { const e = new Error("getaddrinfo ENOTFOUND tuf-repo-cdn.sigstore.dev"); e.name = "TUFError"; throw e; };

function repo() {
  const root = mkdtempSync(join(tmpdir(), "sm-sign-"));
  mkdirSync(join(root, "src"), { recursive: true });
  writeFileSync(join(root, "src/pay.ts"), "export const fee = 2;\n");
  return root;
}

/** Sign the way sigstore.attest does: a DSSE envelope over the canonical attestation. Only the signature bytes are fake. */
function fakeSign(att: Attestation, payload = signedPayload(att)): Attestation {
  const bundle: SigstoreBundle = {
    mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
    verificationMaterial: { certificate: { rawBytes: CERT } },
    dsseEnvelope: { payload: payload.toString("base64"), payloadType: PAYLOAD_TYPE, signatures: [{ sig: "c2ln" }] },
  };
  return { ...att, signature: { bundle } };
}

function attest(root: string, signed: boolean, file = "security-reviewer.json") {
  let att = createAttestation({ root, by: "security-reviewer", verdict: "pass", subjects: ["src/pay.ts"], now: new Date("2026-10-23T10:00:00Z") });
  if (signed) att = fakeSign(att);
  writeAttestation(join(root, DIR, file), att);
  return att;
}

const policy = (sig: Policy["signatures"]): Policy => ({ schema: POLICY_SCHEMA, signatures: sig });

test("canonical JSON sorts keys at every level and drops undefined", () => {
  assert.equal(canonicalJson({ b: 1, a: { d: [3, { y: 1, x: 2 }], c: undefined } }), '{"a":{"d":[3,{"x":2,"y":1}]},"b":1}');
});

test("the signed payload leaves out the signature itself", () => {
  const a = { schema: "x", by: "a", signature: { bundle: {} } };
  assert.equal(signedPayload(a).toString(), '{"by":"a","schema":"x"}');
});

test("signer patterns: * matches anything, everything else is literal", () => {
  assert.ok(identityMatches(WORKFLOW, WORKFLOW));
  assert.ok(identityMatches(WORKFLOW, "https://github.com/acme/*/.github/workflows/agent-review.yml@refs/heads/main"));
  assert.ok(!identityMatches(WORKFLOW.replace("main", "evil"), "https://github.com/acme/api/.github/workflows/agent-review.yml@refs/heads/main"));
  assert.ok(!identityMatches("https://github.com/acmeXapi", "https://github.com/acme.api"));
});

test("reads the workflow identity from the signing certificate", () => {
  assert.equal(bundleIdentity({ verificationMaterial: { certificate: { rawBytes: CERT } } }), WORKFLOW);
});

test("a valid signature names its signer, trusted or not", async () => {
  const root = repo();
  const att = attest(root, true);
  assert.deepEqual(await checkSignature(att as unknown as Record<string, unknown>, { trusted: [WORKFLOW] }, ok), { state: "valid", identity: WORKFLOW, issuer: "https://token.actions.githubusercontent.com", trusted: true });
  const other = await checkSignature(att as unknown as Record<string, unknown>, { trusted: ["https://github.com/acme/api/.github/workflows/other.yml@refs/heads/main"] }, ok);
  assert.equal(other.state === "valid" && other.trusted, false);
});

test("editing a signed attestation breaks the signature", async () => {
  const root = repo();
  const att = attest(root, true);
  const tampered = { ...att, verdict: "pass", note: "added after signing" };
  const r = await checkSignature(tampered as unknown as Record<string, unknown>, undefined, ok);
  assert.equal(r.state, "invalid");
});

test("a signature Sigstore rejects is invalid; an unreachable Sigstore is unchecked", async () => {
  const root = repo();
  const att = attest(root, true) as unknown as Record<string, unknown>;
  assert.equal((await checkSignature(att, undefined, bad)).state, "invalid");
  assert.equal((await checkSignature(att, undefined, offline)).state, "unchecked");
});

test("without a signature policy, unsigned verdicts pass as before and signed ones record the signer", async () => {
  const root = repo();
  attest(root, false, "a.json");
  attest(root, true, "b.json");
  const report = await verifyWithSignatures({ root, policy: null, verify: ok });
  assert.equal(report.ok, true);
  assert.deepEqual(report.results.map((r) => r.signer ?? null), [null, WORKFLOW]);
});

test("require: an unsigned verdict is refused as unsigned", async () => {
  const root = repo();
  attest(root, false);
  const report = await verifyWithSignatures({ root, policy: policy({ require: true, trusted: [WORKFLOW] }), verify: ok });
  assert.equal(report.ok, false);
  assert.equal(report.results[0]!.status, "unsigned");
});

test("require: a verdict signed by a workflow the policy doesn't trust is refused", async () => {
  const root = repo();
  attest(root, true);
  const report = await verifyWithSignatures({ root, policy: policy({ require: true, trusted: ["https://github.com/acme/api/.github/workflows/release.yml@refs/heads/main"] }), verify: ok });
  assert.equal(report.results[0]!.status, "signer_not_trusted");
});

test("require: a verdict signed by a trusted workflow passes", async () => {
  const root = repo();
  attest(root, true);
  const report = await verifyWithSignatures({ root, policy: policy({ require: true, trusted: [WORKFLOW] }), verify: ok });
  assert.equal(report.ok, true);
  assert.equal(report.results[0]!.signer, WORKFLOW);
});

test("a tampered signature is refused even when signatures aren't required", async () => {
  const root = repo();
  const att = attest(root, true);
  writeFileSync(join(root, DIR, "security-reviewer.json"), JSON.stringify({ ...att, by: "someone-else" }, null, 2));
  const report = await verifyWithSignatures({ root, policy: null, verify: ok });
  assert.equal(report.results[0]!.status, "signature_invalid");
});

test("require: Sigstore unreachable is 'couldn't run', never a pass", async () => {
  const root = repo();
  attest(root, true);
  await assert.rejects(verifyWithSignatures({ root, policy: policy({ require: true, trusted: [WORKFLOW] }), verify: offline }), /couldn't check signatures/);
});

test("the plain synchronous gate treats a signed attestation without a check as unsigned when required", () => {
  const root = repo();
  attest(root, true);
  const report = verifyAttestations({ root, policy: policy({ require: true, trusted: [WORKFLOW] }) });
  assert.equal(report.results[0]!.status, "unsigned");
});

test("policy: require without a trusted list is rejected", () => {
  const root = repo();
  mkdirSync(join(root, ".slipmark"), { recursive: true });
  writeFileSync(join(root, ".slipmark/policy.json"), JSON.stringify({ schema: POLICY_SCHEMA, signatures: { require: true } }));
  assert.throws(() => loadPolicy(root), /needs a "trusted" list/);
});

test("a v1 attestation can carry a signature too", async () => {
  const root = repo();
  const att = attest(root, true);
  assert.equal(att.schema, "slipmark/attestation@1");
  const saved = JSON.parse(readFileSync(join(root, DIR, "security-reviewer.json"), "utf8"));
  assert.ok(saved.signature.bundle.dsseEnvelope);
  const report = await verifyWithSignatures({ root, policy: policy({ require: true, trusted: [WORKFLOW] }), verify: ok });
  assert.equal(report.ok, true);
});

// A genuine verdict signed through Sigstore by .github/workflows/signed-fixture.yml (see that file).
const REAL = JSON.parse(readFileSync(new URL("../../test/fixtures/signed-attestation.json", import.meta.url), "utf8"));
const REAL_ID = readFileSync(new URL("../../test/fixtures/signed-attestation.identity", import.meta.url), "utf8").trim();

test("real signature: the Fulcio certificate names the workflow that signed it", () => {
  assert.equal(bundleIdentity(REAL.signature.bundle), REAL_ID);
});

test("real signature: the envelope covers exactly this attestation", async () => {
  const r = await checkSignature(REAL, { trusted: [REAL_ID] }, ok);
  assert.deepEqual(r, { state: "valid", identity: REAL_ID, issuer: "https://token.actions.githubusercontent.com", trusted: true });
  assert.equal((await checkSignature({ ...REAL, verdict: "cleared" }, undefined, ok)).state, "invalid");
});

// --- in-toto Statement signing ---

/** Sign the way sigstore.attest does with --sign-format intoto: a DSSE envelope over the canonical Statement. */
function fakeSignStatement(att: Attestation, payload = statementPayload(att)): Attestation {
  const bundle: SigstoreBundle = {
    mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
    verificationMaterial: { certificate: { rawBytes: CERT } },
    dsseEnvelope: { payload: payload.toString("base64"), payloadType: INTOTO_PAYLOAD_TYPE, signatures: [{ sig: "c2ln" }] },
  };
  return { ...att, signature: { bundle } };
}

function statementAttest(root: string, file = "security-reviewer.json") {
  const att = fakeSignStatement(createAttestation({ root, by: "security-reviewer", verdict: "pass", subjects: ["src/pay.ts"], now: new Date("2026-10-23T10:00:00Z") }));
  writeAttestation(join(root, DIR, file), att);
  return att;
}

test("in-toto: the Statement names each attested file as a subject and carries the verdict as its predicate", () => {
  const root = repo();
  const att = createAttestation({ root, by: "security-reviewer", verdict: "pass", subjects: ["src/pay.ts"], now: new Date("2026-10-23T10:00:00Z") });
  const st = toStatement({ ...att, signature: { bundle: {} } }) as { _type: string; subject: { name: string; digest: { sha256: string } }[]; predicateType: string; predicate: Record<string, unknown> };
  assert.equal(st._type, STATEMENT_TYPE);
  assert.equal(st.predicateType, PREDICATE_TYPE);
  assert.deepEqual(st.subject, [{ name: "src/pay.ts", digest: { sha256: att.subjects[0]!.sha256 } }]);
  assert.equal(st.predicate.verdict, "pass");
  assert.equal("signature" in st.predicate, false);
});

test("in-toto: a Statement-signed verdict passes the gate from a trusted workflow", async () => {
  const root = repo();
  statementAttest(root);
  const report = await verifyWithSignatures({ root, policy: policy({ require: true, trusted: [WORKFLOW] }), verify: ok });
  assert.equal(report.ok, true);
  assert.equal(report.results[0]!.signer, WORKFLOW);
});

test("in-toto: editing the attestation after signing breaks the Statement signature", async () => {
  const root = repo();
  const att = statementAttest(root);
  writeFileSync(join(root, DIR, "security-reviewer.json"), JSON.stringify({ ...att, note: "added after signing" }, null, 2));
  const report = await verifyWithSignatures({ root, policy: null, verify: ok });
  assert.equal(report.results[0]!.status, "signature_invalid");
});

test("in-toto: a Statement whose subject digest differs from the attestation is invalid", async () => {
  const root = repo();
  const att = createAttestation({ root, by: "security-reviewer", verdict: "pass", subjects: ["src/pay.ts"], now: new Date("2026-10-23T10:00:00Z") });
  const st = toStatement(att) as { subject: { digest: { sha256: string } }[] };
  st.subject[0]!.digest.sha256 = "0".repeat(64);
  const signed = fakeSignStatement(att, Buffer.from(canonicalJson(st)));
  assert.equal((await checkSignature(signed as unknown as Record<string, unknown>, undefined, ok)).state, "invalid");
});

test("in-toto: a Slipmark-format payload labelled as in-toto is invalid", async () => {
  const root = repo();
  const att = createAttestation({ root, by: "security-reviewer", verdict: "pass", subjects: ["src/pay.ts"], now: new Date("2026-10-23T10:00:00Z") });
  const signed = fakeSignStatement(att, signedPayload(att));
  assert.equal((await checkSignature(signed as unknown as Record<string, unknown>, undefined, ok)).state, "invalid");
});

test("in-toto: an unknown payload type is invalid", async () => {
  const root = repo();
  const att = attest(root, true) as unknown as { signature: { bundle: SigstoreBundle } };
  att.signature.bundle.dsseEnvelope!.payloadType = "application/json";
  assert.equal((await checkSignature(att as unknown as Record<string, unknown>, undefined, ok)).state, "invalid");
});

test("in-toto Bundle: one envelope line per Statement-signed verdict, others skipped and named", () => {
  const root = repo();
  const a = statementAttest(root, "a.json") as unknown as Record<string, unknown>;
  const b = attest(root, true, "b.json") as unknown as Record<string, unknown>;
  const c = attest(root, false, "c.json") as unknown as Record<string, unknown>;
  const { lines, skipped } = intotoBundleLines([{ file: "a.json", att: a }, { file: "b.json", att: b }, { file: "c.json", att: c }]);
  assert.equal(lines.length, 1);
  const env = JSON.parse(lines[0]!) as { payloadType: string; payload: string; signatures: unknown[] };
  assert.equal(env.payloadType, INTOTO_PAYLOAD_TYPE);
  assert.equal(JSON.parse(Buffer.from(env.payload, "base64").toString()).predicateType, PREDICATE_TYPE);
  assert.deepEqual(skipped.map((s) => s.file), ["b.json", "c.json"]);
});

test("the existing Slipmark-format envelope still verifies", async () => {
  const root = repo();
  attest(root, true);
  const report = await verifyWithSignatures({ root, policy: policy({ require: true, trusted: [WORKFLOW] }), verify: ok });
  assert.equal(report.ok, true);
});

// A genuine in-toto Statement signed by the same workflow. Made on the first run after this lands on main.
const INTOTO_FIXTURE = new URL("../../test/fixtures/signed-intoto-attestation.json", import.meta.url);
const hasIntotoFixture = (() => { try { readFileSync(INTOTO_FIXTURE); return true; } catch { return false; } })();

test("real in-toto signature: the envelope is a Statement covering exactly this attestation", { skip: !hasIntotoFixture && "fixture not generated yet" }, async () => {
  const real = JSON.parse(readFileSync(INTOTO_FIXTURE, "utf8"));
  assert.equal(real.signature.bundle.dsseEnvelope.payloadType, INTOTO_PAYLOAD_TYPE);
  assert.equal(bundleIdentity(real.signature.bundle), REAL_ID);
  assert.deepEqual(await checkSignature(real, { trusted: [REAL_ID] }, ok), { state: "valid", identity: REAL_ID, issuer: "https://token.actions.githubusercontent.com", trusted: true });
  assert.equal((await checkSignature({ ...real, verdict: "cleared" }, undefined, ok)).state, "invalid");
});

test("in-toto: malformed subjects are invalid, not a crash", async () => {
  for (const subjects of ["src/pay.ts", 5, [null], [{ path: "src/pay.ts" }], null]) {
    const att = { schema: "slipmark/attestation@1", by: "r", verdict: "pass", at: "2026-10-23T10:00:00.000Z", subjects, signature: { bundle: { verificationMaterial: { certificate: { rawBytes: CERT } }, dsseEnvelope: { payload: "e30=", payloadType: INTOTO_PAYLOAD_TYPE, signatures: [{ sig: "c2ln" }] } } } };
    assert.equal((await checkSignature(att, undefined, ok)).state, "invalid");
  }
});

test("in-toto: one malformed file is refused and the gate still runs over the rest", async () => {
  const root = repo();
  attest(root, false, "good.json");
  writeFileSync(join(root, DIR, "bad.json"), JSON.stringify({ schema: "slipmark/attestation@1", by: "r", verdict: "pass", at: "2026-10-23T10:00:00.000Z", subjects: "src/pay.ts", signature: { bundle: { dsseEnvelope: { payload: "e30=", payloadType: INTOTO_PAYLOAD_TYPE, signatures: [] } } } }));
  const report = await verifyWithSignatures({ root, policy: null, verify: ok });
  assert.equal(report.ok, false);
  assert.ok(report.results.some((r) => r.status === "verified"));
});
