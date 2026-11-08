/**
 * Signed verdicts.
 *
 * An unsigned attestation proves the files haven't changed since the verdict. It
 * doesn't prove who gave it: anyone can write `"by": "security-reviewer"`. A
 * signed attestation carries a Sigstore bundle made where the verdict was given,
 * usually a GitHub Actions job, so it names the exact workflow that produced it
 * and is logged in Sigstore's public Rekor log. A verdict typed by hand on a
 * laptop can't carry one.
 *
 * What is signed is the attestation itself, minus the `signature` field, as
 * canonical JSON (keys sorted, no whitespace), in a DSSE envelope with payload
 * type PAYLOAD_TYPE. Change one byte of the verdict, a hash or a note and the
 * signature no longer matches.
 *
 * With `format: "intoto"` the envelope instead carries an in-toto Statement v1
 * (payload type INTOTO_PAYLOAD_TYPE): the attested files and their SHA-256 as
 * `subject`, and the same unsigned attestation as the predicate. Any in-toto
 * tool can read it, and the envelope can be lifted into an in-toto Bundle.
 */
import { X509Certificate } from "node:crypto";
import type { Attestation } from "./attestation.js";

export const PAYLOAD_TYPE = "application/vnd.slipmark.attestation+json";
export const INTOTO_PAYLOAD_TYPE = "application/vnd.in-toto+json";
export const STATEMENT_TYPE = "https://in-toto.io/Statement/v1";
/** Identifies a Slipmark verdict as an in-toto predicate. The predicate is the attestation without its `signature`. */
export const PREDICATE_TYPE = "https://github.com/founder-ship-it/Slipmark/attestation/v1";
export type SignFormat = "slipmark" | "intoto";
export const GITHUB_ACTIONS_ISSUER = "https://token.actions.githubusercontent.com";

/** A Sigstore bundle as JSON (sigstore's SerializedBundle). Kept loose so the gate has no type dependency on it. */
export type SigstoreBundle = {
  mediaType?: string;
  verificationMaterial?: {
    certificate?: { rawBytes: string };
    x509CertificateChain?: { certificates: { rawBytes: string }[] };
  };
  dsseEnvelope?: { payload: string; payloadType: string; signatures: { sig: string; keyid?: string }[] };
  [k: string]: unknown;
};

export interface AttestationSignature {
  /** Sigstore bundle with a DSSE envelope over the canonical attestation. */
  bundle: SigstoreBundle;
}

/** `.slipmark/policy.json` → `signatures`. */
export interface SignaturePolicy {
  /** Refuse any verdict that isn't signed by a trusted signer. */
  require?: boolean;
  /**
   * Signer identities to trust, matched against the signing certificate's identity.
   * For GitHub Actions that's the workflow, for example
   * `https://github.com/acme/api/.github/workflows/agent-review.yml@refs/heads/main`.
   * `*` matches anything. Pin a protected ref, so a pull request can't change the workflow that signs its own verdicts.
   */
  trusted?: string[];
  /** OIDC issuer the certificate must come from. Default: GitHub Actions. */
  issuer?: string;
}

export type SignatureCheck =
  | { state: "valid"; identity: string; issuer: string; trusted: boolean }
  | { state: "invalid"; reason: string }
  | { state: "unchecked"; reason: string };

/** Deterministic JSON: object keys sorted at every level, no whitespace. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((v) => (v === undefined ? "null" : canonicalJson(v))).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
}

/** The exact bytes a signature covers: the attestation without its `signature` field. */
export function signedPayload(att: Attestation | Record<string, unknown>): Buffer {
  const { signature: _sig, ...rest } = att as Record<string, unknown>;
  return Buffer.from(canonicalJson(rest), "utf8");
}

/** The in-toto Statement for an attestation: its subjects as resource descriptors, the attestation itself as the predicate. */
export function toStatement(att: Attestation | Record<string, unknown>): Record<string, unknown> {
  const predicate = JSON.parse(signedPayload(att).toString("utf8")) as Record<string, unknown>;
  const subjects = (predicate.subjects as { path: string; sha256: string }[] | undefined) ?? [];
  return {
    _type: STATEMENT_TYPE,
    subject: subjects.map((s) => ({ name: s.path, digest: { sha256: s.sha256 } })),
    predicateType: PREDICATE_TYPE,
    predicate,
  };
}

/** The exact bytes an in-toto signature covers: the canonical Statement. */
export function statementPayload(att: Attestation | Record<string, unknown>): Buffer {
  return Buffer.from(canonicalJson(toStatement(att)), "utf8");
}

/** `*` matches any run of characters; everything else is literal. Whole-string match. */
export function identityMatches(identity: string, pattern: string): boolean {
  const re = new RegExp(`^${pattern.split("*").map((p) => p.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`);
  return re.test(identity);
}

/** The signer named in a bundle's certificate: a URI (workflows) or an email (people). */
export function bundleIdentity(bundle: SigstoreBundle): string | null {
  const raw = bundle.verificationMaterial?.certificate?.rawBytes ?? bundle.verificationMaterial?.x509CertificateChain?.certificates?.[0]?.rawBytes;
  if (!raw) return null;
  try {
    const san = new X509Certificate(Buffer.from(raw, "base64")).subjectAltName ?? "";
    const m = /(?:^|,\s*)(?:URI|email):([^,]+)/.exec(san);
    return m ? m[1]!.trim() : null;
  } catch {
    return null;
  }
}

/** Sign an attestation where it was made. Keyless: in GitHub Actions the job's identity is used (needs `id-token: write`). */
export async function signAttestation(att: Attestation, opts: { identityToken?: string; format?: SignFormat } = {}): Promise<Attestation & { signature: AttestationSignature }> {
  const { signature: _old, ...unsigned } = att as Attestation & { signature?: unknown };
  let sigstore: typeof import("sigstore");
  try {
    sigstore = await import("sigstore");
  } catch {
    throw new Error("signing needs the sigstore package: npm install sigstore");
  }
  const identityToken = opts.identityToken ?? process.env.SIGSTORE_ID_TOKEN ?? undefined;
  if (!identityToken && !(process.env.ACTIONS_ID_TOKEN_REQUEST_URL && process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN)) {
    throw new Error(
      "--sign needs an identity to sign with. Run it in a GitHub Actions job with `permissions: id-token: write`, or set SIGSTORE_ID_TOKEN.",
    );
  }
  const intoto = opts.format === "intoto";
  const payload = intoto ? statementPayload(unsigned as Attestation) : signedPayload(unsigned as Attestation);
  const bundle = (await sigstore.attest(payload, intoto ? INTOTO_PAYLOAD_TYPE : PAYLOAD_TYPE, identityToken ? { identityToken } : {})) as unknown as SigstoreBundle;
  return { ...(unsigned as Attestation), signature: { bundle } };
}

type Verify = (bundle: SigstoreBundle, issuer: string) => Promise<void>;

async function sigstoreVerify(bundle: SigstoreBundle, issuer: string): Promise<void> {
  const sigstore = await import("sigstore");
  await sigstore.verify(bundle as unknown as Parameters<typeof sigstore.verify>[0], { certificateIssuer: issuer });
}

/**
 * Check one attestation's signature: the envelope covers exactly this attestation,
 * the certificate chains to Sigstore and was issued to `issuer`, the entry is in the
 * transparency log, and (if a trusted list is given) the signer is on it.
 */
export async function checkSignature(att: Record<string, unknown>, policy: SignaturePolicy | undefined, verify: Verify = sigstoreVerify): Promise<SignatureCheck> {
  const sig = att.signature as AttestationSignature | undefined;
  const bundle = sig?.bundle;
  const env = bundle?.dsseEnvelope;
  if (!bundle || !env) return { state: "invalid", reason: "signature has no Sigstore DSSE bundle" };
  // Either form must cover exactly this attestation, byte for byte in canonical form. A Statement
  // whose subjects or predicate differ from the attestation, however slightly, doesn't count.
  let expected: Buffer;
  if (env.payloadType === PAYLOAD_TYPE) expected = signedPayload(att);
  else if (env.payloadType === INTOTO_PAYLOAD_TYPE) expected = statementPayload(att);
  else return { state: "invalid", reason: `signed payload type is ${env.payloadType}, not a Slipmark attestation` };
  if (!Buffer.from(env.payload, "base64").equals(expected)) {
    return { state: "invalid", reason: "the signature is for different content: the attestation was changed after it was signed" };
  }
  const issuer = policy?.issuer ?? GITHUB_ACTIONS_ISSUER;
  try {
    await verify(bundle, issuer);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    // Couldn't fetch Sigstore's trust root or reach the network: not proof of tampering.
    if (/TUF|fetch|ENOTFOUND|ECONNREFUSED|ETIMEDOUT|EAI_AGAIN|network|socket/i.test(`${(e as { name?: string })?.name ?? ""} ${msg}`)) {
      return { state: "unchecked", reason: `couldn't reach Sigstore to check the signature: ${msg}` };
    }
    return { state: "invalid", reason: `signature didn't verify: ${msg}` };
  }
  const identity = bundleIdentity(bundle);
  if (!identity) return { state: "invalid", reason: "signing certificate names no identity" };
  const trusted = !policy?.trusted?.length || policy.trusted.some((p) => identityMatches(identity, p));
  return { state: "valid", identity, issuer, trusted };
}

/**
 * In-toto Bundle lines (JSON Lines, one DSSE envelope each) for the attestations signed as
 * in-toto Statements. Attestations signed in Slipmark's own format, or unsigned, are skipped and
 * named, since an in-toto consumer couldn't read them. The Bundle isn't signed as a whole: a
 * consumer must require each entry it needs by predicate type and signer.
 */
export function intotoBundleLines(atts: { file: string; att: Record<string, unknown> }[]): { lines: string[]; skipped: { file: string; reason: string }[] } {
  const lines: string[] = [];
  const skipped: { file: string; reason: string }[] = [];
  for (const { file, att } of atts) {
    const env = (att.signature as AttestationSignature | undefined)?.bundle?.dsseEnvelope;
    if (!env) skipped.push({ file, reason: "not signed" });
    else if (env.payloadType !== INTOTO_PAYLOAD_TYPE) skipped.push({ file, reason: "signed in Slipmark's own format; re-attest with --sign-format intoto" });
    else lines.push(canonicalJson({ payload: env.payload, payloadType: env.payloadType, signatures: env.signatures }));
  }
  return { lines, skipped };
}
