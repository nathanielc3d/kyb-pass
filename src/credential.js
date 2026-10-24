// KYB Pass credential: turns a KYB evidence report into a privacy-preserving credential.
//
// What the issuer signs never contains the VAT number, the company name or the IBAN.
// It contains coarse claims (country, VAT valid, decision, SEPA IBAN, validity window),
// a salted commitment to the subject (so the holder can later open it to an auditor),
// a commitment to a secret that only the holder knows (so only the holder can present it),
// and the hash of the full evidence report (kept by the holder, auditable on demand).
//
// This file is the off-chain issuer. The on-chain part (Compact contract on Midnight that stores
// credential leaves in a Merkle tree and verifies zero-knowledge presentations) is built in
// Midnight Buildathon Wave 3, see docs/MIDNIGHT_PLAN.md.

import { buildReport, canonical, sha256Hex, normalizeVat, validateInput } from "./kyb/evidence.js";
import { checkIban } from "./kyb/iban.js";

export const CREDENTIAL_SCHEMA = "kyb-pass/0";
export const DEFAULT_VALIDITY_DAYS = 90;
const HEX32 = /^0x[0-9a-f]{64}$/;
const DAY_MS = 86400000;

export const epochDay = (date) => Math.floor(date.getTime() / DAY_MS);
export const dayToIso = (d) => new Date(d * DAY_MS).toISOString().slice(0, 10);

export function randomHex32() {
  const b = crypto.getRandomValues(new Uint8Array(32));
  return "0x" + [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
}

/** Domain-separated hash of the subject identity. Only the holder receives the salt. */
export async function subjectCommitment(vat, salt) {
  return sha256Hex(`kyb-pass/subject|${normalizeVat(vat)}|${salt}`);
}

/** Holder commitment = H(holder secret). Computed by the holder (browser or agent); the issuer only sees the commitment. */
export async function holderCommitment(holderSecret) {
  if (!HEX32.test(holderSecret)) throw new Error("holder secret must be 32 bytes hex (0x + 64 hex chars)");
  return sha256Hex(`kyb-pass/holder|${holderSecret}`);
}

/** Credential leaf: the single value the issuer signs (and, from Wave 3, inserts in the on-chain Merkle tree). */
export async function credentialLeaf({ claims, subject_commitment, holder_commitment, evidence_hash }) {
  return sha256Hex(canonical({ claims, evidence_hash, holder_commitment, subject_commitment }));
}

/** Coarse claims derived from an evidence report. No identifier, no name, no IBAN. */
export function claimsFromReport(report, { now, validityDays = DEFAULT_VALIDITY_DAYS, ibanGiven }) {
  const vies = report.checks.find((c) => c.id === "vat.vies");
  const iban = report.checks.find((c) => c.id === "iban.structure");
  const name = report.checks.find((c) => c.id === "name.match");
  const issued = epochDay(now);
  return {
    schema: CREDENTIAL_SCHEMA,
    country: report.subject.vat.slice(0, 2),
    eu_vat_valid: vies && vies.status !== "unavailable" ? vies.status === "pass" : null,
    decision: report.verdict.decision,
    iban_sepa: ibanGiven ? !!(iban && iban.result.valid && iban.result.sepa) : null,
    name_checked: !!(name && name.status === "pass"),
    issued_day: issued,
    expires_day: issued + validityDays,
    rules_version: report.verdict.rules_version,
  };
}

// ---------- Ed25519 issuer keys (WebCrypto, works in Workers and Node >= 20) ----------

const ED = { name: "Ed25519" };
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64u = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));
const hexBytes = (h) => Uint8Array.from(h.slice(2).match(/../g).map((x) => parseInt(x, 16)));

export async function generateIssuerKey() {
  const kp = await crypto.subtle.generateKey(ED, true, ["sign", "verify"]);
  return { privateJwk: await crypto.subtle.exportKey("jwk", kp.privateKey), publicJwk: await crypto.subtle.exportKey("jwk", kp.publicKey) };
}

export async function loadIssuer(privateJwk) {
  const jwk = typeof privateJwk === "string" ? JSON.parse(privateJwk) : privateJwk;
  const privateKey = await crypto.subtle.importKey("jwk", jwk, ED, false, ["sign"]);
  const publicJwk = { kty: "OKP", crv: "Ed25519", x: jwk.x };
  return { privateKey, publicJwk, id: "did:jwk:" + b64u(new TextEncoder().encode(JSON.stringify(publicJwk))) };
}

export async function signLeaf(issuer, leaf) {
  return b64u(await crypto.subtle.sign(ED, issuer.privateKey, hexBytes(leaf)));
}

export async function verifyLeafSignature(publicJwk, leaf, sig) {
  try {
    const key = await crypto.subtle.importKey("jwk", publicJwk, ED, false, ["verify"]);
    return await crypto.subtle.verify(ED, key, unb64u(sig), hexBytes(leaf));
  } catch { return false; }
}

// ---------- issuance ----------

/**
 * Run live KYB checks and issue a credential bound to the holder's commitment.
 * @param {{vat:string, iban?:string, name?:string, holder_commitment:string}} input
 * @param {{issuer:object, fetchImpl?:Function, now?:Date, sleep?:Function, validityDays?:number, salt?:string}} deps
 */
export async function issueCredential(input, deps) {
  const err = validateInput(input) || (!HEX32.test(String(input.holder_commitment || "")) ? "holder_commitment must be 0x + 64 lowercase hex chars (SHA-256 of your holder secret)" : null);
  if (err) return { error: err };
  const now = deps.now || new Date();
  const report = await buildReport({ vat: input.vat, iban: input.iban, name: input.name, purpose: "KYB Pass credential issuance" }, { ...deps, now });
  const claims = claimsFromReport(report, { now, validityDays: deps.validityDays, ibanGiven: !!input.iban });
  if (claims.eu_vat_valid === null) return { error: "VIES is unavailable for this member state right now; no credential issued (never a guess). Retry later.", report };
  const salt = deps.salt || randomHex32();
  const body = {
    claims,
    subject_commitment: await subjectCommitment(input.vat, salt),
    holder_commitment: input.holder_commitment,
    evidence_hash: report.attestation.hash,
  };
  const leaf = await credentialLeaf(body);
  const credential = {
    ...body,
    leaf,
    issuer: { id: deps.issuer.id, public_key: deps.issuer.publicJwk },
    signature: await signLeaf(deps.issuer, leaf),
    // Private opening data: stays with the holder, never goes on-chain.
    holder_private: { subject_salt: salt, note: "Keep this and your holder secret private. Together with the VAT number they open subject_commitment to an auditor." },
  };
  return { credential, report };
}

/** Check a credential's integrity and issuer signature (no policy). */
export async function verifyCredential(c, trustedPublicJwk) {
  if (!c || typeof c !== "object" || !c.claims) return { ok: false, error: "not a kyb-pass credential" };
  const leaf = await credentialLeaf(c);
  const leafOk = leaf === c.leaf;
  const keyOk = !trustedPublicJwk || (c.issuer && c.issuer.public_key && c.issuer.public_key.x === trustedPublicJwk.x);
  const sigOk = leafOk && keyOk && (await verifyLeafSignature(c.issuer.public_key, c.leaf, c.signature));
  return { ok: leafOk && keyOk && sigOk, leaf: { claimed: c.leaf, recomputed: leaf, match: leafOk }, trusted_issuer: keyOk, signature_valid: sigOk };
}

/** Holder side: open the subject commitment to an auditor (selective disclosure on request). */
export async function openSubject(c, vat) {
  return (await subjectCommitment(vat, c.holder_private.subject_salt)) === c.subject_commitment;
}

export { checkIban };
