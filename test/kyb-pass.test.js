import { test } from "node:test";
import assert from "node:assert/strict";
import { issueCredential, verifyCredential, openSubject, holderCommitment, generateIssuerKey, loadIssuer, epochDay, credentialLeaf } from "../src/credential.js";
import { evaluatePolicy, presentation, nullifier, validatePolicy, EXAMPLE_POLICIES } from "../src/policy.js";
import { handle } from "../src/worker.js";

const NOW = new Date("2026-10-24T12:00:00Z");
const TODAY = epochDay(NOW);
const SECRET = "0x" + "11".repeat(32);
const SALT = "0x" + "22".repeat(32);
const LA_POSTE = { isValid: true, requestDate: "2026-10-24T12:00:00.000Z", userError: "VALID", name: "SA LA POSTE", address: "9 RUE DU COLONEL PIERRE AVIA\n92130 ISSY LES MOULINEAUX" };
const vies = (b, status = 200) => async () => new Response(JSON.stringify(b), { status });
const issuer = await loadIssuer((await generateIssuerKey()).privateJwk);
const deps = (fetchImpl, extra = {}) => ({ issuer, fetchImpl, now: NOW, sleep: async () => {}, salt: SALT, ...extra });
const GOOD_FR_IBAN = "FR7630006000011234567890189";

async function laPoste(extra = {}) {
  return issueCredential({ vat: "FR 39356000000", iban: GOOD_FR_IBAN, name: "La Poste", holder_commitment: await holderCommitment(SECRET), ...extra }, deps(vies(LA_POSTE)));
}

test("issues a signed credential with coarse claims only", async () => {
  const { credential: c, report } = await laPoste();
  assert.deepEqual(c.claims, { schema: "kyb-pass/0", country: "FR", eu_vat_valid: true, decision: "pass", iban_sepa: true, name_checked: true, issued_day: TODAY, expires_day: TODAY + 90, rules_version: report.verdict.rules_version });
  assert.equal(c.evidence_hash, report.attestation.hash);
  assert.match(c.leaf, /^0x[0-9a-f]{64}$/);
  assert.equal((await verifyCredential(c, issuer.publicJwk)).ok, true);
});

test("the signed part never contains the VAT number, the name or the IBAN", async () => {
  const { credential: c } = await laPoste();
  const signed = JSON.stringify({ claims: c.claims, s: c.subject_commitment, h: c.holder_commitment, e: c.evidence_hash, l: c.leaf });
  for (const needle of ["39356000000", "LA POSTE", "La Poste", GOOD_FR_IBAN, "0189"]) assert.ok(!signed.includes(needle), needle);
  assert.ok(!JSON.stringify(c).includes(GOOD_FR_IBAN));
});

test("holder can open the subject commitment to an auditor, and only with the right VAT", async () => {
  const { credential: c } = await laPoste();
  assert.equal(await openSubject(c, "FR39356000000"), true);
  assert.equal(await openSubject(c, "FR40303265045"), false);
});

test("any tampering with claims breaks the leaf and the signature", async () => {
  const { credential: c } = await laPoste();
  const forged = { ...c, claims: { ...c.claims, decision: "pass", country: "DE" } };
  const v = await verifyCredential(forged, issuer.publicJwk);
  assert.equal(v.ok, false);
  assert.equal(v.leaf.match, false);
  const relabelled = { ...forged, leaf: await credentialLeaf(forged) };
  assert.equal((await verifyCredential(relabelled, issuer.publicJwk)).signature_valid, false);
});

test("a credential from another issuer key is not trusted", async () => {
  const other = await loadIssuer((await generateIssuerKey()).privateJwk);
  const { credential: c } = await issueCredential({ vat: "FR39356000000", holder_commitment: await holderCommitment(SECRET) }, { ...deps(vies(LA_POSTE)), issuer: other });
  const v = await verifyCredential(c, issuer.publicJwk);
  assert.equal(v.ok, false);
  assert.equal(v.trusted_issuer, false);
});

test("invalid VAT gives a fail credential that no pass policy accepts", async () => {
  const { credential: c } = await issueCredential({ vat: "FR00000000000", holder_commitment: await holderCommitment(SECRET) }, deps(vies({ isValid: false, userError: "INVALID" })));
  assert.equal(c.claims.decision, "fail");
  assert.equal(c.claims.eu_vat_valid, false);
  assert.equal(evaluatePolicy(c.claims, EXAMPLE_POLICIES["eu-pass-90d"], TODAY).ok, false);
});

test("VIES unavailable: no credential is issued (never a guess)", async () => {
  const out = await issueCredential({ vat: "FR39356000000", holder_commitment: await holderCommitment(SECRET) }, deps(vies({ userError: "MS_MAX_CONCURRENT_REQ" })));
  assert.match(out.error, /unavailable/);
  assert.equal(out.credential, undefined);
});

test("input validation: bad VAT and bad holder commitment are refused before any network call", async () => {
  let called = 0;
  const f = async () => { called++; return new Response("{}"); };
  assert.match((await issueCredential({ vat: "XX123", holder_commitment: "0x" + "a".repeat(64) }, deps(f))).error, /VAT/);
  assert.match((await issueCredential({ vat: "FR39356000000", holder_commitment: "abc" }, deps(f))).error, /holder_commitment/);
  assert.equal(called, 0);
  await assert.rejects(holderCommitment("not-hex"));
});

test("policy rules: country, decision, SEPA, freshness, expiry", async () => {
  const { credential: c } = await laPoste();
  const P = EXAMPLE_POLICIES;
  assert.equal(evaluatePolicy(c.claims, P["eu-pass-90d"], TODAY).ok, true);
  assert.equal(evaluatePolicy(c.claims, P["eu-pass-sepa-30d"], TODAY + 30).ok, true);
  const stale = evaluatePolicy(c.claims, P["eu-pass-sepa-30d"], TODAY + 31);
  assert.deepEqual(stale.rules.filter((r) => !r.ok).map((r) => r.rule), ["fresh_enough"]);
  const expired = evaluatePolicy(c.claims, P["eu-pass-90d"], TODAY + 91);
  assert.ok(expired.rules.find((r) => r.rule === "not_expired").ok === false);
  const deOnly = { ...P["fr-de-pass-disclose-country"], countries: ["DE"] };
  assert.deepEqual(evaluatePolicy(c.claims, deOnly, TODAY).rules.filter((r) => !r.ok).map((r) => r.rule), ["country_allowed"]);
  const noIban = (await issueCredential({ vat: "FR39356000000", holder_commitment: await holderCommitment(SECRET) }, deps(vies(LA_POSTE)))).credential;
  assert.equal(noIban.claims.iban_sepa, null);
  assert.equal(evaluatePolicy(noIban.claims, P["eu-pass-sepa-30d"], TODAY).ok, false);
  assert.equal(evaluatePolicy(c.claims, P["eu-pass-90d"], TODAY - 1).ok, false, "issued in the future");
});

test("review decisions pass only pass_or_review policies", async () => {
  const { credential: c } = await laPoste({ name: "Totally Different Holding" });
  assert.equal(c.claims.decision, "review");
  assert.equal(evaluatePolicy(c.claims, EXAMPLE_POLICIES["eu-pass-90d"], TODAY).ok, false);
  assert.equal(evaluatePolicy(c.claims, { ...EXAMPLE_POLICIES["eu-pass-90d"], id: "eu-review-ok", require_decision: "pass_or_review" }, TODAY).ok, true);
});

test("nullifiers are deterministic per scope and unlinkable across scopes", async () => {
  const a1 = await nullifier(SECRET, "shop-a:1"), a2 = await nullifier(SECRET, "shop-a:1"), b = await nullifier(SECRET, "shop-b:1");
  assert.equal(a1, a2);
  assert.notEqual(a1, b);
  assert.notEqual(a1, await nullifier("0x" + "33".repeat(32), "shop-a:1"));
});

test("reference presentation discloses only what the policy asks for", async () => {
  const { credential: c } = await laPoste();
  const p1 = await presentation(c, SECRET, EXAMPLE_POLICIES["eu-pass-90d"], "s:1", TODAY);
  assert.deepEqual(p1.disclosed, {});
  assert.equal(p1.satisfied, true);
  assert.equal(p1.zk, false);
  const p2 = await presentation(c, SECRET, EXAMPLE_POLICIES["fr-de-pass-disclose-country"], "s:1", TODAY);
  assert.deepEqual(p2.disclosed, { country: "FR" });
  for (const k of ["leaf", "subject_commitment", "holder_commitment", "evidence_hash"]) assert.ok(!JSON.stringify(p1).includes(c[k]), k);
});

test("policy validation", () => {
  for (const p of Object.values(EXAMPLE_POLICIES)) assert.equal(validatePolicy(p), null);
  assert.match(validatePolicy({ ...EXAMPLE_POLICIES["eu-pass-90d"], countries: ["US"] }), /countries/);
  assert.match(validatePolicy({ ...EXAMPLE_POLICIES["eu-pass-90d"], max_age_days: 0 }), /max_age_days/);
});

test("worker routes", async () => {
  const d = { issuer, fetchImpl: vies(LA_POSTE), now: NOW, sleep: async () => {} };
  const get = (p) => handle(new Request("https://x" + p), {}, d);
  const post = (p, b) => handle(new Request("https://x" + p, { method: "POST", body: JSON.stringify(b) }), {}, d);
  assert.equal((await get("/")).status, 200);
  assert.equal((await (await get("/health")).json()).ok, true);
  assert.equal((await (await get("/.well-known/kyb-pass-issuer.json")).json()).public_key.x, issuer.publicJwk.x);
  assert.equal((await (await get("/api/policies")).json()).length, 3);
  const issued = await post("/api/issue", { vat: "FR39356000000", holder_commitment: await holderCommitment(SECRET) });
  assert.equal(issued.status, 200);
  const { credential } = await issued.json();
  assert.equal((await (await post("/api/verify", { credential })).json()).ok, true);
  const ev = await (await post("/api/evaluate", { claims: credential.claims, policy: "eu-pass-90d" })).json();
  assert.equal(ev.ok, true);
  assert.equal((await post("/api/evaluate", { claims: credential.claims, policy: "nope" })).status, 400);
  assert.equal((await post("/api/issue", { vat: "FR39356000000" })).status, 400);
  assert.equal((await get("/api/issue")).status, 405);
  assert.equal((await get("/nope")).status, 404);
});

test("committed test vectors match the reference predicate", async () => {
  const { readFileSync } = await import("node:fs");
  const { vectors } = JSON.parse(readFileSync(new URL("../test-vectors/policy.json", import.meta.url)));
  assert.ok(vectors.length >= 10);
  for (const v of vectors) {
    const r = evaluatePolicy(v.claims, v.policy, v.today);
    assert.deepEqual({ ok: r.ok, failed: r.rules.filter((x) => !x.ok).map((x) => x.rule) }, v.expected, v.name);
  }
});
