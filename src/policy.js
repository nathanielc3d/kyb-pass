// Verifier policies and their reference semantics.
//
// A policy is what a payer, marketplace or agent asks for: "the counterparty passed EU KYB, is in
// one of these countries, has a SEPA IBAN, was checked recently". evaluatePolicy() is the reference
// implementation of the predicate that the Wave 3 Compact circuit proves in zero knowledge.
// The test vectors in test-vectors/ are generated from it so the circuit can be checked against it.

import { canonical, sha256Hex } from "./kyb/evidence.js";

export const EU = ["AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "EL", "ES", "FI", "FR", "HR", "HU", "IE", "IT", "LT", "LU", "LV", "MT", "NL", "PL", "PT", "RO", "SE", "SI", "SK"];

export const EXAMPLE_POLICIES = {
  "eu-pass-90d": { id: "eu-pass-90d", countries: EU, require_decision: "pass", require_sepa_iban: false, max_age_days: 90, disclose_country: false },
  "eu-pass-sepa-30d": { id: "eu-pass-sepa-30d", countries: EU, require_decision: "pass", require_sepa_iban: true, max_age_days: 30, disclose_country: false },
  "fr-de-pass-disclose-country": { id: "fr-de-pass-disclose-country", countries: ["FR", "DE"], require_decision: "pass", require_sepa_iban: false, max_age_days: 180, disclose_country: true },
};

export function validatePolicy(p) {
  if (!p || typeof p !== "object") return "policy must be an object";
  if (!/^[a-z0-9][a-z0-9-]{1,62}$/.test(String(p.id || ""))) return "policy.id must be 2-63 chars of a-z, 0-9, -";
  if (!Array.isArray(p.countries) || !p.countries.length || p.countries.some((c) => !EU.includes(c))) return "policy.countries must be a non-empty list of EU VIES country codes";
  if (!["pass", "pass_or_review"].includes(p.require_decision)) return "policy.require_decision must be pass or pass_or_review";
  if (!Number.isInteger(p.max_age_days) || p.max_age_days < 1 || p.max_age_days > 365) return "policy.max_age_days must be 1..365";
  return null;
}

/** Reference predicate. `today` is an epoch day number. Returns every rule so failures are explainable. */
export function evaluatePolicy(claims, policy, today) {
  const rules = [
    { rule: "schema", ok: claims.schema === "kyb-pass/0" },
    { rule: "eu_vat_valid", ok: claims.eu_vat_valid === true },
    { rule: "decision", ok: policy.require_decision === "pass" ? claims.decision === "pass" : ["pass", "review"].includes(claims.decision) },
    { rule: "country_allowed", ok: policy.countries.includes(claims.country) },
    { rule: "sepa_iban", ok: !policy.require_sepa_iban || claims.iban_sepa === true },
    { rule: "not_expired", ok: today <= claims.expires_day },
    { rule: "fresh_enough", ok: today - claims.issued_day <= policy.max_age_days },
    { rule: "not_from_future", ok: claims.issued_day <= today },
  ];
  return { ok: rules.every((r) => r.ok), rules };
}

export const policyHash = (p) => sha256Hex("kyb-pass/policy|" + canonical(p));

/**
 * Scoped nullifier: one presentation per (holder, scope). Unlinkable across scopes because it
 * depends on the holder secret, which never leaves the holder.
 */
export async function nullifier(holderSecret, scope) {
  return sha256Hex(`kyb-pass/nullifier|${holderSecret}|${scope}`);
}

/**
 * Off-chain reference presentation: what a verifier learns. Wave 3 replaces the holder-side
 * computation with a Compact zero-knowledge proof; the disclosed fields stay exactly these.
 */
export async function presentation(credential, holderSecret, policy, scope, today) {
  const r = evaluatePolicy(credential.claims, policy, today);
  return {
    kind: "kyb-pass/presentation-reference",
    zk: false,
    note: "Reference semantics only: this JSON is computed by the holder and is NOT a zero-knowledge proof. The Midnight circuit (Wave 3) proves the same statement without revealing the credential.",
    policy_id: policy.id,
    policy_hash: await policyHash(policy),
    scope,
    nullifier: await nullifier(holderSecret, scope),
    satisfied: r.ok,
    disclosed: policy.disclose_country ? { country: credential.claims.country } : {},
  };
}
