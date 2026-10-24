// Generates test-vectors/policy.json: inputs and expected outputs of the reference predicate.
// The Wave 3 Compact circuit and its TypeScript witnesses are tested against these vectors.
import { writeFileSync, mkdirSync } from "node:fs";
import { evaluatePolicy, EXAMPLE_POLICIES } from "../src/policy.js";

const base = { schema: "kyb-pass/0", country: "FR", eu_vat_valid: true, decision: "pass", iban_sepa: true, name_checked: true, issued_day: 20750, expires_day: 20840, rules_version: "2026-10-24.1" };
const cases = [
  ["fresh FR pass", base, "eu-pass-90d", 20750],
  ["last valid day", base, "eu-pass-90d", 20840],
  ["expired", base, "eu-pass-90d", 20841],
  ["too old for 30d policy", base, "eu-pass-sepa-30d", 20781],
  ["no IBAN for SEPA policy", { ...base, iban_sepa: null }, "eu-pass-sepa-30d", 20751],
  ["non-SEPA IBAN", { ...base, iban_sepa: false }, "eu-pass-sepa-30d", 20751],
  ["review decision", { ...base, decision: "review" }, "eu-pass-90d", 20751],
  ["fail decision", { ...base, decision: "fail", eu_vat_valid: false }, "eu-pass-90d", 20751],
  ["country not allowed", { ...base, country: "IT" }, "fr-de-pass-disclose-country", 20751],
  ["DE allowed and disclosed", { ...base, country: "DE" }, "fr-de-pass-disclose-country", 20751],
  ["issued in the future", base, "eu-pass-90d", 20749],
];
const vectors = cases.map(([name, claims, pid, today]) => {
  const r = evaluatePolicy(claims, EXAMPLE_POLICIES[pid], today);
  return { name, claims, policy: EXAMPLE_POLICIES[pid], today, expected: { ok: r.ok, failed: r.rules.filter((x) => !x.ok).map((x) => x.rule) } };
});
mkdirSync(new URL("../test-vectors/", import.meta.url), { recursive: true });
writeFileSync(new URL("../test-vectors/policy.json", import.meta.url), JSON.stringify({ generated_by: "scripts/make-vectors.mjs", vectors }, null, 2) + "\n");
console.log(`wrote ${vectors.length} vectors`);
