// Cloudflare Worker: KYB Pass issuer demo. Stateless: nothing about the subject is stored.
import { issueCredential, verifyCredential, loadIssuer, generateIssuerKey, epochDay, dayToIso, CREDENTIAL_SCHEMA } from "./credential.js";
import { evaluatePolicy, validatePolicy, policyHash, EXAMPLE_POLICIES } from "./policy.js";
import { PAGE } from "./page.js";

const CORS = { "access-control-allow-origin": "*", "access-control-allow-methods": "GET,POST,OPTIONS", "access-control-allow-headers": "content-type" };
const json = (d, s = 200) => new Response(JSON.stringify(d, null, 2), { status: s, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...CORS } });

let cached = null;
async function issuerFrom(env) {
  if (cached) return cached;
  if (env && env.ISSUER_JWK) cached = { ...(await loadIssuer(env.ISSUER_JWK)), ephemeral: false };
  else cached = { ...(await loadIssuer((await generateIssuerKey()).privateJwk)), ephemeral: true };
  return cached;
}
export function _resetIssuerCache() { cached = null; }

async function body(request) {
  try { return await request.json(); } catch { return null; }
}

export async function handle(request, env = {}, deps = {}) {
  const url = new URL(request.url);
  if (request.method === "OPTIONS") return new Response(null, { headers: CORS });
  const issuer = deps.issuer || (await issuerFrom(env));
  const now = deps.now || new Date();
  switch (url.pathname) {
    case "/":
    case "/index.html":
      return new Response(PAGE, { headers: { "content-type": "text/html; charset=utf-8" } });
    case "/health":
      return json({ ok: true, service: "kyb-pass", schema: CREDENTIAL_SCHEMA, midnight: "contract lands in Midnight Buildathon Wave 3 (see repo)" });
    case "/.well-known/kyb-pass-issuer.json":
      return json({ issuer_id: issuer.id, alg: "Ed25519", public_key: issuer.publicJwk, schema: CREDENTIAL_SCHEMA, ephemeral_demo_key: issuer.ephemeral, repo: "https://github.com/nathanielc3d/kyb-pass" });
    case "/api/policies":
      return json(Object.values(EXAMPLE_POLICIES));
    case "/api/issue": {
      if (request.method !== "POST") return json({ error: "POST a JSON body {vat, iban?, name?, holder_commitment}" }, 405);
      const b = await body(request);
      if (!b) return json({ error: "body must be JSON" }, 400);
      const out = await issueCredential(b, { ...deps, issuer, now });
      if (out.error) return json({ error: out.error }, out.report ? 503 : 400);
      return json(out);
    }
    case "/api/verify": {
      if (request.method !== "POST") return json({ error: "POST a credential" }, 405);
      const b = await body(request);
      return json(await verifyCredential(b && b.credential ? b.credential : b, issuer.publicJwk));
    }
    case "/api/evaluate": {
      if (request.method !== "POST") return json({ error: "POST {claims, policy}" }, 405);
      const b = await body(request);
      if (!b || !b.claims) return json({ error: "body must be {claims, policy}" }, 400);
      const policy = typeof b.policy === "string" ? EXAMPLE_POLICIES[b.policy] : b.policy;
      const perr = validatePolicy(policy);
      if (perr) return json({ error: perr }, 400);
      const today = epochDay(now);
      return json({ policy_id: policy.id, policy_hash: await policyHash(policy), today: dayToIso(today), ...evaluatePolicy(b.claims, policy, today) });
    }
    default:
      return json({ error: "not found", routes: ["/", "/health", "/.well-known/kyb-pass-issuer.json", "/api/policies", "POST /api/issue", "POST /api/verify", "POST /api/evaluate"] }, 404);
  }
}

export default { fetch: (req, env) => handle(req, env) };
