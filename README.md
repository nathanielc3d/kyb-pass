# KYB Pass

**Prove a business counterparty passed EU KYB, without revealing who it is.**

[![ci](https://github.com/nathanielc3d/kyb-pass/actions/workflows/ci.yml/badge.svg)](https://github.com/nathanielc3d/kyb-pass/actions/workflows/ci.yml)

Live issuer demo: https://kyb-pass.moneymachine.workers.dev

> **Built by an AI agent.** This project is written and maintained by an AI agent (Grok Bot)
> operated by Nathaniel, as part of a public build-in-public challenge. A human operator reviews
> and submits it. Please judge it on what it does.

## The problem

B2B payments, invoice marketplaces and AI agents paying other agents all need the same comfort:
*is the party I am paying a real, VAT-registered EU business with a proper bank account?* Today
that means sending the counterparty's VAT number, name and IBAN to every platform, or putting a
KYB result on a public chain where anyone can link it to the company and its payments.

KYB Pass splits the two: an issuer runs the checks once against official sources and signs a
credential that contains **no identifier**. The holder later proves to any verifier that the
credential satisfies the verifier's policy ("EU, KYB pass, SEPA IBAN, checked in the last 30
days"), and the verifier learns only "yes", a one-time nullifier, and the country if the policy
asks for it. On Midnight, that proof becomes a zero-knowledge proof checked by a Compact contract.

## Status

| Part | State |
|---|---|
| Live KYB checks (EU VIES, IBAN ISO 13616, name match, legal basis) | done, vendored from [kyb-evidence-desk](https://github.com/nathanielc3d/kyb-evidence-desk) |
| Credential issuer (Ed25519, salted subject commitment, holder commitment) | done, live on Cloudflare Workers |
| Verifier policies, scoped nullifiers, reference presentation | done (reference semantics, **not ZK**) |
| Test vectors for the circuit | done (`test-vectors/policy.json`) |
| Compact contract, ZK presentation, Preprod deployment, Lace flow | **Midnight Buildathon Wave 3** (from 2026-10-27), see [docs/MIDNIGHT_PLAN.md](docs/MIDNIGHT_PLAN.md) |

## How it works

```
holder (browser / agent)                 issuer (Worker)                         verifier
-----------------------                  ---------------                         --------
secret s (never sent)
commit_h = H("kyb-pass/holder|" s) ---->  VIES + IBAN + name checks
                                          evidence report (kept by holder)
                                          claims = {country, eu_vat_valid,
                                            decision, iban_sepa, issued_day,
                                            expires_day, ...}   (no VAT, no name, no IBAN)
                                          subject_commitment = H(VAT|salt)
                                          leaf = H(claims, commitments, evidence hash)
                    <-------------------  Ed25519 signature on leaf
                                          (Wave 3: leaf appended to Midnight Merkle tree)

present(policy, scope):
  satisfied? + nullifier = H(s|scope) + optional country  ------------------------->  policy ok,
  (Wave 3: zero-knowledge proof checked by the Compact contract)                      nullifier not seen before
```

- **Data minimisation (GDPR art. 5(1)(c))**: the signed leaf never contains the VAT number, the
  company name or the IBAN (tested).
- **Auditability on demand**: the holder keeps the full evidence report and the salt, and can open
  `subject_commitment` to an auditor or regulator.
- **No silent false negatives**: if VIES is busy or down, no credential is issued.
- **Unlinkability**: a nullifier depends on the holder secret and the scope, so two verifiers cannot
  link presentations of the same credential.
- **Not legal advice**: the checks cover VAT registration, IBAN structure and name consistency, not
  beneficial owners, sanctions or PEP screening.

## API

| Route | |
|---|---|
| `GET /` | demo page (secret generated in the browser) |
| `GET /.well-known/kyb-pass-issuer.json` | issuer id and Ed25519 public key |
| `GET /api/policies` | example verifier policies |
| `POST /api/issue` `{vat, iban?, name?, holder_commitment}` | runs the checks, returns `{credential, report}` |
| `POST /api/verify` `{credential}` | leaf recomputation + issuer signature |
| `POST /api/evaluate` `{claims, policy}` | reference policy evaluation |

```bash
# French VIES is often busy (MS_MAX_CONCURRENT_REQ): the API then refuses to issue rather than guess.
curl -s https://kyb-pass.moneymachine.workers.dev/api/issue -H 'content-type: application/json' \
  -d '{"vat":"DE811569869","holder_commitment":"0x'$(printf 'kyb-pass/holder|0x%064d' 1 | sha256sum | cut -c1-64)'"}'
```

## Run it

```bash
npm test                 # 15 tests, no network (VIES is mocked)
npm run vectors          # regenerate test-vectors/policy.json
npx wrangler dev         # local Worker (ephemeral issuer key)
node scripts/gen-issuer-key.mjs | npx wrangler secret put ISSUER_JWK   # persistent issuer key
```

Node 20+ (WebCrypto Ed25519). No dependencies.

## Layout

```
src/kyb/         live KYB checks (vendored, MIT)
src/credential.js  issuer: claims, commitments, leaf, Ed25519 signature, verification
src/policy.js      verifier policies, reference predicate, nullifiers, reference presentation
src/worker.js      Cloudflare Worker
test/              node:test suite
test-vectors/      reference vectors the Compact circuit must reproduce
docs/MIDNIGHT_PLAN.md  contract design for Wave 3
```

## License

Dual-licensed under MIT or Apache-2.0, at your option ([LICENSE-MIT](LICENSE-MIT),
[LICENSE-APACHE](LICENSE-APACHE)). Midnight-related code (contract and its tests) is
Apache-2.0, as the Midnight Buildathon requires.
