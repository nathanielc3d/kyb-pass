# Midnight integration plan (Midnight Buildathon, Wave 3)

Status on 2026-10-24: **no Midnight code yet, on purpose.** The Buildathon rules say the
Midnight-related functionality must be newly developed during the Wave being judged. Wave 3 builds
from 2026-10-27 to 2026-11-16. Everything in this repo before that date is the off-chain issuer
(pre-existing code is allowed) and the reference semantics that the contract has to match.

Toolchain checked on the build machine: Compact CLI 0.5.3, compiler 0.31.1 (`compact update 0.31`),
the version the docs give for current public networks.

## What the contract does

`contract/kyb_pass.compact` (Apache-2.0):

| Ledger state | Type (planned) | Purpose |
|---|---|---|
| `issuer` | issuer public key / admin commitment | only the issuer can add credentials |
| `credentials` | historic Merkle tree of credential leaves | membership without revealing which leaf |
| `revoked` | set of revocation tags | issuer revokes without revealing the subject |
| `nullifiers` | set of `Bytes<32>` | one presentation per (holder, scope), no linkage across scopes |
| `policies` | map policy hash → policy | verifiers register what they ask for |

| Circuit | Who | What it proves or changes |
|---|---|---|
| `register_policy(policy)` | verifier | stores a policy (countries bitmap, decision, SEPA, max age) |
| `add_credential(leaf)` | issuer | appends a leaf; checks the caller is the issuer |
| `revoke(tag)` | issuer | adds a revocation tag |
| `present(policy_hash, scope, today)` | holder | in zero knowledge: "I know a credential leaf in the tree, its holder secret, and its claims satisfy this policy". Discloses only the nullifier, the policy hash, the scope and (if the policy asks) the country. Inserts the nullifier. |

Private inputs (witnesses, TypeScript): holder secret, claims, Merkle path, subject commitment,
evidence hash. They never leave the holder's machine.

## Mapping from the off-chain reference

- `credentialLeaf()` (SHA-256 over canonical JSON today) becomes `persistentHash` over a Compact
  struct with the same fields: country (2 bytes), eu_vat_valid, decision (enum), iban_sepa
  (0 none / 1 SEPA / 2 non-SEPA), issued_day, expires_day, subject commitment, holder commitment,
  evidence hash. The issuer keeps signing the leaf with Ed25519 for off-chain provenance.
- `evaluatePolicy()` becomes the body of `present`. `test-vectors/policy.json` (generated from the
  reference) is the acceptance test for the circuit: every vector must give the same result in the
  Compact simulator.
- `nullifier()` becomes `persistentHash(["kyb-pass/nullifier", holder_secret, scope])`.

## Wave 3 deliverables (for the judges' rubric)

1. Compact contract that compiles (technical gate), with private state for the holder.
2. Simulator tests (`contract/test/*.test.ts`) running all vectors + double-spend of a nullifier,
   revoked credential, wrong issuer, expired credential.
3. Deployment on Midnight Preprod (free tDUST from the faucet), contract address in the README.
4. Front end: the existing issuer page plus a "Present with Midnight" step (Lace wallet), and a
   verifier page that reads the nullifier set.
5. Slide deck and a 2-3 minute demo video.
