// Prints a fresh Ed25519 issuer private JWK on stdout, to pipe into `wrangler secret put ISSUER_JWK`.
// Example: node scripts/gen-issuer-key.mjs | npx wrangler secret put ISSUER_JWK
import { generateIssuerKey } from "../src/credential.js";
process.stdout.write(JSON.stringify((await generateIssuerKey()).privateJwk));
