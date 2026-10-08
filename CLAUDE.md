# @getparafe/sdk

Official Node.js/TypeScript SDK for the Parafe Trust Broker. Published on npm as `@getparafe/sdk`.

## Project Structure

- `src/index.ts` — Main `ParafeClient` class. All broker API methods (registration, handshake, consent, receipts, metrics).
- `src/http.ts` — HTTP client with retry logic (502/503/504), exponential backoff, AbortController timeouts.
- `src/crypto.ts` — Agent key generation (Ed25519 or P-256; SPKI DER public, PKCS8 DER private), challenge signing, proof-of-possession JWTs (`signProof`, `createPresentationProof`).
- `src/credentials.ts` — Credential encryption at rest via AES-256-GCM. Save/load from disk.
- `src/errors.ts` — Error class hierarchy (`ParafeError` → `AuthError`, `ForbiddenError`, `NotFoundError`, etc.).
- `src/types.ts` — TypeScript type definitions for all broker API types.
- `tests/` — Jest. `client.test.ts` is the integration suite (needs a running broker, `PARAFE_TEST_BROKER_URL`); the rest are unit tests (`npm run test:unit` runs seven of them; `ap2-mandates.test.ts`, which stubs fetch, runs only with `npm test`).

## Running

```bash
npm install
npm run build          # Builds CJS + ESM + types (three tsconfig files)
npm run test:unit      # Unit tests, no broker
npm test               # All Jest tests, including the integration suite (needs a broker)
```

## Key Design Decisions

- **Dual module output** — Builds to both CJS (`dist/cjs/`) and ESM (`dist/esm/`) via separate tsconfig files. `package.json` has `main` (CJS), `module` (ESM), and `types` exports. Known bug (CODE_REVIEW P-48): with `"type": "module"` and no `dist/cjs/package.json`, `require()` loads the CJS build as ESM and throws.
- **snake_case → camelCase** — Broker API uses snake_case. SDK normalizes everything to camelCase for TypeScript consumers. This happens consistently in `index.ts`.
- **Credential encryption** — `credentials.ts` uses AES-256-GCM with a passphrase-derived key. Credentials are encrypted before writing to disk, decrypted on load.
- **Broker keys** — `verifyConsentLocally` and `verifyReceiptLocally` resolve broker keys from the JWKS (`getJwks()`, cached 5 min, falls back to `/public-key` on a pre-2026-09-30 broker). The legacy base64 SPKI key is still accepted; it's wrapped in PEM headers without re-encoding.
- **Proof of possession (0.4.0)** — every call that authenticates with the agent's credential also sends a `Parafe-PoP` header signed with its key (`proofHeader`/`agentHttpOpts`). Keep this for any new credential-authenticated method.
- **Receipts are JWS (0.4.0)** — `SessionReceipt.receipt` is the evidence; the rest is decoded from it. Never rebuild or re-serialize a receipt.
- **Action receipts (0.6.0)** — `signActionReceipt` signs with the agent key (`kid` = `<agent DID>#keys-1`; the DID comes from the SD-JWT credential, else the agent's DID document); `fileActionReceipt` treats a 409 `duplicate_receipt` as success (`duplicate: true`, the original acknowledgment). `recordAction` (`/interaction/record`) always fails: the broker answers 410 since 2026-09-30.
- **Retry logic** — `http.ts` retries on 502/503/504 and network errors or timeouts with exponential backoff (200ms * 2^attempt). 4xx and 500 fail immediately. Retries resend the same `Parafe-PoP` (CODE_REVIEW P-49).

## When Making Changes

- If adding a new broker API method, add it to `ParafeClient` in `index.ts`, add types to `types.ts`, and add tests.
- Maintain snake_case → camelCase normalization for any new response types.
- The `verifyConsentLocally` method does offline ES256/EdDSA verification — test carefully if modifying crypto paths.
- Run `npm test` and `npm run build` before pushing. Published via GitHub Actions on release.
- This SDK is a dependency of `@getparafe/mcp-server`. `@getparafe/a2a-extension` does not depend on it (only `jose`), but its docs show the two used together. Breaking changes affect downstream packages.
