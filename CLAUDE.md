# @getparafe/sdk

Official Node.js/TypeScript SDK for the Parafe Trust Broker. Published on npm as `@getparafe/sdk`.

## Project Structure

- `src/index.ts` — Main `ParafeClient` class. All broker API methods (registration, handshake, consent, receipts, metrics).
- `src/http.ts` — HTTP client with retry logic (502/503/504), exponential backoff, AbortController timeouts.
- `src/crypto.ts` — Ed25519 key generation (SPKI DER public, PKCS8 DER private), challenge signing.
- `src/credentials.ts` — Credential encryption at rest via AES-256-GCM. Save/load from disk.
- `src/errors.ts` — Error class hierarchy (`ParafeError` → `AuthError`, `ForbiddenError`, `NotFoundError`, etc.).
- `src/types.ts` — TypeScript type definitions for all broker API types.
- `tests/` — Unit tests (`client.test.ts`, `credentials.test.ts`, `crypto.test.ts`).

## Running

```bash
npm install
npm run build          # Builds CJS + ESM + types (three tsconfig files)
npm test               # Jest tests
```

## Key Design Decisions

- **Dual module output** — Builds to both CJS (`dist/cjs/`) and ESM (`dist/esm/`) via separate tsconfig files. `package.json` has `main` (CJS), `module` (ESM), and `types` exports.
- **snake_case → camelCase** — Broker API uses snake_case. SDK normalizes everything to camelCase for TypeScript consumers. This happens consistently in `index.ts`.
- **Credential encryption** — `credentials.ts` uses AES-256-GCM with a passphrase-derived key. Credentials are encrypted before writing to disk, decrypted on load.
- **SPKI PEM construction** — `index.ts:560-567` wraps base64 SPKI DER in PEM headers for `verifyConsentLocally`. There is an explicit comment not to re-encode — this is correct and intentional.
- **Retry logic** — `http.ts` retries on 502/503/504 with exponential backoff (200ms * 2^attempt). Other errors fail immediately.

## When Making Changes

- If adding a new broker API method, add it to `ParafeClient` in `index.ts`, add types to `types.ts`, and add tests.
- Maintain snake_case → camelCase normalization for any new response types.
- The `verifyConsentLocally` method does offline Ed25519 verification — test carefully if modifying crypto paths.
- Run `npm test` and `npm run build` before pushing. Published via GitHub Actions on release.
- This SDK is a dependency of `@getparafe/mcp-server`. `@getparafe/a2a-extension` does not depend on it (only `jose`), but its docs show the two used together. Breaking changes affect downstream packages.
