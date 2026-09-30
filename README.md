# @getparafe/sdk

Node.js client SDK for the [Parafe](https://platform.parafe.ai) Trust Broker — the neutral trust infrastructure for agent-to-agent interactions.

## Install

```bash
npm install @getparafe/sdk
```

Requires Node.js 18+.

## Quickstart

```typescript
import { ParafeClient } from '@getparafe/sdk';

// 1. Initialize the client
const parafe = new ParafeClient({
  brokerUrl: 'https://api.parafe.ai',
  apiKey: 'prf_key_live_...', // From the Parafe Developer Portal
});

// 2. Register your agent (once — generates its key pair internally)
const agent = await parafe.register({
  name: 'my-travel-agent',       // lowercase alphanumeric + hyphens, 3–100 chars
  type: 'enterprise',             // 'personal' or 'enterprise'
  owner: 'Acme Corp',
  keyAlgorithm: 'P-256',          // Optional: 'Ed25519' (default) or 'P-256' (ES256, the key type AP2 uses)
  scopePolicies: {               // Optional: declare what scopes this agent accepts
    'flight-rebooking': {
      permissions: ['read_bookings', 'search_alternatives', 'request_rebooking'],
      exclusions: ['cancel_booking', 'charge_payment'],
      minimum_authorization_modality: 'attested',
      minimum_verification_tier: 'email_verified',
    },
  },
});
// agent.agentId, agent.did, agent.credential, agent.credentialSdJwt, agent.publicKey, agent.privateKey, ...

// 3. Save credentials to an encrypted file (AES-256-GCM + scrypt)
await parafe.saveCredentials('./parafe-credentials.enc', 'your-passphrase');

// 4. On subsequent runs, load them back
await parafe.loadCredentials('./parafe-credentials.enc', 'your-passphrase');

// 5. Check credential state
const status = parafe.credentialStatus();
// { loaded: true, agentId: 'prf_agent_...', expiresAt: '...', expired: false }
```

### Trying the full flow on your own

A handshake needs two agents, and each `ParafeClient` holds one agent's credentials. To play both sides yourself, create two clients with the same API key:

```typescript
const initiator = new ParafeClient({ brokerUrl: 'https://api.parafe.ai', apiKey });
const target = new ParafeClient({ brokerUrl: 'https://api.parafe.ai', apiKey });
await initiator.register({ name: 'my-initiator', type: 'personal', owner: 'Me' });
await target.register({ name: 'my-target', type: 'personal', owner: 'Me', scopePolicies: { /* ... */ } });
```

Scope policies are enforced. The example above requires `minimum_verification_tier: 'email_verified'`, so a brand-new, unverified account will get `403 tier_insufficient` on `handshake()`. Verify your email in the [Developer Portal](https://platform.parafe.ai), or leave out `minimum_verification_tier` while you experiment.

Agent names must be unique — pick your own rather than copying the examples.

## Handshake Flow

### Initiator side

```typescript
const { handshakeId, challengeForTarget } = await parafe.handshake({
  targetAgentId: 'prf_agent_target01',
  scope: 'flight-rebooking',
  permissions: ['read_bookings', 'search_alternatives'],
  authorization: ParafeClient.authorization.attested({
    instruction: 'User requested flight rebooking via chat',
    platform: 'acme-travel-app',
  }),
  context: { userId: 'alex-mercer' }, // Optional
});

// Send handshakeId + challengeForTarget to the target agent via your transport
```

### Target side

```typescript
const { sessionId, consentToken } = await parafe.completeHandshake({
  handshakeId,                // Received from initiator
  challengeNonce,             // The challengeForTarget value
  // SDK signs the nonce internally with your stored private key
});
```

### Verify consent and record actions

```typescript
// Verify an action is permitted
const check = await parafe.verifyConsent({
  consentToken: consentToken.token,
  action: 'read_bookings',
  sessionId,
});
// { valid: true, permitted: true, action: 'read_bookings' }

// Record an action (logged on the session; see "What the receipt contains" below)
await parafe.recordAction({
  sessionId,
  agentId: agent.agentId,
  action: 'read_bookings',
  details: { bookingRef: 'BK-001' },
  consentToken: consentToken.token,
});

// Close the session — returns the signed receipt
const receipt = await parafe.closeSession(sessionId);
// receipt.receipt is the evidence: a compact JWS signed by the broker (ES256).
// The other fields (receiptId, participants, consentTokens, session, ...) are decoded from it.

// The other participant fetches the same receipt
const same = await otherParafe.getReceipt(sessionId);

// Verify it: with the broker, or offline against the broker's JWKS
const verification = await parafe.verifyReceipt(receipt);
// { valid: true, tamperDetected: false, signedBy: 'did:web:api.parafe.ai', formatVersion: 2 }
const offline = await parafe.verifyReceiptLocally(receipt);
```

**Proof of possession.** Wherever the SDK authenticates as your agent with its credential (`handshake()`, `escalateScope()`, `recordAction()`, `closeSession()`, `getReceipt()`, `revokeAgent()`, `updateScopePolicies()`), it also signs a `Parafe-PoP` proof with the agent's private key, bound to that request. A leaked credential is useless on its own. Nothing to do on your side.

**Key-bound consent tokens.** A consent token names the initiator (`sub`), the target (`aud`, its DID) and the initiator's key (`cnf.jkt`). When you present one to a target, attach a presentation proof so it can check you hold that key:

```typescript
const proof = await parafe.createPresentationProof(consentToken.token, a2aMessageId);
// Target side: verify it with the broker, or offline with @getparafe/a2a-extension
await target.verifyConsent({ consentToken: token, action: 'read_bookings', sessionId, presentationProof: proof });
// { valid: true, permitted: true, keyBound: true, proofVerified: true }
```

**What the receipt contains:** both participants (agent ID, DID, assurance, tier), mutual authentication and a hash of the handshake `context`, every consent token issued in the session (a hash of the token, scope, permissions, **exclusions**, authorization modality, a hash of the human's instruction rather than its text, and how the initiator proved itself: `pop` or `credential`), and the session times and who closed it. It does **not** yet list the actions recorded with `recordAction()`: per-action receipts come next (Phase 2).

> For third parties who receive a Parafe receipt but don't want the full SDK, [`@getparafe/verify`](https://github.com/getparafe/verify) is a minimal standalone package that offers the same offline verification for credentials, consent tokens, and receipts. Give it `receipt.receipt` (the JWS). No Parafe account required; works in Node and browsers.

## Scope Escalation

Request additional scope within an existing session without re-handshaking:

```typescript
const escalated = await parafe.escalateScope({
  sessionId,
  targetAgentId: 'prf_agent_target01',
  scope: 'payment-processing',
  permissions: ['charge_card'],
  authorization: ParafeClient.authorization.attested({
    instruction: 'User confirmed payment of $247',
    platform: 'acme-payments',
  }),
});
```

## Authorization Helpers

```typescript
// Autonomous — agent acting alone
ParafeClient.authorization.autonomous()

// Attested — agent claims a human issued this instruction
ParafeClient.authorization.attested({
  instruction: 'User clicked "Rebook"',
  platform: 'acme-app',
  timestamp: new Date().toISOString(), // Optional, defaults to now
})

```

`ParafeClient.authorization.verified()` is deprecated. The broker refuses `verified` with `400 verified_evidence_unverifiable`: it can't check a bare signature string, so it won't vouch for one. `verified` will require a user-signed AP2 mandate that the broker verifies. Until then, use `attested`, and note that a scope requiring `verified` can't be reached.

## Agent Lifecycle

```typescript
// Revoke an agent
await parafe.revokeAgent('prf_agent_...');

// Renew the credential: re-issued when the owner's tier changed, or it is expired
// or within 7 days of expiry. Without an API key, the loaded agent renews itself
// (credential + proof of possession).
await parafe.renewCredential('prf_agent_...');

// Update scope policies
await parafe.updateScopePolicies('prf_agent_...', {
  'new-scope': { permissions: ['read'], exclusions: ['delete'] },
});
```

## Reputation Metrics

Retrieve raw trust signals for any agent — useful for assessing trustworthiness before interacting, especially with self-registered agents.

```typescript
const metrics = await parafe.getAgentMetrics('prf_agent_...');

// metrics.tenureDays          — days since first session
// metrics.sessions.completionRate  — completed / total (0–1)
// metrics.counterparties.totalUnique — distinct agents interacted with
// metrics.handshakes.successRate    — successful / total (0–1)
// metrics.deniedScopeRequests.last30Days — rejected consent requests in last 30 days
// metrics.actions.totalRecorded     — total actions logged across all sessions
```

Returns raw signals, not a composite score — your agent decides how to weight them.

## Error Handling

The SDK throws typed errors matching the broker's error codes:

```typescript
import {
  ParafeError,
  ValidationError,
  AuthError,
  ForbiddenError,
  NotFoundError,
  ConflictError,
  ExpiredError,
  RateLimitError,
  InternalError,
} from '@getparafe/sdk';

try {
  await parafe.handshake({ ... });
} catch (err) {
  if (err instanceof AuthError) {
    // err.code — broker error string (e.g. 'invalid_credential')
    // err.statusCode — HTTP status (401)
    // err.message — human-readable description
  }
  if (err instanceof RateLimitError) {
    // Back off and retry
  }
}
```

## API Key Format

API keys issued by the broker follow this format:

```
prf_key_live_user_<64 hex chars>   # personal key
prf_key_live_org_<64 hex chars>    # organization key
```

- Prefix: `prf_key_live_user_` or `prf_key_live_org_` — identifies a Parafe live API key and whether it belongs to you or to an organization. Older keys use the bare `prf_key_live_<64 hex>` form and keep working.
- Suffix: 64 random hex characters (32 bytes)
- The `key_prefix` field returned at creation contains the first 21 characters, useful for display in UIs without exposing the full key
- Keys carry permission scopes. The starter key issued at signup can read and register agents; create a key in the Developer Portal for anything more.

Keys are shown **once** at creation and stored as SHA-256 hashes — they cannot be recovered. Use the Developer Portal to generate replacements.

## Credential formats

Since 2026-09-30 the broker signs with ES256 and publishes its keys at `/.well-known/jwks.json`; every token names its key (`kid`). `getJwks()` fetches them (cached), and `verifyConsentLocally()` uses them. Tokens and v1 receipts from before are Ed25519 and still verify (`getPublicKey()` returns that retired key).

- **Credential:** a JWT, plus (`credentialSdJwt`) the same identity as an **SD-JWT VC** that binds the agent's key (`cnf.jwk`), with `owner`/`owner_id` selectively disclosable and `org_domain` for domain-verified orgs.
- **Consent token (v2):** a JWT with `sub`, `aud`, `cnf.jkt`, `jti`, `exclusions` and `initiator_proof`.
- **Receipt (v2):** a compact JWS (`typ: parafe-session-receipt+jwt`). v1 receipts (signed JSON) still verify: `getReceipt()` returns them as `{ formatVersion: 1, issued }`.

The broker used to also return W3C-style `*_vdc` fields; they didn't verify with standard VC libraries and were removed on 2026-09-29.

## Running Tests

```bash
cd sdk/
npm install

# Unit tests only (no broker needed)
npm run test:unit

# Integration tests (requires a running broker — no API key needed)
npm run test:integration

# Or point at a specific broker URL
PARAFE_TEST_BROKER_URL=http://localhost:3000 npm run test:integration
```

## Building

```bash
npm run build
# Outputs:
#   dist/esm/    — ES modules (Node ESM)
#   dist/cjs/    — CommonJS
#   dist/types/  — TypeScript declarations
```

## License

MIT — see [LICENSE](./LICENSE).
