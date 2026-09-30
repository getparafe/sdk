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

A policy can also set floors on the initiator's reputation signals (0.6.0): `minimum_tenure_days`, `minimum_session_completion_rate` (0–1), `maximum_denied_requests_30d`, `minimum_unique_counterparties`, `minimum_handshake_success_rate` (0–1). A handshake below one is refused with its own code (`tenure_insufficient`, `completion_rate_insufficient`, `denied_requests_exceeded`, `counterparties_insufficient`, `handshake_success_rate_insufficient`) and `ForbiddenError.reputation` says which signal and by how much. Rates are 0 for an agent with no history.

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

### Verify consent and receipt each action

```typescript
// Verify an action is permitted
const check = await parafe.verifyConsent({
  consentToken: consentToken.token,
  action: 'read_bookings',
  sessionId,
});
// { valid: true, permitted: true, action: 'read_bookings' }

// The agent that performs (or refuses) an action signs an action receipt and
// files it with the broker, which indexes it for the session
const { receipt: actionReceipt, ack } = await parafe.recordActionReceipt({
  sessionId,
  consentToken: consentToken.token,  // the token the action was requested under
  action: 'read_bookings',
  details: { bookingRef: 'BK-001' },  // only its hash goes on the receipt
  businessRef: 'BK-001',              // your reference; the broker sees it
});
// ack.seq: its place in the session's index; ack.acknowledgment: the broker's signed JWS.
// Return actionReceipt to the other agent: either side may file it (a duplicate returns the same ack).

// Refusals get a receipt too
await parafe.recordActionReceipt({ sessionId, consentToken: consentToken.token, action: 'delete_booking', result: 'error', error: 'excluded' });

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

**Proof of possession.** Wherever the SDK authenticates as your agent with its credential (`handshake()`, `escalateScope()`, `recordActionReceipt()`, `fileActionReceipt()`, `getActionReceipts()`, `closeSession()`, `getReceipt()`, `revokeAgent()`, `updateScopePolicies()`), it also signs a `Parafe-PoP` proof with the agent's private key, bound to that request. A leaked credential is useless on its own. Nothing to do on your side.

**Key-bound consent tokens.** A consent token names the initiator (`sub`), the target (`aud`, its DID) and the initiator's key (`cnf.jkt`). When you present one to a target, attach a presentation proof so it can check you hold that key:

```typescript
const proof = await parafe.createPresentationProof(consentToken.token, a2aMessageId);
// Target side: verify it with the broker, or offline with @getparafe/a2a-extension
await target.verifyConsent({ consentToken: token, action: 'read_bookings', sessionId, presentationProof: proof });
// { valid: true, permitted: true, keyBound: true, proofVerified: true }
```

**What the receipt contains:** both participants (agent ID, DID, assurance, tier), mutual authentication and a hash of the handshake `context`, every consent token issued in the session (a hash of the token, scope, permissions, **exclusions**, authorization modality, a hash of the human's instruction rather than its text, and how the initiator proved itself: `pop` or `credential`), every action receipt filed in the session (its hash, who signed it, the action, the result and error code) with the index's chain head, and the session times and who closed it. The broker learns action names, results and business references, never request or response content.

**Action receipts (0.6.0).** `signActionReceipt()` signs a receipt with your agent's key (`typ: parafe-action-receipt+jwt`); `fileActionReceipt(sessionId, receipt)` files it (yours, the other agent's, or an AP2 Checkout/Payment Receipt with `{ kind: 'ap2.checkout_receipt' }`); `recordActionReceipt()` does both; `getActionReceipts(sessionId)` lists the session's index. File before the session is closed: a receipt filed after close is refused. Error codes: `not_permitted`, `excluded`, `consent_invalid`, `consent_expired`, `proof_invalid` (a consent check failed) and `failed` (you tried and it failed). `recordAction()` (`/interaction/record`) is deprecated; the broker answers 410 since 2026-09-30. If a language model decides which tools to call, tell it to attempt the tool and let your consent check refuse: a model that declines on its own leaves no refusal receipt.

> For third parties who receive a Parafe receipt but don't want the full SDK, [`@getparafe/verify`](https://github.com/getparafe/verify) is a minimal standalone package that offers the same offline verification for credentials, consent tokens, and receipts, plus action receipts and the session index (`verifyActionReceipt`, `verifySessionIndex`). Give it `receipt.receipt` (the JWS). No Parafe account required; works in Node and browsers.

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

// Delegated — an AP2 open mandate the user signed (the limits), closed with this agent's key
ParafeClient.authorization.delegated({ mandate })

// Verified — an AP2 closed mandate the user signed for this purchase
ParafeClient.authorization.verified({ mandate, checkoutJwt })
```

`delegated` and `verified` (broker B8) carry an [AP2](https://github.com/google-agentic-commerce/AP2) v0.2 mandate, as presented (the `~~`-joined Delegate SD-JWT chain). The broker checks it against the issuers the target's scope trusts (`ap2_trusted_issuers` in its scope policy); the mandate's merchant or payee must be the target, and each mandate is used once. `delegated` also needs the open mandate to endorse this agent's own key. From weakest to strongest: `autonomous` < `attested` < `delegated` < `verified`. The consent token and the session receipt list the mandates by hash (`mandateRefs`). A bare signature string is refused.

## AP2 mandates

If your agent is a merchant (or a credential provider) and a shopping agent presents an [AP2](https://github.com/google-agentic-commerce/AP2) v0.2 Checkout or Payment Mandate, the broker can check it for you:

```typescript
const r = await parafe.verifyMandate({
  mandate,                      // as presented: the ~~-joined Delegate SD-JWT chain
  checkoutJwt,                  // the Checkout JWT you signed, if the mandate doesn't disclose it
  expectedAudience: 'merchant', // what you asked the agent to bind it to
  expectedNonce,
  trustedIssuers: [{ jwk: providerPublicJwk, name: 'Example Agent Provider' }],
  sessionId,                    // optional: record it in the Parafé session
});
if (!r.valid) {
  // r.error is the AP2 error code for your Checkout Receipt; r.references gives its `reference`.
}
```

The broker checks the chain against the issuers you trust (plus its own list), every constraint, and the checkout binding, and records the redemption: the same mandate, or another one for the same checkout, presented again returns `alreadyRedeemed: true`. `r.agent` names the registered Parafé agent whose key signed the mandate (human not present), with `isCounterparty` in a session. To verify offline instead, use `verifyAp2Mandate` from `@getparafe/verify`.

## Agent Lifecycle

```typescript
// Revoke an agent
await parafe.revokeAgent('prf_agent_...');

// Renew the credential: re-issued when the owner's tier changed, when the
// credential no longer shows the agent's owner (e.g. after a claim), or it is
// expired or within 7 days of expiry. Without an API key, the loaded agent renews itself
// (credential + proof of possession).
await parafe.renewCredential('prf_agent_...');

// Update scope policies
await parafe.updateScopePolicies('prf_agent_...', {
  'new-scope': { permissions: ['read'], exclusions: ['delete'] },
});
```

## Self-registered agents and claim links

An agent can register with no API key: a personal assistant running on a platform, say. It starts `self_registered` and `unverified`, with no owner. To be trusted by services that require more, it asks the person it acts for to claim it. That person opens a link, signs in to the Parafé portal (or creates an account), and approves. No secret passes through the AI: the link only works for someone signed in who approves it.

```typescript
const parafe = new ParafeClient({ brokerUrl: 'https://api.parafe.ai' }); // no apiKey

// 1. Register. A keyless registration comes with a claim link.
const agent = await parafe.register({ name: 'alex-assistant', type: 'assistant', owner: 'Alex' });
await parafe.saveCredentials('./alex-assistant.enc', process.env.PASSPHRASE!);
console.log(agent.claimLink);
// { url: 'https://platform.parafe.ai/claim?code=7KQ2-M9XD-4H', code: '7KQ2-M9XD-4H', expiresAt: '…' }

// 2. Show the link to the person. It is single use and lasts 30 minutes;
//    ask for a new one any time (it replaces the old one):
const link = await parafe.createClaimLink();

// 3. A service refuses the agent for its identity or tier? The error carries a link too.
try {
  await parafe.handshake({ targetAgentId: 'prf_agent_shop', scope: 'place-order', permissions: ['create_order'] });
} catch (err) {
  if (err instanceof ForbiddenError && err.claim) {
    // err.hint: "Ask the person you act for to open this link to verify you."
    showToUser(err.claim.url);
  }
}

// 4. After they approve: the agent is theirs ('claimed', their verification tier).
//    Handshakes use this at once. Renew so the credential says it too.
const status = await parafe.getClaimStatus();
// { claimed: true, identityAssurance: 'claimed', verificationTier: 'unverified',
//   ownerTier: 'unverified', credentialCurrent: false }
if (!status.credentialCurrent || status.ownerTier !== status.verificationTier) {
  await parafe.renewCredential(agent.agentId); // reason 'identity_changed' or 'tier_changed'
}
```

- `claimed` meets a `minimum_identity_assurance: 'registered'` policy; `self_registered` does not.
- The agent gets the person's verification tier. If their email isn't verified yet, the tier rises once they verify it: check `getClaimStatus()` (`ownerTier` above `verificationTier`) and renew.
- `createClaimLink()`, `getClaimStatus()` and self-renewal authenticate as the agent (credential plus proof of possession). `createClaimLink()` answers 409 `already_claimed` once the agent has an owner.
- The person can revoke the agent from the portal like any of their agents.

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
  if (err instanceof ForbiddenError && err.claim) {
    // Refused for identity or tier, and the agent has no owner:
    // show err.claim.url to the person it acts for (see claim links above)
  }
  if (err instanceof ForbiddenError && err.reputation) {
    // Refused by a reputation floor in the target's scope policy (0.6.0), e.g.
    // err.code 'tenure_insufficient', err.reputation { signal: 'tenure_days', required: 30, actual: 2 }
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
