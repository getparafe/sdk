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

// 2. Register your agent (once — generates Ed25519 key pair internally)
const agent = await parafe.register({
  name: 'my-travel-agent',       // lowercase alphanumeric + hyphens, 3–100 chars
  type: 'enterprise',             // 'personal' or 'enterprise'
  owner: 'Acme Corp',
  scopePolicies: {               // Optional: declare what scopes this agent accepts
    'flight-rebooking': {
      permissions: ['read_bookings', 'search_alternatives', 'request_rebooking'],
      exclusions: ['cancel_booking', 'charge_payment'],
      minimum_authorization_modality: 'attested',
      minimum_verification_tier: 'email_verified',
    },
  },
});
// agent.agentId, agent.credential, agent.publicKey, agent.privateKey, ...

// 3. Save credentials to an encrypted file (AES-256-GCM + scrypt)
await parafe.saveCredentials('./parafe-credentials.enc', 'your-passphrase');

// 4. On subsequent runs, load them back
await parafe.loadCredentials('./parafe-credentials.enc', 'your-passphrase');

// 5. Check credential state
const status = parafe.credentialStatus();
// { loaded: true, agentId: 'prf_agent_...', expiresAt: '...', expired: false }
```

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

// Record an action
await parafe.recordAction({
  sessionId,
  agentId: agent.agentId,
  action: 'read_bookings',
  details: { bookingRef: 'BK-001' },
  consentToken: consentToken.token,
});

// Close the session — returns a signed receipt
const receipt = await parafe.closeSession(sessionId);

// Independently verify the receipt
const verification = await parafe.verifyReceipt(receipt);
// { valid: true, tamperDetected: false, signedBy: 'parafe-broker' }
```

## Scope Escalation

Request additional scope within an existing session without re-handshaking:

```typescript
const escalated = await parafe.escalateScope({
  sessionId,
  targetAgentId: 'prf_agent_target01',
  scope: 'payment-processing',
  permissions: ['charge_card'],
  authorization: ParafeClient.authorization.verified({
    instruction: 'User confirmed payment of $247',
    platform: 'acme-payments',
    userSignature: '<cryptographic proof>',
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

// Verified — cryptographic proof of human approval
ParafeClient.authorization.verified({
  instruction: 'User confirmed $247 charge',
  platform: 'acme-payments',
  userSignature: '<base64 signature>',
  timestamp: new Date().toISOString(), // Optional, defaults to now
})
```

## Agent Lifecycle

```typescript
// Revoke an agent
await parafe.revokeAgent('prf_agent_...');

// Renew credential to pick up org's current verification tier
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
prf_key_live_<64 hex chars>
```

- Prefix: `prf_key_live_` (13 characters) — identifies the key as a Parafe live API key
- Suffix: 64 random hex characters (32 bytes)
- Total length: 77 characters
- The `key_prefix` field returned at creation contains the first 21 characters (prefix + 8 hex chars), useful for display in UIs without exposing the full key

Keys are shown **once** at creation and stored as SHA-256 hashes — they cannot be recovered. Use the Developer Portal to generate replacements.

## Verifiable Digital Credentials (VDC)

The broker returns all trust artifacts in dual format:

| Artifact | JWT field | VDC field |
|----------|-----------|-----------|
| Agent credential | `credential` | `credential_vdc` |
| Consent token | `consent_token.token` | `consent_token.token_vdc` |
| Receipt | `signature` | `receipt_vdc` |

The SDK works with the JWT fields. If you need W3C Verifiable Credential format (e.g., for interop with other trust frameworks), use the `_vdc` fields from the raw broker API response.

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
