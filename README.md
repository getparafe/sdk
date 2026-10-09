# @getparafe/sdk

Node.js client SDK for the [Parafe](https://platform.parafe.ai) Trust Broker — the neutral trust infrastructure for agent-to-agent interactions.

## Install

```bash
npm install @getparafe/sdk
```

Requires Node.js 18+ (CI tests Node 22). Works with `import` and `require()` (in 0.12.0 and earlier, `require('@getparafe/sdk')` throws).

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
  principalName: 'Acme Corp',
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
// { loaded: true, agentId: 'prf_agent_...', agentName: '...', expiresAt: '...', expired: false }
```

### Trying the full flow on your own

A handshake needs two agents, and each `ParafeClient` holds one agent's credentials. To play both sides yourself, create two clients with the same API key:

```typescript
const initiator = new ParafeClient({ brokerUrl: 'https://api.parafe.ai', apiKey });
const target = new ParafeClient({ brokerUrl: 'https://api.parafe.ai', apiKey });
await initiator.register({ name: 'my-initiator', type: 'personal', principalName: 'Me' });
await target.register({ name: 'my-target', type: 'personal', principalName: 'Me', scopePolicies: { /* ... */ } });
```

Scope policies are enforced. The example above requires `minimum_verification_tier: 'email_verified'`, so a brand-new, unverified account will get `403 tier_insufficient` on `handshake()`. Verify your email in the [Developer Portal](https://platform.parafe.ai), then call `renewCredential(agentId)` so the agent picks up the new tier (reason `tier_changed`), or leave out `minimum_verification_tier` while you experiment.

A policy can also set floors on the initiator's reputation signals (0.6.0): `minimum_tenure_days`, `minimum_session_completion_rate` (0–1), `maximum_denied_requests_30d`, `minimum_unique_counterparties`, `minimum_handshake_success_rate` (0–1). A handshake below one is refused with its own code (`tenure_insufficient`, `completion_rate_insufficient`, `denied_requests_exceeded`, `counterparties_insufficient`, `handshake_success_rate_insufficient`) and `ForbiddenError.reputation` says which signal and by how much. Rates are 0 for an agent with no history. These numbers count dealings with any agent, so an operator can build them up with agents it runs itself (or from a second free account): pair a floor with a minimum verification tier. Counting only agents from platforms Parafé has verified is planned.

Agent names are unique per operator (per operator and user reference with `actsFor`), and a revoked agent's name is never reused: pick your own rather than copying the examples.

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
// An invalid, expired or revoked token, a token issued for another agent, or a bad proof,
// throws AuthError (err.code says which): check `permitted` on return.

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

**Proof of possession.** Wherever the SDK authenticates as your agent with its credential (`handshake()`, `escalateScope()`, `recordActionReceipt()`, `fileActionReceipt()`, `getActionReceipts()`, `closeSession()`, `getReceipt()`, `revokeAgent()`, `updateScopePolicies()`), it also signs a `Parafe-PoP` proof with the agent's private key, bound to that request. On api.parafe.ai, which requires proofs, a leaked credential is useless on its own. Nothing to do on your side.

**Key-bound consent tokens.** A consent token names the initiator (`sub`), the target (`aud`, its DID) and the initiator's key (`cnf.jkt`). When you present one to a target, attach a presentation proof so it can check you hold that key:

```typescript
const proof = await parafe.createPresentationProof(consentToken.token, a2aMessageId);
// Target side: verify it with the broker, or offline with @getparafe/a2a-extension
await target.verifyConsent({ consentToken: token, action: 'read_bookings', sessionId, presentationProof: proof });
// { valid: true, permitted: true, keyBound: true, proofVerified: true }
```

**What the receipt contains:** both participants (agent ID, DID, assurance, tier), mutual authentication and a hash of the handshake `context`, every consent token issued in the session (a hash of the token, scope, permissions, **exclusions**, authorization modality, a hash of the human's instruction rather than its text, and how the initiator proved itself: `pop` or `credential`), every action receipt filed in the session (its hash, who signed it, the action, the result and error code) with the index's chain head, and the session times and who closed it. The broker learns action names, results and business references, never request or response content. It does receive the handshake `context` and an `attested` instruction's text, kept on the session record (the receipt carries only their hashes).

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

## New in 0.14.0

Fixes from Parafé's behaviour checks of 2026-10-08. Two changes in behaviour: a consent token issued for another agent than the loaded one now throws `AuthError` (`wrong_audience`); pass `agentId: null` to check without it. And `ClaimStatus` no longer has `principalEmail` or `principalEmailVerified`: the broker stopped sharing a person's email on 2026-10-09.

- A consent token must be for the agent checking it. `verifyConsentLocally()` and `verifyConsent()` check that the token's target is the loaded agent (unless the loaded agent is the token's initiator), and refuse a token issued for another agent with `AuthError` code `wrong_audience`. Pass `agentId` to name the agent to check against, or `agentId: null` to skip the check. `verifyConsentLocally()` also returns `targetAgentId`. `verifyConsent()` also compares the token's target itself after the broker's answer, so an older broker (which ignores `agent_id`) can't pass a token issued for another agent.
- `verifyConsent()` refusals carry the broker's code: `token_expired`, `token_invalid`, `wrong_audience`, `session_mismatch`, `session_not_found`, `session_inactive`, `agent_revoked` or `proof_invalid` (`err.code`).
- `renewCredential()` writes the renewed credential back to the file `saveCredentials()` or `loadCredentials()` last used, if that file holds the agent being renewed, because the broker revokes the old one (`saved: true`; `saved: false` and `saveError` if the file couldn't be written, with the new credential still loaded). Credential files are written to a temporary file and renamed, so a crash never leaves half a file.
- With an API key, `renewCredential()` of the loaded agent falls back to the agent's own credential and proof when the broker answers `agent_renews_itself` (an agent with no operator renews only itself).
- `ValidationError` has `details` (each problem the broker found, e.g. in `register()`) and `unknownFields` (scope policy fields the broker doesn't know); when the broker sends only details, they are the message.
- `getAgentMetrics()` reads only your own agents' track record (the broker restricted it to the owner on 2026-10-08); without an API key it signs the request with the loaded agent's key.
- `verifyConsentLocally()` throws Parafé's `AuthError` for a token that doesn't check out, not the underlying library's error: code `invalid_signature` for a forged token (or one signed with a key the broker never published), `invalid_token` for a malformed one or another issuer. An expired token still returns `{ valid: false, expired: true }`.
- `evidenceSalt`: the session receipt's hash of an `attested` instruction (or an AP2 mandate) mixes in a random salt since 2026-10-09, so a short instruction can't be guessed from the receipt. The initiator gets the salt from `handshake()` (or `escalateScope()`'s `consentToken`), the target from `completeHandshake()`'s `consentToken`; keep it with the evidence to show what the hash covers.

## New in 0.13.0

- `register()` proves it holds the key it registers: it signs a `Parafe-PoP` proof with the new key. The broker requires this since 2026-10-08 (SPEC-003 part 4), so **earlier versions can no longer register agents**; agents already registered are unaffected. Update before registering new agents.
- `register()` makes a new key pair each time, so it always registers a new agent. It no longer retries on its own (a retry would resend the single-use proof); if it fails on a network error, call it again.
- `require('@getparafe/sdk')` works, and CommonJS TypeScript projects get types (0.12.0 threw, and TypeScript reported TS1479).
- A retried request signs a new proof (a proof is single use, so a retry used to be refused as replayed). A request that changes something is retried only when the broker can't have received it (a 502 or 503, or a connection that never opened); after a timeout or a 504 it throws, because the broker may have done it already.

## New in 0.12.0

- `waitForClaim()` waits for the person to approve the claim link and returns as soon as they do; `getClaimStatus({ waitSeconds })` asks the broker to wait (up to 60 seconds). Needs a broker from 2026-10-08 (api.parafe.ai and staging have it). See [Self-registered agents and claim links](#self-registered-agents-and-claim-links).

## Breaking in 0.11.0

- `pairingCode` is gone from claim links (`register().claimLink`, `createClaimLink()`, `ForbiddenError.claim`). The link's own `code` does the same job: tell the person the code with the link ("The page will show the code 7KQ2-M9XD-4H"); the claim page shows it first. Needs the broker from 2026-10-01 (later the same day as 0.10.0).

## New in 0.10.0

Needs a broker with agent naming and the claim page (Parafé SPEC-002 decision 10; api.parafe.ai since 2026-10-01). Nothing breaks.

- Without an API key, `register()` needs no `name` or `principalName`: `register({ type: 'personal' })`. A self-registered agent's public name is its agent ID (registry, credentials, receipts). If you send a name or principal, the person sees them only on the claim page ("Calls itself", "Says it acts for"); they're never in the credential. With an API key, `name` is still required and unique per operator.
- 0.10.1: `renewCredential()` also updates the stored agent name from the new credential (a self-registered agent's name becomes its agent ID).
- Credentials of self-registered agents no longer carry `principal_name` or the self-chosen name. Credentials issued before still do: `getClaimStatus()` reports `credentialCurrent: false` and `renewCredential()` gives one without them (reason `identity_changed`).

## Breaking in 0.9.0

Needs a broker with operator and principal (Parafé SPEC-002; api.parafe.ai since 2026-10-01). See [Operator and principal](#operator-and-principal-registering-for-your-users).

- `register({ owner })` is now `register({ principalName })`: who the agent acts for, as free text. The broker ignores `owner` (dropped silently). New, optional: `actsFor: { ref }` registers the agent for one of your users (you become its operator).
- `getClaimStatus()`: `ownerTier` → `principalTier`, `ownerEmail` → `principalEmail`, `ownerEmailVerified` → `principalEmailVerified`. New: `operatorType`, `operatorId`, `principalType`, `principalRef`. `claimed` is false for an agent acting for a platform's user that no person has claimed.
- `verifyMandate()`: the matched agent's `orgDomain` is now `operatorDomain` (the verified domain of the org that runs it).
- Credentials: the claims `owner`, `owner_type`, `owner_id` are now `principal_name`, `principal_type`, `principal_id`, plus `principal_ref`, `operator_type`, `operator_id`; a person's user ID is never in the JWT credential (the SD-JWT VC carries it as a selectively disclosable `principal_id`). Credentials issued before still say `owner` until they renew: call `getClaimStatus()` and renew when `credentialCurrent` is false.
- New, additive: `register()` returns `operatorType`, `operatorId`, `principalType`, `principalId`, `principalRef`; `completeHandshake()` and `verifyConsentLocally()` return `initiatorParties` / `targetParties`; receipts carry `participants.*.parties` (type `Parties`).

## Breaking in 0.8.0

- `register()` and `generateKeyPair()` create a **P-256** (ES256) key by default, the key type AP2 uses: an AP2 receipt counts as mandate-verified only when it is signed with the participant's registered P-256 key. Pass `keyAlgorithm: 'Ed25519'` for the old default; the broker accepts both. An agent keeps the key it registered with: to move an existing Ed25519 agent to P-256, register a new agent.

## Breaking in 0.7.0

- `ParafeClient.authorization.verified()` takes the user-signed AP2 mandate (`{ mandate, checkoutJwt?, checkoutHash?, checkoutMandate? }`) instead of `{ instruction, platform, userSignature }`. The old form was deprecated and the broker refused it; passing `userSignature` now throws.
- `ReceiptConsentToken.authorization.mandateRefs` is `MandateRef[]` (`{ family, closedJwt, sdHash }`) instead of `string[]` (it was always empty before).
- New, additive: `authorization.delegated()`, `verifyMandate()`, `signAp2Receipt()` / `recordAp2Receipt()`, `ap2MandateReferences()`, `mandateRefs` on consent tokens, and the A3 mandate check (`referenceVerified`, `mandateRef`, `mandateVerifiedBy`, `mandateIssuerSource`) on acknowledgments, index entries and receipt actions.

## Authorization Helpers

```typescript
// Autonomous — agent acting alone
ParafeClient.authorization.autonomous()

// Attested — agent claims a human issued this instruction. In a new handshake the
// target agent receives the instruction: write a short summary, without personal details.
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
  expectedAudience: myDid,      // your agent's DID (or agent ID): what the agent bound it to
  expectedNonce: quoteId,       // your own nonce for this purchase, e.g. the quote ID
  trustedIssuers: [{ jwk: providerPublicJwk, name: 'Example Agent Provider' }],
  sessionId,                    // optional: record it in the Parafé session
});
if (!r.valid) {
  // r.error is the AP2 error code for your Checkout Receipt; r.references gives its `reference`.
}
```

The broker checks the chain against the issuers you trust (plus its own list; never the broker's own keys), every constraint, and the checkout binding, refuses a "human present" mandate signed by a registered agent's key, and records the redemption: the same mandate, or another one for the same checkout, presented again returns `alreadyRedeemed: true`. `r.agent` names the registered Parafé agent whose key signed the mandate (human not present), with `isCounterparty` in a session. To verify offline instead, use `verifyAp2Mandate` from `@getparafe/verify`.

**What the mandate must say, when you're the merchant.** The shopping agent (or the user's app) builds the mandate; tell it these values:

| Field | Value |
|---|---|
| Checkout `merchant.id`, or payment `payee.id` | Your agent ID (`prf_agent_…`) or DID (`did:web:api.parafe.ai:agents:prf_agent_…`). Or `merchant.website` on your org's verified domain. For `delegated`, the user's allow-list entry (`allowed_merchants` / `allowed_payees`) must name you the same way. |
| The last hop's `aud` | Your DID or agent ID. At a handshake the broker refuses any other (`audience_mismatch`). |
| The last hop's `nonce` | Yours: something you issued for this purchase, e.g. the quote ID. The broker can't know it, so it doesn't check it at the handshake: check it yourself (`expectedNonce`). |

- **AP2 receipts need a P-256 key.** Checkout and Payment Receipts are ES256: one counts as signed by you (`issuerVerified`) only when your registered key is P-256. `register()` creates one by default since 0.8.0; an agent registered with Ed25519 must register a new agent.
- **A mandate the issuer signed directly must be fresh.** In AP2's human-present model the issuer (the user's Credential Provider) signs the closed mandate itself: there is no hop, so no `aud` or `nonce`. The broker accepts it for `verified` only if it was signed in the last 5 minutes; the merchant check and the one-time redemption stand in for `aud` and `nonce`. Passing `expectedAudience` or `expectedNonce` for such a mandate fails (`missing_audience`, `missing_nonce`): leave them out.

Once you've accepted or rejected the mandate, AP2 says you MUST return a Checkout Receipt (a payment processor: a Payment Receipt). Sign it as your agent (it needs a P-256 key, the default since 0.8.0) and file it in the session:

```typescript
const receipt = await parafe.recordAp2Receipt(sessionId, r.valid
  ? { kind: 'checkout', mandate, orderId }
  : { kind: 'checkout', mandate, error: r.error, errorDescription: r.message });
// return receipt.receipt to the shopping agent
```

AP2's spec and its SDK compute the receipt's `reference` differently; the receipt uses the AP2 SDK's form by default (`referenceForm: 'sd_hash'` for the spec's), and `receipt.references` gives both. The broker checks it against the mandates verified in the session: `ack.referenceVerified`, with `mandateVerifiedBy` and `mandateIssuerSource` (`scope_policy`, `broker` or `request`). A mandate checked at the handshake counts for both participants' receipts; one verified with `verifyMandate()` counts only for the receipts of the agent that verified it, and the other participant's verifications don't count for yours. Read `referenceVerified` with those two fields: it is as strong as the verifier's trust list. `scope_policy` (the risk-bearer's own list, at the handshake) is the strong case; `request` means the verifier chose the issuers itself.

## Agent Lifecycle

```typescript
// Revoke an agent
await parafe.revokeAgent('prf_agent_...');

// Renew the credential: re-issued when the principal's tier changed, when the
// credential no longer shows the agent's principal or operator (e.g. after a claim), or it is
// expired or within 7 days of expiry. Without an API key, the loaded agent renews itself
// (credential + proof of possession), even within a year after its credential expired
// (broker from 2026-10-08): renewal is the one thing an expired credential can still do. An agent with an
// operator can also be renewed with the operator's API key. The new credential is written
// back to the credential file.
await parafe.renewCredential('prf_agent_...');

// Update scope policies
await parafe.updateScopePolicies('prf_agent_...', {
  'new-scope': { permissions: ['read'], exclusions: ['delete'] },
});
```

## Operator and principal; registering for your users

An agent names an **operator** (who runs it and answers for it: the account whose API key registered it) and a **principal** (who it acts for). A self-registered agent has neither until someone claims it; then it has a principal and still no operator. A platform's agent (`actsFor`) keeps its operator when the person claims it. `register()` returns both (`operatorType`, `operatorId`, `principalType`, `principalId`, `principalRef`), and `getClaimStatus()` returns them without `principalId`. Consent tokens and receipts name both parties too (`initiatorParties`/`targetParties` from `verifyConsentLocally()` and `completeHandshake()`, `participants.*.parties` on receipts); they never show a person's user ID.

A platform registers an agent for one of its users with `actsFor`:

```typescript
const parafe = new ParafeClient({ brokerUrl: 'https://api.parafe.ai', apiKey: process.env.PARAFE_API_KEY });
const agent = await parafe.register({
  name: 'assistant-u42', type: 'personal', principalName: 'Platform user',
  actsFor: { ref: 'u42' }, // your opaque reference for the user
});
// agent.principalType === 'external', agent.operatorType === 'org' (with an org API key; 'personal' with a personal one),
// agent.verificationTier === 'unverified'
```

- The `ref` is opaque: letters, digits, `.` `_` `:` `-`, up to 128. Not an email (the broker refuses `@`): counterparties see the ref in consent tokens and receipts.
- Agent names are unique per (your account, ref), so every user can have an `assistant-…` of the same name.
- The agent starts `unverified` (a platform's word about its user carries no tier). The person can claim it with a claim link (`createClaimLink()`): it then acts for them, at their tier, and you still run it. They can see it in their portal and disconnect it, which takes it back to your reference, `unverified`.

## Self-registered agents and claim links

An agent can register with no API key: a personal assistant running on a platform, say. It starts `self_registered` and `unverified`, with no operator or principal. To be trusted by services that require more, it asks the person it acts for to claim it. That person opens a link, signs in to the Parafé portal (or creates an account), and approves. No secret passes through the AI. Approval needs a signed-in Parafé session, and until passkeys ship that is all it needs: software driving the person's signed-in browser could approve too (Parafé security finding S-63). The person is emailed on every claim and can revoke the agent from the portal. Read `claimed` as "a signed-in Parafé account approved this agent", not as proof of a fresh human step.

```typescript
const parafe = new ParafeClient({ brokerUrl: 'https://api.parafe.ai' }); // no apiKey

// 1. Register. A keyless registration comes with a claim link. No name needed:
//    the agent's public name is its agent ID.
const agent = await parafe.register({ type: 'personal' });
await parafe.saveCredentials('./alex-assistant.enc', process.env.PASSPHRASE!);
console.log(agent.claimLink);
// { url: 'https://platform.parafe.ai/claim?code=7KQ2-M9XD-4H', code: '7KQ2-M9XD-4H', expiresAt: '…' }

// 2. Show the person the link and tell them its code ("The page will show the code 7KQ2-M9XD-4H").
//    The claim page shows the code first, so they can check the link is yours.
//    It is single use and lasts 30 minutes; ask for a new one any time (it replaces the old one):
const link = await parafe.createClaimLink();

// 3. A service refuses the agent for its identity or tier? The error carries a link too.
try {
  await parafe.handshake({ targetAgentId: 'prf_agent_shop', scope: 'place-order', permissions: ['create_order'] });
} catch (err) {
  if (err instanceof ForbiddenError && err.claim) {
    // err.hint: "Ask the person you act for to open this link to verify you, and tell them its code."
    showToUser(err.claim.url, err.claim.code);
  }
}

// 4. Wait for the approval. The broker answers the moment they approve (each request
//    waits up to 25 seconds; gives up after 30 minutes, the link's life, and returns
//    the last status). Then the agent is theirs ('claimed', their verification tier).
//    Handshakes use this at once. Renew so the credential says it too.
const status = await parafe.waitForClaim();
if (!status.claimed) { /* timed out: createClaimLink() and show the new link */ }
// { claimed: true, identityAssurance: 'claimed', verificationTier: 'unverified',
//   principalTier: 'unverified', credentialCurrent: false, registeredAt: '2026-09-30T…',
//   operatorType: null, operatorId: null, principalType: 'personal', principalRef: null }
if (!status.credentialCurrent || status.principalTier !== status.verificationTier) {
  await parafe.renewCredential(agent.agentId); // reason 'identity_changed' or 'tier_changed'
}
```

- `claimed` meets a `minimum_identity_assurance: 'registered'` policy; `self_registered` does not.
- The agent gets the person's verification tier. If their email isn't verified yet, the tier rises once they verify it: check `getClaimStatus()` (`principalTier` above `verificationTier`) and renew.
- `waitForClaim({ timeoutMs, waitSeconds })` (0.12.0, a broker from 2026-10-08) asks the broker to hold each request until the claim is approved, so it needs few requests: platforms that put every outbound request behind an approval show few prompts. `getClaimStatus({ waitSeconds })` makes one such request. Don't poll `getClaimStatus()` every few seconds instead.
- `createClaimLink()`, `getClaimStatus()`, `waitForClaim()` and self-renewal authenticate as the agent (credential plus proof of possession). `createClaimLink()` answers 409 `already_claimed` once a person or org has claimed the agent.
- The person can revoke the agent from the portal like any of their agents.
- **What the person sees.** The claim page shows the link's code first, then "Platform: Unknown (self-registered)" (Parafé only names a platform it authenticated), and whatever the agent sent at registration as "Calls itself" (`name`) and "Says it acts for" (`principalName`), unverified. The person can give the agent a private name of their own; only they see it.
- **For an organization.** An owner or admin of an org can claim the agent for the org instead of for themselves. It then gets the org's verification tier and stays with the org if that person leaves it.
- **No email.** Parafé never gives the agent or its platform the person's email (removed 2026-10-09): a platform knows its own users, and an agent can ask its person.
- **Key fingerprint.** The claim page shows the agent's key fingerprint under "Details" (the link's code comes first). It is the RFC 7638 JWK thumbprint of the agent's public key: the 43-character base64url SHA-256 of the canonical JWK, shown in full, not grouped. It's the same value as a consent token's `cnf.jkt`. Show the identical string on your platform with `publicKeyThumbprint(agent.publicKey)`. Don't use the credential's `pub_key_thumbprint` claim: it's a different hash (hex SHA-256 of the base64 SPKI) and won't match.
- **Public record.** The registry's list (`GET /registry/agents`) shows a self-registered agent once a person has claimed it. `GET https://api.parafe.ai/registry/agents/<agent_id>` (no auth) returns `registered_at`, `status`, `verification_tier`, `identity_assurance`, `operator_type` (and `operator_name` for an org) and `principal_type` for an active agent (never a person's name or ID) (listed or unlisted). A revoked or suspended agent returns a minimal record: `agent_id`, `did`, `status`, `registered_at` and `revoked_at` (null for agents revoked before the broker recorded the date). `parafe.ai/registry/<agent_id>` shows the same.

## Reputation Metrics

Retrieve the raw trust signals (track record) of one of your own agents. Only the agent's owner can read them (broker from 2026-10-08): with an API key, an agent it manages (403 for others); without one, the loaded agent itself (signed with its key). Other agents' signals aren't public, and the registry no longer shows them: a shop sets minimums in its scope policies and the broker checks them at the handshake.

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
    // Refused for identity or tier, and no person has claimed the agent yet:
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

Offline checks (`verifyConsentLocally()`, `verifyReceiptLocally()`, `@getparafe/verify`) prove Parafé signed the artifact and it hasn't expired; they can't see revocation. Only the broker knows an agent was revoked: `verifyConsent()` (online) refuses its tokens at once. Consent tokens last 5 minutes, which bounds the gap.

- **Credential:** a JWT, plus (`credentialSdJwt`) the same identity as an **SD-JWT VC** that binds the agent's key (`cnf.jwk`), with `principal_name`/`principal_id`/`principal_ref` selectively disclosable and `operator_domain` when the operator is a domain-verified org. A person's user ID is never in the JWT credential; in the SD-JWT VC it is the selectively disclosable `principal_id`, which registration returns disclosed: drop that disclosure before presenting the credential to anyone.
- **Consent token (v2):** a JWT with `sub`, `aud`, `cnf.jkt`, `jti`, `exclusions` and `initiator_proof`.
- **Receipt (v2):** a compact JWS (`typ: parafe-session-receipt+jwt`). v1 receipts (signed JSON) still verify: `getReceipt()` returns them as `{ formatVersion: 1, issued }`.

The broker used to also return W3C-style `*_vdc` fields; they didn't verify with standard VC libraries and were removed on 2026-09-29.

## Release notes

The "New in" and "Breaking in" sections above cover 0.7.0 on; every version's notes are on [GitHub Releases](https://github.com/getparafe/sdk/releases).

## Running Tests

```bash
cd sdk/
npm install

# Unit tests only (no broker needed)
npm run test:unit

# Integration tests (requires a running Parafé broker — no API key needed; the broker
# isn't open source, and CI runs this suite against staging)
npm run test:integration

# Or point at a specific broker URL
PARAFE_TEST_BROKER_URL=http://localhost:3000 npm run test:integration
```

## Building

```bash
npm run build
# Outputs:
#   dist/esm/    — ES modules (Node ESM)
#   dist/cjs/    — CommonJS (marked with its own package.json)
#   dist/types/  — TypeScript declarations
```

## License

MIT — see [LICENSE](./LICENSE).
