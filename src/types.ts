/**
 * TypeScript interfaces for @parafe-trust/sdk
 */

// ── Client configuration ──

export interface ParafeClientOptions {
  brokerUrl: string;
  /** API key from the Parafe developer portal. Required for agent management operations. */
  apiKey?: string;
  /** HTTP timeout in milliseconds. Default: 10000 */
  timeout?: number;
  /** Number of retries on 5xx/network errors. Default: 3 */
  retries?: number;
}

// ── Authorization modalities ──

export interface AutonomousAuthorization {
  modality: 'autonomous';
}

export interface AttestedAuthorization {
  modality: 'attested';
  evidence: {
    instruction: string;
    platform: string;
    timestamp: string;
  };
}

/**
 * Evidence for 'verified' and 'delegated' (broker B8): an AP2 mandate the
 * broker checks against the issuers the target's scope trusts.
 */
export interface MandateEvidence {
  /** The AP2 mandate as presented: the `~~`-joined Delegate SD-JWT chain. */
  ap2_mandate: string;
  /** The merchant-signed Checkout JWT, when the checkout mandate doesn't disclose it (or the checkout a payment mandate pays). */
  checkout_jwt?: string;
  checkout_hash?: string;
  /** For a payment mandate: the checkout mandate chain it belongs to. */
  checkout_mandate?: string;
}

/** A closed mandate the user signed for this purchase (human present), checked by the broker. */
export interface VerifiedAuthorization {
  modality: 'verified';
  evidence: MandateEvidence;
}

/** An AP2 open-mandate chain closed with the initiator's own key (human not present), checked by the broker. */
export interface DelegatedAuthorization {
  modality: 'delegated';
  evidence: MandateEvidence;
}

export type Authorization = AutonomousAuthorization | AttestedAuthorization | DelegatedAuthorization | VerifiedAuthorization;

/** An AP2 mandate behind a consent token, by hash both ways (broker B8). */
export interface MandateRef {
  family: 'checkout' | 'payment';
  /** SHA-256 of the closed mandate JWT (the AP2 SDK's receipt reference). */
  closedJwt: string;
  /** sd_hash of the final SD-JWT as presented (the AP2 spec's). */
  sdHash: string;
}

// ── Scope policies ──

export interface ScopePolicy {
  permissions?: string[];
  exclusions?: string[];
  minimum_authorization_modality?: 'autonomous' | 'attested' | 'delegated' | 'verified';
  minimum_identity_assurance?: 'self_registered' | 'registered' | 'claimed';
  minimum_verification_tier?: 'unverified' | 'email_verified' | 'domain_verified' | 'org_verified';
  /** Require the initiator to prove it holds its key ('pop'), not just show its credential. */
  minimum_initiator_proof?: 'pop' | 'credential';
  /** Floors on the initiator's reputation signals (broker B18). Refused with `tenure_insufficient` etc. */
  minimum_tenure_days?: number;
  /** 0 to 1. Sessions closed / sessions started (0 with no history). */
  minimum_session_completion_rate?: number;
  /** Policy refusals of the initiator's requests in the last 30 days, at most. */
  maximum_denied_requests_30d?: number;
  minimum_unique_counterparties?: number;
  /** 0 to 1. Successful / all handshake events (0 with no history). */
  minimum_handshake_success_rate?: number;
  /** AP2 mandate issuers this scope accepts for 'delegated' and 'verified' (broker B8), as public JWKs. */
  ap2_trusted_issuers?: Ap2TrustedIssuer[];
  /** Informational; stored and returned, never enforced. Any other field is refused by the broker. */
  description?: string;
}

export type ScopePolicies = Record<string, ScopePolicy>;

// ── register() ──

/**
 * Broker SPEC-002: who runs an agent (operator) and who it acts for
 * (principal). A person's user ID is never shown: a personal operator or
 * principal has `type` only; an org has `id`; an external principal (one of a
 * platform's users) has the platform's opaque `ref`.
 */
export interface Parties {
  operator: { type: 'personal' | 'org'; id?: string } | null;
  principal: { type: 'personal' | 'org' | 'external'; id?: string; ref?: string } | null;
}

export interface RegisterOptions {
  /**
   * The agent's name. Required with an API key: unique per operator (you), never reused.
   * Without one (self-registration, broker SPEC-002 decision 10) it's optional and shown
   * only to the person on the claim page; the agent's public name is its agent ID.
   */
  name?: string;
  type: 'personal' | 'enterprise';
  /**
   * Who the agent acts for, as free text (at most 100 characters), optional. With an API key,
   * the account's own name is used (for actsFor, what you send for your user). Without one,
   * it's only what the agent says it acts for, shown on the claim page; the agent has no
   * principal name in its credential until a person claims it.
   */
  principalName?: string;
  /**
   * Register an agent acting for one of your users (needs an API key; you become its operator).
   * `ref` is your opaque reference for the user: 1-128 letters, digits, . _ : - (no `@`: the broker
   * refuses emails, because counterparties see the ref in consent tokens and receipts). The agent
   * starts unverified; the person can claim it (createClaimLink) to give it their tier.
   * Agent names are unique per (you, ref).
   */
  actsFor?: { ref: string };
  scopePolicies?: ScopePolicies;
  /** The agent's key type. Default 'P-256' (ES256, what AP2 uses); 'Ed25519' is also accepted. */
  keyAlgorithm?: 'Ed25519' | 'P-256';
}

export interface RegisterResult {
  agentId: string;
  /** did:web identifier of the agent */
  did?: string;
  credential: string;
  /** The same identity as an SD-JWT VC binding the agent's key (cnf.jwk). */
  credentialSdJwt?: string;
  publicKey: string;
  privateKey: string;
  verificationTier: string;
  identityAssurance: string;
  /** Who runs the agent: the account that registered it; null when keyless. */
  operatorType: 'personal' | 'org' | null;
  operatorId: string | null;
  /** Who it acts for: 'external' for one of your users (actsFor); null when keyless. */
  principalType: 'personal' | 'org' | 'external' | null;
  principalId: string | null;
  /** Your reference for the user (actsFor). */
  principalRef: string | null;
  issuedAt: string;
  expiresAt: string;
  /**
   * Keyless registrations only (no API key: the agent has no operator or principal). Show the
   * link to the person the agent acts for; once they approve it in the portal,
   * the agent is theirs (identity assurance 'claimed', their verification tier).
   */
  claimLink?: ClaimLink;
}

// ── Claim links (Phase 1.5) ──

/** A single-use link (30 minutes) for the person an unowned agent acts for. */
export interface ClaimLink {
  /** Portal URL to open, e.g. https://platform.parafe.ai/claim?code=7KQ2-M9XD-4H */
  url: string;
  /** The code, shown XXXX-XXXX-XX */
  code: string;
  /**
   * Show it to the person with the link (broker SPEC-002 decision 10, e.g. "K7-Q2"): the claim
   * page shows the same code, so they can check the link is yours before approving.
   */
  pairingCode: string;
  expiresAt: string;
}

export interface ClaimStatus {
  /** True once a person or org has approved a claim link (the agent has a principal who is a Parafé account). */
  claimed: boolean;
  /** Who runs the agent (null for a self-registered or claimed one). */
  operatorType: 'personal' | 'org' | null;
  operatorId: string | null;
  /** Who it acts for: 'external' for a platform's user not yet claimed (or disconnected). */
  principalType: 'personal' | 'org' | 'external' | null;
  principalRef: string | null;
  /** 'self_registered' before a claim, 'claimed' after ('registered' for an operator's agent). */
  identityAssurance: string;
  /** The agent's verification tier (handshakes use this at once). */
  verificationTier: string;
  /** The principal's current tier, or null with no verified principal. If higher, renew. */
  principalTier: string | null;
  /** False when the credential doesn't show the agent's current principal, operator, assurance or tier yet: call renewCredential(). */
  credentialCurrent: boolean;
  /** When the agent registered (ISO 8601). */
  registeredAt: string;
  /** The principal's email, only if they chose to share it with the operator (at the claim, or later in the portal). Never in the credential. */
  principalEmail?: string;
  /** Whether that email is verified (present with principalEmail). */
  principalEmailVerified?: boolean;
}

// ── Credential status ──

export type CredentialStatus =
  | { loaded: true; agentId: string; agentName: string; expiresAt: string; expired: boolean }
  | { loaded: false };

// ── exportKeys() ──

export interface ExportedKeys {
  publicKey: string;
  privateKey: string;
  credential: string;
}

// ── Internal credential store ──

export interface StoredCredentials {
  agentId: string;
  agentName: string;
  credential: string;
  /** SD-JWT VC identity credential (broker 2026-09-30+). */
  credentialSdJwt?: string;
  publicKey: string;
  privateKey: string;
  issuedAt: string;
  expiresAt: string;
}

// ── handshake() ──

export interface HandshakeOptions {
  targetAgentId: string;
  scope: string;
  permissions: string[];
  authorization?: Authorization;
  context?: Record<string, unknown>;
}

export interface HandshakeResult {
  handshakeId: string;
  challengeForTarget: string;
  expiresAt: string;
}

// ── completeHandshake() ──

export interface CompleteHandshakeOptions {
  handshakeId: string;
  challengeNonce: string;
}

export interface ConsentTokenDetail {
  token: string;
  scope: string;
  permissions: string[];
  exclusions: string[];
  authorization: Authorization;
  sessionId: string;
  issuedAt: string;
  expiresAt: string;
  /** How the initiator proved itself: 'pop' (proof signed with its key) or 'credential'. */
  initiatorProof?: 'pop' | 'credential' | null;
  /** The AP2 mandates behind 'delegated' / 'verified' (empty otherwise). */
  mandateRefs: MandateRef[];
}

export interface CompleteHandshakeResult {
  handshakeId: string;
  sessionId: string;
  consentToken: ConsentTokenDetail;
  /** Who runs each agent and who it acts for (broker SPEC-002). */
  initiatorParties?: Parties;
  targetParties?: Parties;
}

// ── escalateScope() ──

export interface EscalateScopeOptions {
  sessionId: string;
  targetAgentId: string;
  scope: string;
  permissions: string[];
  authorization?: Authorization;
}

export interface EscalateScopeResult {
  sessionId: string;
  consentToken: ConsentTokenDetail;
}

// ── verifyConsent() ──

export interface VerifyConsentOptions {
  consentToken: string;
  action: string;
  sessionId: string;
  /** The initiator's presentation proof, if it sent one; the broker checks it against the token's cnf.jkt. */
  presentationProof?: string;
}

export interface VerifyConsentResult {
  valid: boolean;
  action: string;
  permitted: boolean;
  sessionId: string;
  expiresAt?: string;
  reason?: string;
  /** The token is bound to the initiator's key (cnf.jkt). */
  keyBound?: boolean;
  /** A presentation proof was sent and checked. */
  proofVerified?: boolean;
}

// ── recordAction() ──

// ── Action receipts (B6) ──

/** Why an action was refused or failed (an action receipt's `error`). */
export type ActionErrorCode = 'not_permitted' | 'excluded' | 'consent_invalid' | 'consent_expired' | 'proof_invalid' | 'failed';

export type ReceiptKind = 'parafe.action_receipt' | 'ap2.checkout_receipt' | 'ap2.payment_receipt';

export interface SignActionReceiptOptions {
  sessionId: string;
  /** The consent token the action was requested under (the receipt carries its hash). */
  consentToken: string;
  /** The action, e.g. a permission name like `create_order`. */
  action: string;
  /** Default 'success'; 'error' needs `error`. */
  result?: 'success' | 'error';
  error?: ActionErrorCode;
  errorDescription?: string;
  /** The request message (bytes or string): the receipt carries its SHA-256 (`request_ref`). */
  request?: string | Uint8Array;
  /** Or the reference itself. */
  requestRef?: string;
  /** Details of what was done: the receipt carries only their hash (`details_hash`, JCS). */
  details?: unknown;
  detailsHash?: string;
  /** Your own reference for the outcome, e.g. an order ID. The broker sees it. */
  businessRef?: string;
  /** An AP2 closed-mandate hash, when the action was AP2-authorized. */
  mandateRef?: string;
}

/** The broker's signed acknowledgment that a receipt was indexed. */
export interface ActionReceiptAck {
  sessionId: string;
  seq: number;
  receiptHash: string;
  entryHash: string;
  /** The acknowledgment: a JWS signed by the broker (typ parafe-index-ack+jwt). */
  acknowledgment: string;
  /** Decoded from the acknowledgment. */
  claims: Record<string, unknown>;
  /** True when the receipt was already filed (by you or the other participant). */
  duplicate: boolean;
  /**
   * A3, for entries that name an AP2 mandate (an AP2 receipt's `reference`, an
   * action receipt's `mandateRef`); null otherwise. `referenceVerified`: it
   * matched a mandate that this receipt's issuer (or the handshake) verified in
   * the session; `mandateRef`: that closed-mandate hash; `mandateVerifiedBy`:
   * the agent that verified it; `mandateIssuerSource`: whose trust list it
   * passed (`scope_policy`, `broker`, or `request`: the verifier's own list).
   */
  referenceVerified: boolean | null;
  mandateRef: string | null;
  mandateVerifiedBy: string | null;
  mandateIssuerSource: string | null;
}

export interface RecordActionReceiptResult {
  /** The action receipt you signed (a JWS). Return it to the other agent too. */
  receipt: string;
  ack: ActionReceiptAck;
}

export interface SessionIndexEntry {
  seq: number;
  kind: ReceiptKind | string;
  /** The receipt exactly as filed. */
  receipt: string;
  receiptHash: string;
  receiptIss: string;
  issuerVerified: boolean;
  action: string;
  result: 'success' | 'error';
  error: string | null;
  businessRef: string | null;
  prev: string | null;
  entryHash: string;
  indexedAt: string;
  filedBy: string | null;
  acknowledgment: string;
  /**
   * A3, for entries that name an AP2 mandate (an AP2 receipt's `reference`, an
   * action receipt's `mandateRef`); null otherwise. `referenceVerified`: it
   * matched a mandate that this receipt's issuer (or the handshake) verified in
   * the session; `mandateRef`: that closed-mandate hash; `mandateVerifiedBy`:
   * the agent that verified it; `mandateIssuerSource`: whose trust list it
   * passed (`scope_policy`, `broker`, or `request`: the verifier's own list).
   */
  referenceVerified: boolean | null;
  mandateRef: string | null;
  mandateVerifiedBy: string | null;
  mandateIssuerSource: string | null;
}

export interface SessionIndex {
  sessionId: string;
  chainHead: string | null;
  entries: SessionIndexEntry[];
}

/** A session receipt's entry for a filed receipt. */
export interface ReceiptAction {
  seq: number;
  receiptHash: string;
  kind: ReceiptKind | string;
  /** The receipt's issuer (an agent DID, or an AP2 receipt's iss). */
  iss: string;
  issuerVerified: boolean;
  action: string;
  result: 'success' | 'error';
  error: string | null;
  /**
   * A3, for entries that name an AP2 mandate (an AP2 receipt's `reference`, an
   * action receipt's `mandateRef`); null otherwise. `referenceVerified`: it
   * matched a mandate that this receipt's issuer (or the handshake) verified in
   * the session; `mandateRef`: that closed-mandate hash; `mandateVerifiedBy`:
   * the agent that verified it; `mandateIssuerSource`: whose trust list it
   * passed (`scope_policy`, `broker`, or `request`: the verifier's own list).
   */
  referenceVerified: boolean | null;
  mandateRef: string | null;
  mandateVerifiedBy: string | null;
  mandateIssuerSource: string | null;
}

/** @deprecated `/interaction/record` is replaced by action receipts (`recordActionReceipt`). */
export interface RecordActionOptions {
  sessionId: string;
  agentId: string;
  action: string;
  details?: Record<string, unknown>;
  consentToken?: string;
}

export interface RecordActionResult {
  recorded: boolean;
  withinScope: boolean;
  actionId: string;
  action: string;
  timestamp: string;
}

// ── closeSession() / getReceipt() ──

export interface ReceiptParticipant {
  agentId: string;
  did?: string;
  agentName: string;
  identityAssurance: string;
  verificationTier?: string;
  /** Who runs the agent and who it acts for (broker SPEC-002). */
  parties?: Parties;
}

export interface ReceiptConsentToken {
  /** base64url(SHA-256(consent token JWS)) */
  tokenRef: string | null;
  scope: string;
  permissions: string[];
  exclusions: string[];
  authorization: {
    modality: Authorization['modality'];
    /** Hash of the evidence: the human's instruction, or the AP2 mandate (neither is on the receipt). */
    evidenceHash: string | null;
    /** The AP2 mandates behind 'delegated' / 'verified' (broker B8). */
    mandateRefs: MandateRef[];
  };
  initiatorProof: 'pop' | 'credential' | null;
  initiatorProofAt: string | null;
  issuedAt: string;
  expiresAt: string;
}

/**
 * A session receipt (v2). `receipt` is the evidence: a compact JWS signed by
 * the broker (ES256). Store or forward that string; the other fields are a
 * read-only view decoded from it.
 */
export interface SessionReceipt {
  formatVersion: 2;
  /** The receipt: compact JWS (typ parafe-session-receipt+jwt). */
  receipt: string;
  receiptId: string;
  sessionId: string;
  handshakeId: string;
  /** The broker's DID (the JWS `iss`). */
  issuer: string;
  issuedAt: string;
  participants: {
    initiator: ReceiptParticipant;
    target: ReceiptParticipant;
  };
  handshake: {
    mutualAuthCompleted: boolean;
    completedAt: string;
    contextHash: string | null;
  };
  consentTokens: ReceiptConsentToken[];
  /** Every receipt filed in the session's index, in order (B6). */
  actions: ReceiptAction[];
  /** The index chain head (entry hash of the last action), or null when none was filed. */
  chainHead: string | null;
  session: {
    startedAt: string;
    closedAt: string;
    closedBy: string | null;
    status: string;
  };
  /** The decoded JWS payload, unmodified. */
  claims: Record<string, unknown>;
}

/** A receipt issued before 2026-09-30 (v1: signed JSON), as `getReceipt()` returns it. */
export interface LegacySessionReceipt {
  formatVersion: 1;
  receiptId: string;
  sessionId: string;
  /** The receipt exactly as issued, with its `signature`. */
  issued: Record<string, unknown>;
}

// ── verifyConsentLocally() ──

export interface VerifyConsentLocalResult {
  valid: boolean;
  scope: string;
  permissions: string[];
  exclusions: string[];
  sessionId: string;
  expiresAt: string;
  expired: boolean;
  /** Initiator agent ID (`sub`). */
  initiatorAgentId?: string;
  /** Target agent DID (`aud`). */
  audience?: string;
  /** cnf.jkt: thumbprint of the key the token is bound to; null for tokens issued before key binding. */
  keyThumbprint: string | null;
  /** How the initiator proved itself when the token was issued. */
  initiatorProof: 'pop' | 'credential' | null;
  tokenId?: string;
  /** Who runs each agent and who it acts for (broker SPEC-002). */
  initiatorParties?: Parties;
  targetParties?: Parties;
}

// ── getPublicKey() / getJwks() ──

export interface BrokerPublicKey {
  publicKey: string;
  algorithm: string;
}

export interface BrokerJwks {
  keys: Array<{ kty: string; kid: string; alg: string; crv?: string; x?: string; y?: string; use?: string; status?: 'active' | 'retired'; [k: string]: unknown }>;
}

// ── verifyReceipt() ──

export interface VerifyReceiptResult {
  valid: boolean;
  signedBy: string | null;
  receiptId: string | null;
  tamperDetected: boolean;
  formatVersion?: 1 | 2;
  /** The verified payload (v2 receipts). */
  claims?: Record<string, unknown>;
  error?: string;
}

// ── revokeAgent() ──

export interface RevokeAgentResult {
  agentId: string;
  status: string;
  revokedAt: string;
}

// ── renewCredential() ──

export interface RenewCredentialResult {
  agentId: string;
  renewed: boolean;
  previousTier?: string;
  currentTier?: string;
  credential?: string;
  credentialSdJwt?: string;
  /** Why it was renewed: 'tier_changed', 'identity_changed' (e.g. after a claim), 'near_expiry' or 'expired'. */
  reason?: string;
  issuedAt?: string;
  expiresAt?: string;
  message?: string;
}

// ── updateScopePolicies() ──

export interface UpdateScopePoliciesResult {
  agentId: string;
  scopePolicies: ScopePolicies;
  updatedAt: string;
}

// ── getAgentMetrics() ──

export interface SessionMetrics {
  total: number;
  completed: number;
  expired: number;
  abandoned: number;
  completionRate: number;
}

export interface CounterpartyMetrics {
  totalUnique: number;
  asInitiator: number;
  asTarget: number;
}

export interface HandshakeMetrics {
  total: number;
  successful: number;
  failed: number;
  successRate: number;
}

export interface ScopeMetrics {
  uniqueScopes: string[];
  totalScopesUsed: number;
}

export interface DeniedScopeRequestMetrics {
  total: number;
  last30Days: number;
  byReason: Record<string, number>;
}

export interface ActionMetrics {
  totalRecorded: number;
  avgPerSession: number;
}

export interface AgentMetrics {
  agentId: string;
  computedAt: string;
  tenureDays: number;
  identityAssurance: string;
  sessions: SessionMetrics;
  counterparties: CounterpartyMetrics;
  handshakes: HandshakeMetrics;
  scopes: ScopeMetrics;
  deniedScopeRequests: DeniedScopeRequestMetrics;
  actions: ActionMetrics;
}

// ── AP2 mandates (verifyMandate(), broker A1) ──

/** An AP2 mandate issuer you trust: a Credential Provider or Agent Provider public key. */
export interface Ap2TrustedIssuer {
  /** A public JWK (EC P-256 in AP2). */
  jwk: { kty: string; crv?: string; x?: string; y?: string; kid?: string; [k: string]: unknown };
  kid?: string;
  iss?: string;
  name?: string;
}

/** The AP2 error codes to put in a Checkout or Payment Receipt. */
export type Ap2ErrorCode = 'invalid_credential' | 'unresolved_constraint' | 'invalid_mandate' | 'mandates_not_supported';

/** A receipt `reference` both ways until AP2 settles it: the spec's (sd_hash of the final SD-JWT) and the AP2 SDK's (SHA-256 of the closed mandate JWT). */
export interface Ap2References {
  sdHash: string;
  closedJwt: string;
}

export interface VerifyMandateOptions {
  /** The AP2 mandate as presented: the `~~`-joined Delegate SD-JWT chain. */
  mandate: string;
  /** Record the mandate in this session (the loaded agent must be a participant). */
  sessionId?: string;
  /** The verifying agent, when authenticating with its operator's API key instead of a loaded credential. */
  agentId?: string;
  /** The merchant-signed Checkout JWT, when the checkout mandate doesn't disclose it; for a payment mandate, the checkout it pays. */
  checkoutJwt?: string;
  /** Payment mandate: the expected `transaction_id`, if you don't hold the Checkout JWT. */
  checkoutHash?: string;
  /** Payment mandate: the checkout mandate chain it belongs to (verified too; supplies payment.reference). */
  checkoutMandate?: string;
  expectedAudience?: string;
  expectedNonce?: string;
  /** Issuers you accept, added to the broker's list. */
  trustedIssuers?: Ap2TrustedIssuer[];
  /** For payment.budget and payment.agent_recurrence: minor units spent, earlier uses, last use (Unix seconds). */
  context?: { totalAmount?: number; totalUses?: number; lastUsedAt?: number };
  /** Record the redemption (default true). A second redemption of the same mandate or checkout is refused. */
  redeem?: boolean;
}

export interface MandateAgentMatch {
  agentId: string;
  did: string;
  agentName: string;
  identityAssurance: string;
  verificationTier: string;
  /** The verified domain of the org that runs the agent (broker SPEC-002; was orgDomain). */
  operatorDomain?: string;
  /** In a session: whether the agent holding the mandate's key is your counterparty. */
  isCounterparty?: boolean;
}

export interface MandateRedemption {
  mandateId: string;
  family: 'checkout' | 'payment';
  mandateHash: string;
  transactionRef: string;
  verifierAgentId: string;
  sessionId: string | null;
  redeemedAt: string;
}

export interface VerifyMandateResult {
  valid: boolean;
  family: 'checkout' | 'payment' | null;
  mode: 'human_present' | 'human_not_present' | null;
  /** When invalid: the AP2 error code for your receipt, a more specific reason, and the failed constraints. */
  error?: Ap2ErrorCode;
  reason?: string;
  message?: string;
  violations?: string[];
  /** True when the broker refused a second redemption (reason `already_redeemed`). */
  alreadyRedeemed: boolean;
  references: Ap2References | null;
  /** The redemption key: SHA-256 of the closed mandate JWT. */
  mandateHash: string | null;
  issuer?: { kid?: string; iss?: string; name?: string; jkt: string; source: string | null };
  audience?: string | null;
  nonce?: string | null;
  presentedAt?: string | null;
  checkoutHash?: string | null;
  transactionId?: string | null;
  closedMandate?: Record<string, unknown>;
  openMandates?: Record<string, unknown>[];
  agentKeyThumbprint?: string | null;
  /**
   * Who signed the closed mandate: `issuer` (the trusted issuer itself),
   * `credential_holder` (the holder of a trusted credential, in AP2's User
   * Credential model normally the user) or `open_mandate_key` (an agent).
   */
  closedBy?: 'issuer' | 'credential_holder' | 'open_mandate_key' | null;
  closedByKeyThumbprint?: string | null;
  /** Who signed the first open mandate (the user's limits), in the same terms: `issuer` or `credential_holder`. */
  openedBy?: 'issuer' | 'credential_holder' | null;
  openedByKeyThumbprint?: string | null;
  /** The registered Parafé agent whose key is the mandate's agent key (human not present). */
  agent: MandateAgentMatch | null;
  redemption: MandateRedemption | null;
}

// ── AP2 receipts (signAp2Receipt(), A3) ──

export interface SignAp2ReceiptOptions {
  kind: 'checkout' | 'payment';
  /** The mandate the receipt answers, as presented; or pass `references`. */
  mandate?: string;
  references?: Ap2References;
  /** Which form goes in `reference`. Default 'closed_jwt' (what the AP2 SDK checks); 'sd_hash' for the spec's. */
  referenceForm?: 'closed_jwt' | 'sd_hash';
  /** The receipt's issuer (the merchant or payment processor). Default: the agent's DID. */
  iss?: string;
  /** Default 'Success', or 'Error' when `error` is set. */
  status?: 'Success' | 'Error';
  /** The AP2 error code, e.g. from verifyMandate(): invalid_credential, unresolved_constraint, invalid_mandate. */
  error?: string;
  errorDescription?: string;
  /** Checkout, Success. */
  orderId?: string;
  /** Payment: always. */
  paymentId?: string;
  /** Payment, Success. */
  pspConfirmationId?: string;
  networkConfirmationId?: string;
}

export interface Ap2Receipt {
  /** The receipt JWT (ES256). Return it to the shopping agent. */
  receipt: string;
  kind: 'ap2.checkout_receipt' | 'ap2.payment_receipt';
  reference: string;
  references: Ap2References;
  claims: Record<string, unknown>;
}

// ── Encrypted credential file format ──

export interface EncryptedCredentialFile {
  version: 1;
  algorithm: 'aes-256-gcm';
  salt: string;
  iv: string;
  tag: string;
  ciphertext: string;
}
