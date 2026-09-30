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

export interface VerifiedAuthorization {
  modality: 'verified';
  evidence: {
    instruction: string;
    platform: string;
    user_signature: string;
    timestamp: string;
  };
}

export type Authorization = AutonomousAuthorization | AttestedAuthorization | VerifiedAuthorization;

// ── Scope policies ──

export interface ScopePolicy {
  permissions?: string[];
  exclusions?: string[];
  minimum_authorization_modality?: 'autonomous' | 'attested' | 'verified';
  minimum_identity_assurance?: 'self_registered' | 'registered';
  minimum_verification_tier?: 'unverified' | 'email_verified' | 'domain_verified' | 'org_verified';
  /** Require the initiator to prove it holds its key ('pop'), not just show its credential. */
  minimum_initiator_proof?: 'pop' | 'credential';
  /** Informational; stored and returned, never enforced. Any other field is refused by the broker. */
  description?: string;
}

export type ScopePolicies = Record<string, ScopePolicy>;

// ── register() ──

export interface RegisterOptions {
  name: string;
  type: 'personal' | 'enterprise';
  owner: string;
  scopePolicies?: ScopePolicies;
  /** The agent's key type. Default 'Ed25519'; 'P-256' (ES256) is what AP2 uses. */
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
  issuedAt: string;
  expiresAt: string;
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
}

export interface CompleteHandshakeResult {
  handshakeId: string;
  sessionId: string;
  consentToken: ConsentTokenDetail;
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
}

export interface ReceiptConsentToken {
  /** base64url(SHA-256(consent token JWS)) */
  tokenRef: string | null;
  scope: string;
  permissions: string[];
  exclusions: string[];
  authorization: {
    modality: Authorization['modality'];
    /** Hash of the human's instruction (the text itself is not on the receipt). */
    evidenceHash: string | null;
    mandateRefs: string[];
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
  /** Per-action receipts (Phase 2); empty for now. */
  actions: unknown[];
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
  /** Why it was renewed: 'tier_changed', 'near_expiry' or 'expired'. */
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

// ── Encrypted credential file format ──

export interface EncryptedCredentialFile {
  version: 1;
  algorithm: 'aes-256-gcm';
  salt: string;
  iv: string;
  tag: string;
  ciphertext: string;
}
