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
}

export type ScopePolicies = Record<string, ScopePolicy>;

// ── register() ──

export interface RegisterOptions {
  name: string;
  type: 'personal' | 'enterprise';
  owner: string;
  scopePolicies?: ScopePolicies;
}

export interface RegisterResult {
  agentId: string;
  credential: string;
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
}

export interface VerifyConsentResult {
  valid: boolean;
  action: string;
  permitted: boolean;
  sessionId: string;
  expiresAt?: string;
  reason?: string;
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

// ── closeSession() ──

export interface ReceiptParticipant {
  agentId: string;
  agentName: string;
  identityAssurance: string;
}

export interface ReceiptConsentToken {
  scope: string;
  permissions: string[];
  authorization: Authorization;
  issuedAt: string;
  expiredAt: string;
}

export interface SessionReceipt {
  receiptId: string;
  sessionId: string;
  handshakeId: string;
  participants: {
    initiator: ReceiptParticipant;
    target: ReceiptParticipant;
  };
  handshake: {
    handshakeId: string;
    mutualAuthCompleted: boolean;
    completedAt: string;
  };
  consentTokens: ReceiptConsentToken[];
  session: {
    startedAt: string;
    closedAt: string;
    status: string;
  };
  signedBy: string;
  issuedAt: string;
  signature: string;
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
}

// ── getPublicKey() ──

export interface BrokerPublicKey {
  publicKey: string;
  algorithm: string;
}

// ── verifyReceipt() ──

export interface VerifyReceiptResult {
  valid: boolean;
  signedBy: string | null;
  receiptId: string | null;
  tamperDetected: boolean;
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
