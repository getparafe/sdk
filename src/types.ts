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
  agent_id: string;
  agent_name: string;
  identity_assurance: string;
}

export interface ReceiptConsentToken {
  scope: string;
  permissions: string[];
  authorization: { modality: string; evidence: unknown };
  issued_at: string;
  expired_at: string;
}

export interface SessionReceipt {
  receipt_id: string;
  session_id: string;
  handshake_id: string;
  participants: {
    initiator: ReceiptParticipant;
    target: ReceiptParticipant;
  };
  handshake: {
    handshake_id: string;
    mutual_auth_completed: boolean;
    completed_at: string;
  };
  consent_tokens: ReceiptConsentToken[];
  session: {
    started_at: string;
    closed_at: string;
    status: string;
  };
  signed_by: string;
  issued_at: string;
  signature: string;
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

// ── Encrypted credential file format ──

export interface EncryptedCredentialFile {
  version: 1;
  algorithm: 'aes-256-gcm';
  salt: string;
  iv: string;
  tag: string;
  ciphertext: string;
}
