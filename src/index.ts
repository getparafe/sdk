/**
 * @parafe-trust/sdk — Parafe Trust Broker Client SDK
 *
 * Usage:
 *   import { ParafeClient } from '@parafe-trust/sdk';
 *
 *   const parafe = new ParafeClient({
 *     brokerUrl: 'https://parafe-production-9bc9.up.railway.app',
 *     apiKey: 'prf_key_live_...',
 *   });
 */

import { generateKeyPair, signChallenge } from './crypto.js';
import { encryptCredentials, decryptCredentials } from './credentials.js';
import { request } from './http.js';
import { ValidationError } from './errors.js';
import type {
  ParafeClientOptions,
  Authorization,
  ScopePolicies,
  StoredCredentials,
  RegisterOptions,
  RegisterResult,
  CredentialStatus,
  ExportedKeys,
  HandshakeOptions,
  HandshakeResult,
  CompleteHandshakeOptions,
  CompleteHandshakeResult,
  ConsentTokenDetail,
  EscalateScopeOptions,
  EscalateScopeResult,
  VerifyConsentOptions,
  VerifyConsentResult,
  RecordActionOptions,
  RecordActionResult,
  SessionReceipt,
  VerifyReceiptResult,
  RevokeAgentResult,
  RenewCredentialResult,
  UpdateScopePoliciesResult,
} from './types.js';

// Re-export everything consumers need
export { ValidationError, AuthError, ForbiddenError, NotFoundError,
         ConflictError, ExpiredError, RateLimitError, InternalError,
         ParafeError } from './errors.js';
export { generateKeyPair, signChallenge } from './crypto.js';
export * from './types.js';

// ─── Authorization helpers ────────────────────────────────────────────────────

const authorization = {
  /**
   * Autonomous authorization — agent acting alone without human instruction.
   */
  autonomous(): Authorization {
    return { modality: 'autonomous' };
  },

  /**
   * Attested authorization — agent claims a human issued this instruction.
   * Timestamp defaults to now if omitted.
   */
  attested(opts: { instruction: string; platform: string; timestamp?: string }): Authorization {
    if (!opts.instruction) {
      throw new ValidationError('instruction is required for attested authorization', 'validation_error');
    }
    if (!opts.platform) {
      throw new ValidationError('platform is required for attested authorization', 'validation_error');
    }
    return {
      modality: 'attested',
      evidence: {
        instruction: opts.instruction,
        platform: opts.platform,
        timestamp: opts.timestamp ?? new Date().toISOString(),
      },
    };
  },

  /**
   * Verified authorization — cryptographic proof of human approval.
   * Timestamp defaults to now if omitted.
   * Note: output key is `user_signature` (snake_case) as expected by the broker.
   */
  verified(opts: {
    instruction: string;
    platform: string;
    userSignature: string;
    timestamp?: string;
  }): Authorization {
    if (!opts.instruction) {
      throw new ValidationError('instruction is required for verified authorization', 'validation_error');
    }
    if (!opts.platform) {
      throw new ValidationError('platform is required for verified authorization', 'validation_error');
    }
    if (!opts.userSignature) {
      throw new ValidationError('userSignature is required for verified authorization', 'validation_error');
    }
    return {
      modality: 'verified',
      evidence: {
        instruction: opts.instruction,
        platform: opts.platform,
        user_signature: opts.userSignature,
        timestamp: opts.timestamp ?? new Date().toISOString(),
      },
    };
  },
};

// ─── ParafeClient ─────────────────────────────────────────────────────────────

export class ParafeClient {
  private readonly brokerUrl: string;
  private readonly apiKey: string;
  private readonly timeout: number;
  private readonly retries: number;

  /** Currently loaded credentials (null when not registered or loaded) */
  private credentials: StoredCredentials | null = null;

  /** Static namespace for authorization helpers */
  static readonly authorization = authorization;

  constructor(opts: ParafeClientOptions) {
    if (!opts.brokerUrl) throw new ValidationError('brokerUrl is required', 'validation_error');

    this.brokerUrl = opts.brokerUrl.replace(/\/$/, ''); // strip trailing slash
    this.apiKey = opts.apiKey ?? '';
    this.timeout = opts.timeout ?? 10_000;
    this.retries = opts.retries ?? 3;
  }

  // ── Private helpers ──────────────────────────────────────────────────────────

  private get httpOpts() {
    return {
      timeout: this.timeout,
      retries: this.retries,
      headers: { Authorization: `Bearer ${this.apiKey}` },
    };
  }

  private requireCredentials(): StoredCredentials {
    if (!this.credentials) {
      throw new ValidationError(
        'No credentials loaded. Call register() or loadCredentials() first.',
        'no_credentials'
      );
    }
    return this.credentials;
  }

  // ── Agent registration ───────────────────────────────────────────────────────

  /**
   * Generate an Ed25519 key pair, register a new agent with the broker,
   * and store the returned credentials in memory.
   */
  async register(opts: RegisterOptions): Promise<RegisterResult> {
    const { name, type, owner, scopePolicies } = opts;

    // Generate key pair
    const { publicKey, privateKey } = generateKeyPair();

    // Build request body (broker uses snake_case)
    const body: Record<string, unknown> = {
      agent_name: name,
      agent_type: type,
      owner,
      public_key: publicKey,
    };
    if (scopePolicies) {
      body.scope_policies = scopePolicies;
    }

    // POST /agents/register
    const raw = await request<{
      agent_id: string;
      agent_name: string;
      agent_type: string;
      owner: string;
      identity_assurance: string;
      verification_tier: string;
      credential: string;
      issued_at: string;
      expires_at: string;
    }>(`${this.brokerUrl}/agents/register`, {
      ...this.httpOpts,
      method: 'POST',
      body,
    });

    // Store in memory
    this.credentials = {
      agentId: raw.agent_id,
      agentName: raw.agent_name,
      credential: raw.credential,
      publicKey,
      privateKey,
      issuedAt: raw.issued_at,
      expiresAt: raw.expires_at,
    };

    return {
      agentId: raw.agent_id,
      credential: raw.credential,
      publicKey,
      privateKey,
      verificationTier: raw.verification_tier,
      identityAssurance: raw.identity_assurance,
      issuedAt: raw.issued_at,
      expiresAt: raw.expires_at,
    };
  }

  // ── Credential persistence ───────────────────────────────────────────────────

  /**
   * Save the currently loaded credentials to an AES-256-GCM encrypted file.
   */
  async saveCredentials(filePath: string, passphrase: string): Promise<void> {
    const creds = this.requireCredentials();
    await encryptCredentials(filePath, creds, passphrase);
  }

  /**
   * Load credentials from an AES-256-GCM encrypted file into memory.
   */
  async loadCredentials(filePath: string, passphrase: string): Promise<void> {
    this.credentials = await decryptCredentials(filePath, passphrase);
  }

  /**
   * Inspect the current in-memory credential state without making a network call.
   */
  credentialStatus(): CredentialStatus {
    if (!this.credentials) return { loaded: false };

    const expired = new Date() > new Date(this.credentials.expiresAt);
    return {
      loaded: true,
      agentId: this.credentials.agentId,
      agentName: this.credentials.agentName,
      expiresAt: this.credentials.expiresAt,
      expired,
    };
  }

  /**
   * Export the raw key material from in-memory credentials.
   * Throws ValidationError if no credentials are loaded.
   */
  exportKeys(): ExportedKeys {
    const creds = this.requireCredentials();
    return {
      publicKey: creds.publicKey,
      privateKey: creds.privateKey,
      credential: creds.credential,
    };
  }

  // ── Handshake (initiator side) ───────────────────────────────────────────────

  /**
   * Initiate a new handshake with a target agent.
   * The broker returns a challenge nonce that the target must sign.
   */
  async handshake(opts: HandshakeOptions): Promise<HandshakeResult> {
    const creds = this.requireCredentials();

    const body: Record<string, unknown> = {
      initiator_credential: creds.credential,
      target_agent_id: opts.targetAgentId,
      requested_scope: opts.scope,
      requested_permissions: opts.permissions,
    };

    if (opts.authorization) {
      body.authorization = opts.authorization;
    }
    if (opts.context) {
      body.context = opts.context;
    }

    const raw = await request<{
      handshake_id: string;
      challenge_for_target: string;
      expires_at: string;
    }>(`${this.brokerUrl}/handshake/initiate`, {
      ...this.httpOpts,
      method: 'POST',
      body,
    });

    return {
      handshakeId: raw.handshake_id,
      challengeForTarget: raw.challenge_for_target,
      expiresAt: raw.expires_at,
    };
  }

  // ── Handshake (target side) ──────────────────────────────────────────────────

  /**
   * Complete a handshake as the target agent.
   * The SDK signs the challenge nonce internally using the stored private key.
   */
  async completeHandshake(opts: CompleteHandshakeOptions): Promise<CompleteHandshakeResult> {
    const creds = this.requireCredentials();

    // Sign the challenge nonce with the stored private key
    const challengeResponse = signChallenge(opts.challengeNonce, creds.privateKey);

    const raw = await request<{
      handshake_id: string;
      session: { session_id: string };
      consent_token: {
        token: string;
        scope: string;
        permissions: string[];
        exclusions: string[];
        authorization: Authorization;
        session_id: string;
        issued_at: string;
        expires_at: string;
      };
    }>(`${this.brokerUrl}/handshake/complete`, {
      ...this.httpOpts,
      method: 'POST',
      body: {
        handshake_id: opts.handshakeId,
        target_credential: creds.credential,
        challenge_response: challengeResponse,
      },
    });

    const ct = raw.consent_token;
    const consentToken: ConsentTokenDetail = {
      token: ct.token,
      scope: ct.scope,
      permissions: ct.permissions,
      exclusions: ct.exclusions ?? [],
      authorization: ct.authorization,
      sessionId: ct.session_id,
      issuedAt: ct.issued_at,
      expiresAt: ct.expires_at,
    };

    return {
      handshakeId: raw.handshake_id,
      sessionId: raw.session.session_id,
      consentToken,
    };
  }

  // ── Scope escalation ─────────────────────────────────────────────────────────

  /**
   * Request additional scope within an existing session without re-handshaking.
   * Uses the same /handshake/initiate endpoint with session_id included.
   */
  async escalateScope(opts: EscalateScopeOptions): Promise<EscalateScopeResult> {
    const creds = this.requireCredentials();

    const body: Record<string, unknown> = {
      initiator_credential: creds.credential,
      target_agent_id: opts.targetAgentId,
      requested_scope: opts.scope,
      requested_permissions: opts.permissions,
      session_id: opts.sessionId,
    };

    if (opts.authorization) {
      body.authorization = opts.authorization;
    }

    const raw = await request<{
      session_id: string;
      consent_token: {
        token: string;
        scope: string;
        permissions: string[];
        exclusions: string[];
        authorization: Authorization;
        session_id: string;
        issued_at: string;
        expires_at: string;
      };
    }>(`${this.brokerUrl}/handshake/initiate`, {
      ...this.httpOpts,
      method: 'POST',
      body,
    });

    const ct = raw.consent_token;
    const consentToken: ConsentTokenDetail = {
      token: ct.token,
      scope: ct.scope,
      permissions: ct.permissions,
      exclusions: ct.exclusions ?? [],
      authorization: ct.authorization,
      sessionId: ct.session_id,
      issuedAt: ct.issued_at,
      expiresAt: ct.expires_at,
    };

    return {
      sessionId: raw.session_id,
      consentToken,
    };
  }

  // ── Consent verification ─────────────────────────────────────────────────────

  /**
   * Verify a consent token against a specific action and session.
   */
  async verifyConsent(opts: VerifyConsentOptions): Promise<VerifyConsentResult> {
    const raw = await request<{
      valid: boolean;
      action: string;
      permitted: boolean;
      session_id: string;
      expires_at?: string;
      reason?: string;
    }>(`${this.brokerUrl}/consent/verify`, {
      ...this.httpOpts,
      method: 'POST',
      body: {
        consent_token: opts.consentToken,
        action: opts.action,
        session_id: opts.sessionId,
      },
    });

    return {
      valid: raw.valid,
      action: raw.action,
      permitted: raw.permitted,
      sessionId: raw.session_id,
      expiresAt: raw.expires_at,
      reason: raw.reason,
    };
  }

  // ── Interaction recording ────────────────────────────────────────────────────

  /**
   * Record an action within an active session.
   */
  async recordAction(opts: RecordActionOptions): Promise<RecordActionResult> {
    const body: Record<string, unknown> = {
      session_id: opts.sessionId,
      agent_id: opts.agentId,
      action: opts.action,
    };
    if (opts.details) body.details = opts.details;
    if (opts.consentToken) body.consent_token = opts.consentToken;

    const raw = await request<{
      recorded: boolean;
      within_scope: boolean;
      action_id: string;
      action: string;
      timestamp: string;
    }>(`${this.brokerUrl}/interaction/record`, {
      ...this.httpOpts,
      method: 'POST',
      body,
    });

    return {
      recorded: raw.recorded,
      withinScope: raw.within_scope,
      actionId: raw.action_id,
      action: raw.action,
      timestamp: raw.timestamp,
    };
  }

  // ── Session close ────────────────────────────────────────────────────────────

  /**
   * Close an active session and receive the signed interaction receipt.
   */
  async closeSession(sessionId: string): Promise<SessionReceipt> {
    return request<SessionReceipt>(`${this.brokerUrl}/session/close`, {
      ...this.httpOpts,
      method: 'POST',
      body: { session_id: sessionId },
    });
  }

  // ── Receipt verification ─────────────────────────────────────────────────────

  /**
   * Verify a session receipt's Ed25519 signature against the broker's public key.
   */
  async verifyReceipt(receipt: SessionReceipt): Promise<VerifyReceiptResult> {
    const raw = await request<{
      valid: boolean;
      signed_by: string | null;
      receipt_id: string | null;
      tamper_detected: boolean;
    }>(`${this.brokerUrl}/receipt/verify`, {
      ...this.httpOpts,
      method: 'POST',
      body: { receipt },
    });

    return {
      valid: raw.valid,
      signedBy: raw.signed_by,
      receiptId: raw.receipt_id,
      tamperDetected: raw.tamper_detected,
    };
  }

  // ── Agent lifecycle ──────────────────────────────────────────────────────────

  /**
   * Revoke an agent by ID.
   * Requires a valid API key auth header (must belong to the same org).
   */
  async revokeAgent(agentId: string): Promise<RevokeAgentResult> {
    const raw = await request<{
      agent_id: string;
      status: string;
      revoked_at: string;
    }>(`${this.brokerUrl}/agents/${agentId}/revoke`, {
      ...this.httpOpts,
      method: 'POST',
    });

    return {
      agentId: raw.agent_id,
      status: raw.status,
      revokedAt: raw.revoked_at,
    };
  }

  /**
   * Renew an agent's credential to pick up the org's current verification tier.
   * Requires a valid API key or session token auth header.
   */
  async renewCredential(agentId: string): Promise<RenewCredentialResult> {
    const raw = await request<{
      agent_id: string;
      renewed: boolean;
      previous_tier?: string;
      current_tier?: string;
      credential?: string;
      issued_at?: string;
      expires_at?: string;
      message?: string;
      verification_tier?: string;
    }>(`${this.brokerUrl}/agents/${agentId}/renew`, {
      ...this.httpOpts,
      method: 'POST',
    });

    // If renewed, update in-memory credential to the new one
    if (raw.renewed && raw.credential && this.credentials?.agentId === agentId) {
      this.credentials = {
        ...this.credentials,
        credential: raw.credential,
        issuedAt: raw.issued_at ?? this.credentials.issuedAt,
        expiresAt: raw.expires_at ?? this.credentials.expiresAt,
      };
    }

    return {
      agentId: raw.agent_id,
      renewed: raw.renewed,
      previousTier: raw.previous_tier,
      currentTier: raw.current_tier ?? raw.verification_tier,
      credential: raw.credential,
      issuedAt: raw.issued_at,
      expiresAt: raw.expires_at,
      message: raw.message,
    };
  }

  /**
   * Update an agent's scope policies.
   * The broker authenticates this via the agent's own credential in the request body.
   */
  async updateScopePolicies(
    agentId: string,
    scopePolicies: ScopePolicies
  ): Promise<UpdateScopePoliciesResult> {
    const creds = this.requireCredentials();

    const raw = await request<{
      agent_id: string;
      scope_policies: ScopePolicies;
      updated_at: string;
    }>(`${this.brokerUrl}/agents/${agentId}/scope-policies`, {
      ...this.httpOpts,
      method: 'PUT',
      body: {
        credential: creds.credential,
        scope_policies: scopePolicies,
      },
    });

    return {
      agentId: raw.agent_id,
      scopePolicies: raw.scope_policies,
      updatedAt: raw.updated_at,
    };
  }
}
