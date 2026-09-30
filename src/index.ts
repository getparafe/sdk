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

import { generateKeyPair, signChallenge, signProof, createPresentationProof } from './crypto.js';
import { encryptCredentials, decryptCredentials } from './credentials.js';
import { request } from './http.js';
import { ValidationError, AuthError, NotFoundError, ParafeError } from './errors.js';
import * as jose from 'jose';
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
  LegacySessionReceipt,
  VerifyReceiptResult,
  RevokeAgentResult,
  RenewCredentialResult,
  UpdateScopePoliciesResult,
  AgentMetrics,
  VerifyConsentLocalResult,
  BrokerPublicKey,
  BrokerJwks,
} from './types.js';

// Re-export everything consumers need
export { ValidationError, AuthError, ForbiddenError, NotFoundError,
         ConflictError, ExpiredError, RateLimitError, InternalError,
         NetworkError, ParafeError } from './errors.js';
export { generateKeyPair, signChallenge, signProof, createPresentationProof, publicKeyThumbprint } from './crypto.js';
export type { KeyAlgorithm, KeyPair } from './crypto.js';
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
   *
   * @deprecated The broker refuses `verified` with `400 verified_evidence_unverifiable`
   * (S-48): it can't check a bare signature string. `verified` will require a
   * user-signed AP2 mandate that the broker verifies. Use `attested` meanwhile.
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

// ─── Receipt helpers ──────────────────────────────────────────────────────────

const RECEIPT_TYP = 'parafe-session-receipt+jwt';

function participantView(raw: Record<string, unknown> = {}): import('./types.js').ReceiptParticipant {
  return {
    agentId: raw.agent_id as string,
    did: raw.did as string | undefined,
    agentName: raw.agent_name as string,
    identityAssurance: raw.identity_assurance as string,
    verificationTier: raw.verification_tier as string | undefined,
  };
}

/** Decode a v2 receipt JWS into the read-only view. Does not verify it. */
export function decodeReceipt(jws: string): SessionReceipt {
  const c = jose.decodeJwt(jws) as Record<string, unknown>;
  const participants = (c.participants ?? {}) as Record<string, Record<string, unknown>>;
  const handshake = (c.handshake ?? {}) as Record<string, unknown>;
  const session = (c.session ?? {}) as Record<string, unknown>;
  const tokens = (c.consent_tokens as Record<string, unknown>[]) ?? [];
  return {
    formatVersion: 2,
    receipt: jws,
    receiptId: c.receipt_id as string,
    sessionId: c.session_id as string,
    handshakeId: c.handshake_id as string,
    issuer: c.iss as string,
    issuedAt: typeof c.iat === 'number' ? new Date(c.iat * 1000).toISOString() : '',
    participants: {
      initiator: participantView(participants.initiator),
      target: participantView(participants.target),
    },
    handshake: {
      mutualAuthCompleted: handshake.mutual_auth_completed as boolean,
      completedAt: handshake.completed_at as string,
      contextHash: (handshake.context_hash as string) ?? null,
    },
    consentTokens: tokens.map((ct) => {
      const auth = (ct.authorization ?? {}) as Record<string, unknown>;
      return {
        tokenRef: (ct.token_ref as string) ?? null,
        scope: ct.scope as string,
        permissions: (ct.permissions as string[]) ?? [],
        exclusions: (ct.exclusions as string[]) ?? [],
        authorization: {
          modality: auth.modality as Authorization['modality'],
          evidenceHash: (auth.evidence_hash as string) ?? null,
          mandateRefs: (auth.mandate_refs as string[]) ?? [],
        },
        initiatorProof: (ct.initiator_proof as 'pop' | 'credential') ?? null,
        initiatorProofAt: (ct.initiator_proof_at as string) ?? null,
        issuedAt: ct.issued_at as string,
        expiresAt: ct.expires_at as string,
      };
    }),
    actions: (c.actions as unknown[]) ?? [],
    chainHead: (c.chain_head as string) ?? null,
    session: {
      startedAt: session.started_at as string,
      closedAt: session.closed_at as string,
      closedBy: (session.closed_by as string) ?? null,
      status: session.status as string,
    },
    claims: c,
  };
}

function receiptFromResponse(raw: Record<string, unknown>): SessionReceipt | LegacySessionReceipt {
  if (typeof raw.receipt === 'string') return decodeReceipt(raw.receipt);
  const issued = (raw.receipt ?? raw) as Record<string, unknown>;
  return { formatVersion: 1, receiptId: issued.receipt_id as string, sessionId: issued.session_id as string, issued };
}

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

  private get httpOpts(): { timeout: number; retries: number; headers: Record<string, string> } {
    const headers: Record<string, string> = this.apiKey ? { Authorization: `Bearer ${this.apiKey}` } : {};
    return { timeout: this.timeout, retries: this.retries, headers };
  }

  /**
   * A proof of possession for a request (B7): the `Parafe-PoP` header, signed
   * with the loaded agent's key and bound to what the request authorizes.
   */
  private async proofHeader(method: string, url: string, claims: Record<string, unknown>): Promise<Record<string, string>> {
    const creds = this.requireCredentials();
    const htu = url.split('?')[0];
    return { 'Parafe-PoP': await signProof(creds.privateKey, { htm: method, htu, ...claims }) };
  }

  /**
   * Request options that authenticate as the loaded agent: its credential plus a
   * proof of possession (B7). For broker routes that act as one participant
   * (recording, closing, fetching a receipt) or on the agent itself. Falls back
   * to the API key when no credential is loaded, or when acting for a different
   * agent than the loaded one.
   */
  private async agentHttpOpts(method: string, url: string, claims: Record<string, unknown>, agentId?: string) {
    const creds = this.credentials;
    if (creds && (!agentId || creds.agentId === agentId)) {
      return {
        ...this.httpOpts,
        headers: { Authorization: `Bearer ${creds.credential}`, ...(await this.proofHeader(method, url, claims)) },
      };
    }
    return this.httpOpts;
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
   *
   * **Important:** The returned `privateKey` is the only copy — the broker does not store it.
   * Call `saveCredentials()` immediately after registration to persist it securely.
   */
  async register(opts: RegisterOptions): Promise<RegisterResult> {
    const { name, type, owner, scopePolicies, keyAlgorithm } = opts;

    // Generate key pair (Ed25519 by default; P-256 for AP2 interop)
    const { publicKey, privateKey } = generateKeyPair(keyAlgorithm ?? 'Ed25519');

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
      did?: string;
      agent_name: string;
      agent_type: string;
      owner: string;
      identity_assurance: string;
      verification_tier: string;
      credential: string;
      credential_sd_jwt?: string;
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
      credentialSdJwt: raw.credential_sd_jwt,
      publicKey,
      privateKey,
      issuedAt: raw.issued_at,
      expiresAt: raw.expires_at,
    };

    return {
      agentId: raw.agent_id,
      did: raw.did,
      credential: raw.credential,
      credentialSdJwt: raw.credential_sd_jwt,
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
   *
   * **Warning:** The returned `privateKey` is sensitive material. Avoid logging it
   * or storing it in plaintext. Use `saveCredentials()` for encrypted persistence.
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

    const url = `${this.brokerUrl}/handshake/initiate`;
    const raw = await request<{
      handshake_id: string;
      challenge_for_target: string;
      expires_at: string;
    }>(url, {
      ...this.httpOpts,
      headers: { ...this.httpOpts.headers, ...(await this.proofHeader('POST', url, { target_agent_id: opts.targetAgentId, requested_scope: opts.scope })) },
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
        initiator_proof?: 'pop' | 'credential' | null;
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
      initiatorProof: ct.initiator_proof ?? null,
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

    const url = `${this.brokerUrl}/handshake/initiate`;
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
        initiator_proof?: 'pop' | 'credential' | null;
      };
    }>(url, {
      ...this.httpOpts,
      headers: { ...this.httpOpts.headers, ...(await this.proofHeader('POST', url, { target_agent_id: opts.targetAgentId, requested_scope: opts.scope, session_id: opts.sessionId })) },
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
      initiatorProof: ct.initiator_proof ?? null,
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
      key_bound?: boolean;
      proof_verified?: boolean;
    }>(`${this.brokerUrl}/consent/verify`, {
      ...this.httpOpts,
      method: 'POST',
      body: {
        consent_token: opts.consentToken,
        action: opts.action,
        session_id: opts.sessionId,
        ...(opts.presentationProof ? { proof: opts.presentationProof } : {}),
      },
    });

    return {
      valid: raw.valid,
      action: raw.action,
      permitted: raw.permitted,
      sessionId: raw.session_id,
      expiresAt: raw.expires_at,
      reason: raw.reason,
      keyBound: raw.key_bound,
      proofVerified: raw.proof_verified,
    };
  }

  // ── Local consent verification ──────────────────────────────────────────────

  /**
   * Verify a consent token locally without a broker round-trip: the broker's
   * signature (resolved by `kid` from the broker's JWKS; ES256 since 2026-09-30,
   * EdDSA before), the issuer, expiry, scope and permissions.
   *
   * `keys` is optional: the broker's JWKS from `getJwks()` (fetched and cached
   * when omitted), or the legacy base64 Ed25519 key from `getPublicKey()` for
   * tokens issued before 2026-09-30.
   *
   * This checks the token, not who presents it. A target receiving a key-bound
   * token should also check the initiator's presentation proof (the A2A
   * extension does), or pass it to `verifyConsent({ presentationProof })`.
   */
  async verifyConsentLocally(
    consentToken: string,
    keys?: BrokerJwks | string
  ): Promise<VerifyConsentLocalResult> {
    let key: jose.KeyLike | ReturnType<typeof jose.createLocalJWKSet>;
    if (typeof keys === 'string') {
      // Legacy: the base64 SPKI Ed25519 key. Wrap in PEM headers directly; don't re-encode the DER.
      const pemLines: string[] = [];
      for (let i = 0; i < keys.length; i += 64) pemLines.push(keys.slice(i, i + 64));
      key = await jose.importSPKI(`-----BEGIN PUBLIC KEY-----\n${pemLines.join('\n')}\n-----END PUBLIC KEY-----`, 'EdDSA');
    } else {
      key = jose.createLocalJWKSet((keys ?? (await this.getJwks())) as unknown as jose.JSONWebKeySet);
    }

    // A bad signature or a foreign issuer throws. An expired token doesn't: jose
    // checks the signature before the claims, so the payload on JWTExpired is
    // authentic, and callers get { valid: false, expired: true } as documented.
    let payload: jose.JWTPayload;
    try {
      ({ payload } = await jose.jwtVerify(consentToken, key as never, {
        algorithms: ['ES256', 'EdDSA'],
        issuer: 'parafe-trust-broker',
      }));
    } catch (err) {
      if (!(err instanceof jose.errors.JWTExpired) || err.payload.iss !== 'parafe-trust-broker') throw err;
      payload = err.payload;
    }
    if (payload.token_type !== 'consent') {
      throw new AuthError('Not a Parafe consent token', 'invalid_token');
    }

    const now = new Date();
    const expiresAt = payload.exp ? new Date(payload.exp * 1000).toISOString() : '';
    const expired = payload.exp ? now.getTime() > payload.exp * 1000 : false;
    const cnf = payload.cnf as { jkt?: string } | undefined;

    return {
      valid: !expired,
      scope: (payload.scope as string) ?? '',
      permissions: (payload.permissions as string[]) ?? [],
      // Consent token v2 names the claim `exclusions`; before, `excluded`. Read both.
      exclusions: (payload.exclusions as string[]) ?? (payload.excluded as string[]) ?? [],
      sessionId: (payload.session_id as string) ?? '',
      expiresAt,
      expired,
      initiatorAgentId: (payload.sub as string) ?? (payload.initiator_agent_id as string | undefined),
      audience: typeof payload.aud === 'string' ? payload.aud : undefined,
      keyThumbprint: cnf?.jkt ?? null,
      initiatorProof: (payload.initiator_proof as 'pop' | 'credential') ?? null,
      tokenId: payload.jti,
    };
  }

  /**
   * The presentation proof to send beside a consent token (B7): signed with the
   * loaded agent's key, bound to this token (`ath`), the target (`aud` = the
   * token's audience, the target's DID) and optionally the A2A message ID.
   */
  async createPresentationProof(consentToken: string, messageId?: string): Promise<string> {
    const creds = this.requireCredentials();
    const aud = jose.decodeJwt(consentToken).aud;
    if (typeof aud !== 'string') {
      throw new ValidationError('This consent token has no audience (issued before key binding); no proof is needed', 'validation_error');
    }
    return createPresentationProof(creds.privateKey, consentToken, aud, messageId);
  }

  // ── Broker keys ────────────────────────────────────────────────────────────

  private jwksCache: { value: BrokerJwks; fetchedAt: number } | null = null;

  /**
   * The broker's signing keys (JWKS): the active ES256 key and retired keys.
   * Cached for 5 minutes. Match a JWS's `kid` against it.
   */
  async getJwks(): Promise<BrokerJwks> {
    if (this.jwksCache && Date.now() - this.jwksCache.fetchedAt < 5 * 60 * 1000) return this.jwksCache.value;
    let value: BrokerJwks;
    try {
      value = await request<BrokerJwks>(`${this.brokerUrl}/.well-known/jwks.json`, { ...this.httpOpts, method: 'GET' });
    } catch (err) {
      // A broker from before 2026-09-30 has no JWKS: use its single Ed25519 key.
      if (!(err instanceof NotFoundError)) throw err;
      const legacy = await this.getPublicKey();
      const spki = Buffer.from(legacy.publicKey, 'base64');
      value = { keys: [{ kty: 'OKP', crv: 'Ed25519', x: spki.subarray(12).toString('base64url'), kid: 'legacy-ed25519', alg: 'EdDSA', status: 'active' }] };
    }
    this.jwksCache = { value, fetchedAt: Date.now() };
    return value;
  }

  /**
   * The broker's legacy Ed25519 public key. It signed v1 receipts and tokens
   * issued before 2026-09-30; everything newer is ES256 (use `getJwks()`).
   */
  async getPublicKey(): Promise<BrokerPublicKey> {
    const raw = await request<{
      public_key: string;
      algorithm: string;
    }>(`${this.brokerUrl}/public-key`, {
      ...this.httpOpts,
      method: 'GET',
    });

    return {
      publicKey: raw.public_key,
      algorithm: raw.algorithm,
    };
  }

  // ── Interaction recording ────────────────────────────────────────────────────

  /**
   * Record an action within an active session.
   * Authenticates as the loaded agent (its credential) when `agentId` is that agent,
   * otherwise with the API key; the broker requires the caller to be that participant.
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
      ...(await this.agentHttpOpts('POST', `${this.brokerUrl}/interaction/record`, { session_id: opts.sessionId }, opts.agentId)),
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

  // ── Session close and receipts ───────────────────────────────────────────────

  /**
   * Close an active session and receive its receipt. `receipt.receipt` is the
   * evidence (a JWS signed by the broker); the other fields are decoded from it.
   * Authenticates as the loaded agent (credential + proof of possession), or with
   * the API key if none is loaded; the broker requires a participant.
   */
  async closeSession(sessionId: string): Promise<SessionReceipt> {
    const url = `${this.brokerUrl}/session/close`;
    const raw = await request<Record<string, unknown>>(url, {
      ...(await this.agentHttpOpts('POST', url, { session_id: sessionId })),
      method: 'POST',
      body: { session_id: sessionId },
    });
    if (typeof raw.receipt !== 'string') {
      throw new ParafeError('This broker issues v1 receipts; SDK 0.4 reads v2 receipts (broker 2026-09-30 or later). Use SDK 0.3.x with it.', 'receipt_v1', 200);
    }
    return decodeReceipt(raw.receipt);
  }

  /**
   * Fetch a closed session's receipt (B5). Either participant can, not only the
   * one that closed it. Receipts from before 2026-09-30 come back as
   * `{ formatVersion: 1, issued }`.
   */
  async getReceipt(sessionId: string): Promise<SessionReceipt | LegacySessionReceipt> {
    const url = `${this.brokerUrl}/sessions/${encodeURIComponent(sessionId)}/receipt`;
    const raw = await request<Record<string, unknown>>(url, {
      ...(await this.agentHttpOpts('GET', url, { session_id: sessionId })),
      method: 'GET',
    });
    return receiptFromResponse(raw);
  }

  /**
   * Verify a receipt with the broker. Accepts a `SessionReceipt` (its JWS is
   * sent; the decoded fields are ignored), the JWS string itself, or a v1
   * receipt (`LegacySessionReceipt`). For offline checks use
   * `verifyReceiptLocally()` or `@getparafe/verify`.
   */
  async verifyReceipt(receipt: SessionReceipt | LegacySessionReceipt | string): Promise<VerifyReceiptResult> {
    const body = typeof receipt === 'string'
      ? { receipt }
      : receipt.formatVersion === 2 ? { receipt: receipt.receipt } : { receipt: receipt.issued };

    const raw = await request<{
      valid: boolean;
      signed_by: string | null;
      receipt_id: string | null;
      tamper_detected: boolean;
      format_version?: 1 | 2;
      claims?: Record<string, unknown>;
      error?: string;
    }>(`${this.brokerUrl}/receipt/verify`, {
      ...this.httpOpts,
      method: 'POST',
      body,
    });

    return {
      valid: raw.valid,
      signedBy: raw.signed_by,
      receiptId: raw.receipt_id,
      tamperDetected: raw.tamper_detected,
      formatVersion: raw.format_version,
      claims: raw.claims,
      error: raw.error,
    };
  }

  /**
   * Verify a v2 receipt offline against the broker's JWKS (fetched and cached
   * when `keys` is omitted): ES256 signature by a broker key, typ, version.
   */
  async verifyReceiptLocally(receipt: SessionReceipt | string, keys?: BrokerJwks): Promise<VerifyReceiptResult> {
    const jws = typeof receipt === 'string' ? receipt : receipt.receipt;
    try {
      const keySet = jose.createLocalJWKSet((keys ?? (await this.getJwks())) as unknown as jose.JSONWebKeySet);
      const { payload } = await jose.jwtVerify(jws, keySet, { typ: RECEIPT_TYP, algorithms: ['ES256'] });
      if (payload.ver !== 2) throw new Error('Not a v2 session receipt');
      return { valid: true, signedBy: payload.iss ?? null, receiptId: (payload.receipt_id as string) ?? null, tamperDetected: false, formatVersion: 2, claims: payload };
    } catch (err) {
      return { valid: false, signedBy: null, receiptId: null, tamperDetected: true, formatVersion: 2, error: err instanceof Error ? err.message : String(err) };
    }
  }

  // ── Agent lifecycle ──────────────────────────────────────────────────────────

  /**
   * Revoke an agent by ID.
   * Uses the agent's own credential if loaded (and matches agentId), otherwise falls back to API key.
   */
  async revokeAgent(agentId: string): Promise<RevokeAgentResult> {
    // Prefer credential auth (plus a proof of possession) when the loaded
    // credential matches this agent
    const url = `${this.brokerUrl}/agents/${agentId}/revoke`;
    let headers: Record<string, string>;
    if (this.credentials?.agentId === agentId && this.credentials.credential) {
      headers = { Authorization: `Bearer ${this.credentials.credential}`, ...(await this.proofHeader('POST', url, { agent_id: agentId })) };
    } else {
      headers = { Authorization: `Bearer ${this.apiKey}` };
    }

    const raw = await request<{
      agent_id: string;
      status: string;
      revoked_at: string;
    }>(`${this.brokerUrl}/agents/${agentId}/revoke`, {
      timeout: this.timeout,
      retries: this.retries,
      headers,
      method: 'POST',
    });

    return {
      agentId: raw.agent_id,
      status: raw.status,
      revokedAt: raw.revoked_at,
    };
  }

  /**
   * Renew an agent's credential. The broker re-issues it when the owner's
   * verification tier changed, or when it is expired or within 7 days of expiry;
   * otherwise `renewed: false`. Authenticates with the API key; without one, the
   * loaded agent renews itself (credential + proof of possession), which is how
   * agents with no owner renew.
   */
  async renewCredential(agentId: string): Promise<RenewCredentialResult> {
    const url = `${this.brokerUrl}/agents/${agentId}/renew`;
    const opts = this.apiKey
      ? this.httpOpts
      : await this.agentHttpOpts('POST', url, { agent_id: agentId }, agentId);
    const raw = await request<{
      agent_id: string;
      renewed: boolean;
      reason?: string;
      previous_tier?: string;
      current_tier?: string;
      credential?: string;
      credential_sd_jwt?: string;
      issued_at?: string;
      expires_at?: string;
      message?: string;
      verification_tier?: string;
    }>(url, {
      ...opts,
      method: 'POST',
    });

    // If renewed, update in-memory credential to the new one
    if (raw.renewed && raw.credential && this.credentials?.agentId === agentId) {
      this.credentials = {
        ...this.credentials,
        credential: raw.credential,
        credentialSdJwt: raw.credential_sd_jwt ?? this.credentials.credentialSdJwt,
        issuedAt: raw.issued_at ?? this.credentials.issuedAt,
        expiresAt: raw.expires_at ?? this.credentials.expiresAt,
      };
    }

    return {
      agentId: raw.agent_id,
      renewed: raw.renewed,
      reason: raw.reason,
      previousTier: raw.previous_tier,
      currentTier: raw.current_tier ?? raw.verification_tier,
      credential: raw.credential,
      credentialSdJwt: raw.credential_sd_jwt,
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
      headers: { ...this.httpOpts.headers, ...(await this.proofHeader('PUT', `${this.brokerUrl}/agents/${agentId}/scope-policies`, { agent_id: agentId })) },
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

  /**
   * Retrieve reputation metrics for an agent.
   * Returns raw trust signals computed from the agent's interaction history.
   *
   * @throws {NotFoundError} 404 — agent not found
   * @throws {AuthError} 401 — invalid or missing API key
   * @throws {NetworkError} Network or timeout error after retries exhausted
   */
  async getAgentMetrics(agentId: string): Promise<AgentMetrics> {
    const raw = await request<{
      agent_id: string;
      computed_at: string;
      tenure_days: number;
      identity_assurance: string;
      sessions: {
        total: number;
        completed: number;
        expired: number;
        abandoned: number;
        completion_rate: number;
      };
      counterparties: {
        total_unique: number;
        as_initiator: number;
        as_target: number;
      };
      handshakes: {
        total: number;
        successful: number;
        failed: number;
        success_rate: number;
      };
      scopes: {
        unique_scopes: string[];
        total_scopes_used: number;
      };
      denied_scope_requests: {
        total: number;
        last_30_days: number;
        by_reason: Record<string, number>;
      };
      actions: {
        total_recorded: number;
        avg_per_session: number;
      };
    }>(`${this.brokerUrl}/agents/${agentId}/metrics`, {
      ...this.httpOpts,
      method: 'GET',
    });

    return {
      agentId: raw.agent_id,
      computedAt: raw.computed_at,
      tenureDays: raw.tenure_days,
      identityAssurance: raw.identity_assurance,
      sessions: {
        total: raw.sessions.total,
        completed: raw.sessions.completed,
        expired: raw.sessions.expired,
        abandoned: raw.sessions.abandoned,
        completionRate: raw.sessions.completion_rate,
      },
      counterparties: {
        totalUnique: raw.counterparties.total_unique,
        asInitiator: raw.counterparties.as_initiator,
        asTarget: raw.counterparties.as_target,
      },
      handshakes: {
        total: raw.handshakes.total,
        successful: raw.handshakes.successful,
        failed: raw.handshakes.failed,
        successRate: raw.handshakes.success_rate,
      },
      scopes: {
        uniqueScopes: raw.scopes.unique_scopes,
        totalScopesUsed: raw.scopes.total_scopes_used,
      },
      deniedScopeRequests: {
        total: raw.denied_scope_requests.total,
        last30Days: raw.denied_scope_requests.last_30_days,
        byReason: raw.denied_scope_requests.by_reason,
      },
      actions: {
        totalRecorded: raw.actions.total_recorded,
        avgPerSession: raw.actions.avg_per_session,
      },
    };
  }
}
