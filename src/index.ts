/**
 * @getparafe/sdk — Parafé Trust Broker Client SDK
 *
 * Usage:
 *   import { ParafeClient } from '@getparafe/sdk';
 *
 *   const parafe = new ParafeClient({
 *     brokerUrl: 'https://api.parafe.ai',
 *     apiKey: 'prf_key_live_...',
 *   });
 */

import { generateKeyPair, signChallenge, signProof, createPresentationProof, signActionReceipt as signActionReceiptJws, sha256b64u, jsonHash, ap2MandateReferences, signAp2ReceiptJws } from './crypto.js';
import { encryptCredentials, decryptCredentials } from './credentials.js';
import { request, type RequestOptions } from './http.js';
import { ValidationError, AuthError, NotFoundError, ParafeError, ConflictError, NetworkError, InternalError } from './errors.js';
import * as jose from 'jose';
import type {
  Parties,
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
  ClaimLink,
  ClaimStatus,
  SignActionReceiptOptions,
  ActionReceiptAck,
  RecordActionReceiptResult,
  SessionIndex,
  ReceiptKind,
  VerifyMandateOptions,
  VerifyMandateResult,
  MandateRef,
  SignAp2ReceiptOptions,
  Ap2Receipt,
} from './types.js';

// Re-export everything consumers need
export { ValidationError, AuthError, ForbiddenError, NotFoundError,
         ConflictError, ExpiredError, RateLimitError, InternalError,
         NetworkError, ParafeError } from './errors.js';
export { generateKeyPair, signChallenge, signProof, createPresentationProof, publicKeyThumbprint, jcs, jsonHash, sha256b64u, ap2MandateReferences } from './crypto.js';
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
   * Verified authorization (broker B8): an AP2 closed mandate the user signed
   * for this purchase (human present), which the broker checks against the
   * issuers the target's scope trusts. The mandate's merchant or payee must be
   * the target; each mandate is redeemed once.
   */
  verified(opts: MandateAuthorizationOptions): Authorization {
    return { modality: 'verified', evidence: mandateEvidence(opts, 'verified') };
  },

  /**
   * Delegated authorization (broker B8): an AP2 open mandate the user signed
   * (the limits), closed with this agent's own registered key (human not
   * present). A scope that requires 'verified' refuses it.
   */
  delegated(opts: MandateAuthorizationOptions): Authorization {
    return { modality: 'delegated', evidence: mandateEvidence(opts, 'delegated') };
  },
};

/** Options for `authorization.verified()` / `delegated()`. */
export interface MandateAuthorizationOptions {
  /** The AP2 mandate as presented: the `~~`-joined Delegate SD-JWT chain. */
  mandate: string;
  checkoutJwt?: string;
  checkoutHash?: string;
  checkoutMandate?: string;
}

function mandateEvidence(opts: MandateAuthorizationOptions, modality: string) {
  if ((opts as unknown as { userSignature?: unknown }).userSignature !== undefined) {
    throw new ValidationError(`'${modality}' no longer takes a signature string: pass the user-signed AP2 mandate (mandate)`, 'validation_error');
  }
  if (!opts || typeof opts.mandate !== 'string' || !opts.mandate) {
    throw new ValidationError(`mandate (the AP2 mandate as presented) is required for ${modality} authorization`, 'validation_error');
  }
  return {
    ap2_mandate: opts.mandate,
    ...(opts.checkoutJwt ? { checkout_jwt: opts.checkoutJwt } : {}),
    ...(opts.checkoutHash ? { checkout_hash: opts.checkoutHash } : {}),
    ...(opts.checkoutMandate ? { checkout_mandate: opts.checkoutMandate } : {}),
  };
}

/** The broker's mandate_refs, camelCased. */
function mandateRefs(raw: unknown): MandateRef[] {
  return Array.isArray(raw)
    ? raw.map((r: Record<string, unknown>) => ({ family: r.family as MandateRef['family'], closedJwt: r.closed_jwt as string, sdHash: r.sd_hash as string }))
    : [];
}

// ─── Receipt helpers ──────────────────────────────────────────────────────────

const RECEIPT_TYP = 'parafe-session-receipt+jwt';

function toClaimLink(raw: { claim_url: string; code: string; expires_at: string }): ClaimLink {
  return { url: raw.claim_url, code: raw.code, expiresAt: raw.expires_at };
}

function participantView(raw: Record<string, unknown> = {}): import('./types.js').ReceiptParticipant {
  return {
    agentId: raw.agent_id as string,
    did: raw.did as string | undefined,
    agentName: raw.agent_name as string,
    identityAssurance: raw.identity_assurance as string,
    verificationTier: raw.verification_tier as string | undefined,
    ...(raw.parties ? { parties: raw.parties as Parties } : {}),
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
          mandateRefs: mandateRefs(auth.mandate_refs),
        },
        initiatorProof: (ct.initiator_proof as 'pop' | 'credential') ?? null,
        initiatorProofAt: (ct.initiator_proof_at as string) ?? null,
        issuedAt: ct.issued_at as string,
        expiresAt: ct.expires_at as string,
      };
    }),
    actions: ((c.actions as Record<string, unknown>[]) ?? []).map((a) => ({
      seq: a.seq as number,
      receiptHash: a.receipt_hash as string,
      kind: a.kind as string,
      iss: a.iss as string,
      issuerVerified: a.issuer_verified !== false,
      action: a.action as string,
      result: a.result as 'success' | 'error',
      error: (a.error as string) ?? null,
      ...mandateCheck(a),
    })),
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

/** A3: the mandate check on an index entry, ack or receipt action (null when it names no mandate). */
function mandateCheck(x: Record<string, unknown> | undefined) {
  const v = x ?? {};
  return {
    referenceVerified: typeof v.reference_verified === 'boolean' ? v.reference_verified : null,
    mandateRef: (v.mandate_ref as string) ?? null,
    mandateVerifiedBy: (v.mandate_verified_by as string) ?? null,
    mandateIssuerSource: (v.mandate_issuer_source as string) ?? null,
  };
}

function ackFromResponse(raw: Record<string, unknown>, duplicate: boolean): ActionReceiptAck {
  const acknowledgment = raw.acknowledgment as string;
  const claims = (raw.claims as Record<string, unknown>) ?? jose.decodeJwt(acknowledgment);
  return {
    sessionId: raw.session_id as string,
    seq: raw.seq as number,
    receiptHash: raw.receipt_hash as string,
    entryHash: raw.entry_hash as string,
    acknowledgment,
    claims,
    duplicate,
    ...mandateCheck(claims),
  };
}

function receiptFromResponse(raw: Record<string, unknown>): SessionReceipt | LegacySessionReceipt {
  if (typeof raw.receipt === 'string') return decodeReceipt(raw.receipt);
  const issued = (raw.receipt ?? raw) as Record<string, unknown>;
  return { formatVersion: 1, receiptId: issued.receipt_id as string, sessionId: issued.session_id as string, issued };
}

// ─── ParafeClient ─────────────────────────────────────────────────────────────

/** AP2 receipt claims per AP2's checkout_receipt.json / payment_receipt.json. */
function ap2ReceiptClaims(opts: SignAp2ReceiptOptions, iss: string, reference: string): Record<string, unknown> {
  const bad = (m: string) => new ValidationError(m, 'validation_error');
  const status = opts.status ?? (opts.error ? 'Error' : 'Success');
  if (opts.kind !== 'checkout' && opts.kind !== 'payment') throw bad("kind must be 'checkout' or 'payment'");
  const claims: Record<string, unknown> = { status, iss, iat: Math.floor(Date.now() / 1000), reference };
  if (status === 'Error') {
    if (!opts.error || !opts.errorDescription) throw bad('An Error receipt needs error and errorDescription');
    claims.error = opts.error;
    claims.error_description = opts.errorDescription;
  } else if (opts.error) {
    throw bad('A Success receipt has no error');
  }
  if (opts.kind === 'checkout') {
    if (status === 'Success') {
      if (!opts.orderId) throw bad('A Success checkout receipt needs orderId');
      claims.order_id = opts.orderId;
    }
  } else {
    if (!opts.paymentId) throw bad('A payment receipt needs paymentId');
    claims.payment_id = opts.paymentId;
    if (status === 'Success') {
      if (!opts.pspConfirmationId || !opts.networkConfirmationId) throw bad('A Success payment receipt needs pspConfirmationId and networkConfirmationId');
      claims.psp_confirmation_id = opts.pspConfirmationId;
      claims.network_confirmation_id = opts.networkConfirmationId;
    }
  }
  return claims;
}

/** The broker's /ap2/mandates/verify response, camelCased. */
function mandateResult(raw: Record<string, unknown>): VerifyMandateResult {
  const refs = raw.references as { sd_hash: string; closed_jwt: string } | null | undefined;
  const agent = raw.agent as Record<string, unknown> | null | undefined;
  const red = raw.redemption as Record<string, unknown> | null | undefined;
  const out: VerifyMandateResult = {
    valid: raw.valid === true,
    family: (raw.family as VerifyMandateResult['family']) ?? null,
    mode: (raw.mode as VerifyMandateResult['mode']) ?? null,
    alreadyRedeemed: raw.reason === 'already_redeemed',
    references: refs ? { sdHash: refs.sd_hash, closedJwt: refs.closed_jwt } : null,
    mandateHash: (raw.mandate_hash as string) ?? null,
    agent: agent
      ? {
          agentId: agent.agent_id as string,
          did: agent.did as string,
          agentName: agent.agent_name as string,
          identityAssurance: agent.identity_assurance as string,
          verificationTier: agent.verification_tier as string,
          ...(agent.operator_domain ? { operatorDomain: agent.operator_domain as string } : {}),
          ...(typeof agent.is_counterparty === 'boolean' ? { isCounterparty: agent.is_counterparty } : {}),
        }
      : null,
    redemption: red
      ? {
          mandateId: red.mandate_id as string,
          family: red.family as 'checkout' | 'payment',
          mandateHash: red.mandate_hash as string,
          transactionRef: red.transaction_ref as string,
          verifierAgentId: red.verifier_agent_id as string,
          sessionId: (red.session_id as string) ?? null,
          redeemedAt: red.redeemed_at as string,
        }
      : null,
  };
  if (!out.valid) {
    out.error = raw.error as VerifyMandateResult['error'];
    out.reason = raw.reason as string;
    out.message = raw.message as string;
    out.violations = (raw.violations as string[]) ?? [];
  }
  if (raw.issuer) out.issuer = raw.issuer as VerifyMandateResult['issuer'];
  for (const [from, to] of [['audience', 'audience'], ['nonce', 'nonce'], ['presented_at', 'presentedAt'], ['checkout_hash', 'checkoutHash'], ['transaction_id', 'transactionId'], ['agent_key_thumbprint', 'agentKeyThumbprint'], ['closed_by', 'closedBy'], ['closed_by_key_thumbprint', 'closedByKeyThumbprint'], ['opened_by', 'openedBy'], ['opened_by_key_thumbprint', 'openedByKeyThumbprint']] as const) {
    if (raw[from] !== undefined) (out as unknown as Record<string, unknown>)[to] = raw[from];
  }
  if (raw.closed_mandate) out.closedMandate = raw.closed_mandate as Record<string, unknown>;
  if (raw.open_mandates) out.openMandates = raw.open_mandates as Record<string, unknown>[];
  return out;
}

/** claim-status `wait`: whole seconds, 0 to 60 (the broker's limit). */
function checkClaimWait(seconds: number): number {
  if (!Number.isInteger(seconds) || seconds < 0 || seconds > 60) {
    throw new RangeError('waitSeconds must be a whole number of seconds from 0 to 60');
  }
  return seconds;
}

/**
 * P-73: what verifyConsentLocally() throws for a token that doesn't check out:
 * Parafé's AuthError, never jose's raw error. `invalid_signature` for a token
 * not signed by the broker (a forgery, or a key it never published);
 * `invalid_token` for anything else (malformed, another issuer, wrong algorithm).
 */
function consentTokenError(err: unknown): unknown {
  if (err instanceof jose.errors.JWSSignatureVerificationFailed || err instanceof jose.errors.JWKSNoMatchingKey) {
    return new AuthError('This consent token is not signed by the Parafé broker', 'invalid_signature');
  }
  if (err instanceof jose.errors.JOSEError) {
    return new AuthError(`Not a valid Parafé consent token: ${err.message}`, 'invalid_token');
  }
  return err;
}

export class ParafeClient {
  private readonly brokerUrl: string;
  private readonly apiKey: string;
  private readonly timeout: number;
  private readonly retries: number;

  /** Currently loaded credentials (null when not registered or loaded) */
  private credentials: StoredCredentials | null = null;
  /** The file saveCredentials()/loadCredentials() last used, and whose credential it holds: a renewal of that agent is written back to it. */
  private credentialFile: { path: string; passphrase: string; agentId: string } | null = null;

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
        refreshHeaders: () => this.proofHeader(method, url, claims),
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
   * Generate a key pair (P-256 by default), register a new agent with the broker,
   * and store the returned credentials in memory.
   *
   * **Important:** The returned `privateKey` is the only copy — the broker does not store it.
   * Call `saveCredentials()` immediately after registration to persist it securely.
   */
  async register(opts: RegisterOptions): Promise<RegisterResult> {
    const { name, type, principalName, actsFor, scopePolicies, keyAlgorithm } = opts;

    // P-256 by default: AP2 receipts need it. Ed25519 stays accepted.
    const { publicKey, privateKey } = generateKeyPair(keyAlgorithm ?? 'P-256');

    // Build request body (broker uses snake_case)
    const body: Record<string, unknown> = {
      agent_type: type,
      public_key: publicKey,
    };
    // Broker SPEC-002 decision 10: both optional without an API key.
    if (name !== undefined) body.agent_name = name;
    if (principalName !== undefined) body.principal_name = principalName;
    if (actsFor) body.acts_for = { ref: actsFor.ref };
    if (scopePolicies) {
      body.scope_policies = scopePolicies;
    }

    // POST /agents/register
    const raw = await request<{
      agent_id: string;
      did?: string;
      agent_name: string;
      agent_type: string;
      principal_name: string | null;
      principal_type?: 'personal' | 'org' | 'external' | null;
      principal_id?: string | null;
      principal_ref?: string | null;
      operator_type?: 'personal' | 'org' | null;
      operator_id?: string | null;
      identity_assurance: string;
      verification_tier: string;
      credential: string;
      credential_sd_jwt?: string;
      issued_at: string;
      expires_at: string;
      claim?: { claim_url: string; code: string; expires_at: string };
    }>(`${this.brokerUrl}/agents/register`, {
      ...this.httpOpts,
      // No automatic retry: a retry would resend the same single-use proof, and if
      // the first attempt reached the broker the agent exists but this call fails.
      retries: 0,
      // Broker SPEC-003 part 4: prove we hold the key we're registering.
      headers: {
        ...this.httpOpts.headers,
        'Parafe-PoP': await signProof(privateKey, { htm: 'POST', htu: `${this.brokerUrl}/agents/register` }),
      },
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
      operatorType: raw.operator_type ?? null,
      operatorId: raw.operator_id ?? null,
      principalType: raw.principal_type ?? null,
      principalId: raw.principal_id ?? null,
      principalRef: raw.principal_ref ?? null,
      issuedAt: raw.issued_at,
      expiresAt: raw.expires_at,
      ...(raw.claim ? { claimLink: toClaimLink(raw.claim) } : {}),
    };
  }

  // ── Claim links (Phase 1.5) ──────────────────────────────────────────────────

  /**
   * A new claim link for the loaded agent, which no person or org has claimed yet (it
   * registered without an API key). Show it to the person the agent acts for:
   * signed in to the Parafé portal, they approve it and the agent becomes theirs.
   * Single use, 30 minutes; replaces the previous link. Authenticates as the
   * agent (credential + proof of possession). 409 `already_claimed` once it has been claimed.
   */
  async createClaimLink(): Promise<ClaimLink> {
    const creds = this.requireCredentials();
    const url = `${this.brokerUrl}/agents/${creds.agentId}/claim-link`;
    const raw = await request<{ claim_url: string; code: string; expires_at: string }>(url, {
      timeout: this.timeout,
      retries: this.retries,
      headers: { Authorization: `Bearer ${creds.credential}`, ...(await this.proofHeader('POST', url, { agent_id: creds.agentId })) },
      refreshHeaders: () => this.proofHeader('POST', url, { agent_id: creds.agentId }),
      method: 'POST',
    });
    return toClaimLink(raw);
  }

  /**
   * Whether the loaded agent has been claimed, and whether its credential shows
   * it yet. When `credentialCurrent` is false, call `renewCredential(agentId)`
   * (reason `identity_changed`, or `tier_changed` after the principal verifies their
   * email). Handshakes use a claim as soon as it is approved.
   */
  async getClaimStatus(opts: { waitSeconds?: number } = {}): Promise<ClaimStatus> {
    const creds = this.requireCredentials();
    const wait = checkClaimWait(opts.waitSeconds ?? 0);
    const url = `${this.brokerUrl}/agents/${creds.agentId}/claim-status`;
    const raw = await request<{
      claimed: boolean;
      operator_type?: 'personal' | 'org' | null;
      operator_id?: string | null;
      principal_type?: 'personal' | 'org' | 'external' | null;
      principal_ref?: string | null;
      identity_assurance: string;
      verification_tier: string;
      principal_tier: string | null;
      credential_current: boolean;
      registered_at: string;
    }>(wait ? `${url}?wait=${wait}` : url, {
      // The broker holds a waiting request up to `wait` seconds: allow for it.
      timeout: wait ? Math.max(this.timeout, (wait + 15) * 1000) : this.timeout,
      retries: this.retries,
      headers: { Authorization: `Bearer ${creds.credential}`, ...(await this.proofHeader('GET', url, { agent_id: creds.agentId })) },
      refreshHeaders: () => this.proofHeader('GET', url, { agent_id: creds.agentId }),
      method: 'GET',
    });
    return {
      claimed: raw.claimed,
      operatorType: raw.operator_type ?? null,
      operatorId: raw.operator_id ?? null,
      principalType: raw.principal_type ?? null,
      principalRef: raw.principal_ref ?? null,
      identityAssurance: raw.identity_assurance,
      verificationTier: raw.verification_tier,
      principalTier: raw.principal_tier ?? null,
      credentialCurrent: raw.credential_current,
      registeredAt: raw.registered_at,
    };
  }

  /**
   * Waits until the person the agent acts for approves its claim link, or
   * `timeoutMs` passes (default 30 minutes, a claim link's life). Each request
   * asks the broker to hold it up to `waitSeconds` (default 25, at most 60) and
   * answer the moment the claim is approved, so this needs few requests and
   * returns at once. Returns the last status: check `claimed`, then call
   * `renewCredential()` (`credentialCurrent` is false after a claim). If it
   * times out unclaimed, make a new link with `createClaimLink()`.
   */
  async waitForClaim(opts: { timeoutMs?: number; waitSeconds?: number } = {}): Promise<ClaimStatus> {
    const waitSeconds = checkClaimWait(opts.waitSeconds ?? 25);
    if (waitSeconds < 1) throw new RangeError('waitSeconds must be at least 1 for waitForClaim()');
    const deadline = Date.now() + (opts.timeoutMs ?? 30 * 60 * 1000);
    let status: ClaimStatus | undefined;
    let failures = 0;
    do {
      const left = Math.ceil((deadline - Date.now()) / 1000);
      try {
        status = await this.getClaimStatus({ waitSeconds: Math.max(1, Math.min(waitSeconds, left)) });
        failures = 0;
      } catch (err) {
        // A deploy or a dropped connection: pause, then ask again (with a new
        // proof). Five failures in a row is not a deploy: give up.
        const transient = err instanceof NetworkError || err instanceof InternalError;
        if (!transient || ++failures >= 5 || Date.now() >= deadline) throw err;
        await new Promise((r) => setTimeout(r, 2000));
      }
    } while (!status?.claimed && Date.now() < deadline);
    if (!status) throw new NetworkError('Could not reach the broker before waitForClaim() timed out');
    return status;
  }

  // ── Credential persistence ───────────────────────────────────────────────────

  /**
   * Save the currently loaded credentials to an AES-256-GCM encrypted file.
   */
  async saveCredentials(filePath: string, passphrase: string): Promise<void> {
    const creds = this.requireCredentials();
    await encryptCredentials(filePath, creds, passphrase);
    this.credentialFile = { path: filePath, passphrase, agentId: creds.agentId };
  }

  /**
   * Load credentials from an AES-256-GCM encrypted file into memory.
   * A later renewal of this agent's credential is written back to the same file.
   */
  async loadCredentials(filePath: string, passphrase: string): Promise<void> {
    this.credentials = await decryptCredentials(filePath, passphrase);
    this.credentialFile = { path: filePath, passphrase, agentId: this.credentials.agentId };
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
      evidence_salt?: string;
    }>(url, {
      ...this.httpOpts,
      headers: { ...this.httpOpts.headers, ...(await this.proofHeader('POST', url, { target_agent_id: opts.targetAgentId, requested_scope: opts.scope })) },
      refreshHeaders: () => this.proofHeader('POST', url, { target_agent_id: opts.targetAgentId, requested_scope: opts.scope }),
      method: 'POST',
      body,
    });

    return {
      handshakeId: raw.handshake_id,
      challengeForTarget: raw.challenge_for_target,
      expiresAt: raw.expires_at,
      evidenceSalt: raw.evidence_salt ?? null,
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
      evidenceSalt: (ct.authorization as { evidence_salt?: string } | undefined)?.evidence_salt ?? null,
      mandateRefs: mandateRefs((ct.authorization as { mandate_refs?: unknown } | undefined)?.mandate_refs),
    };

    const session = raw.session as { session_id: string; initiator?: { parties?: Parties }; target?: { parties?: Parties } };
    return {
      handshakeId: raw.handshake_id,
      sessionId: session.session_id,
      consentToken,
      ...(session.initiator?.parties ? { initiatorParties: session.initiator.parties } : {}),
      ...(session.target?.parties ? { targetParties: session.target.parties } : {}),
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
      refreshHeaders: () => this.proofHeader('POST', url, { target_agent_id: opts.targetAgentId, requested_scope: opts.scope, session_id: opts.sessionId }),
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
      evidenceSalt: (ct.authorization as { evidence_salt?: string } | undefined)?.evidence_salt ?? null,
      mandateRefs: mandateRefs((ct.authorization as { mandate_refs?: unknown } | undefined)?.mandate_refs),
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
    const agentId = this.expectedTarget(opts.consentToken, opts.agentId);
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
        ...(agentId ? { agent_id: agentId } : {}),
      },
    });

    // The broker checks agent_id since 2026-10-08; check here too, so an older
    // broker (which ignores it) can't pass a token issued for another agent.
    if (agentId && raw.valid) {
      let target: unknown;
      try { target = jose.decodeJwt(opts.consentToken).target_agent_id; } catch { target = undefined; }
      if (target !== agentId) throw new AuthError(`This consent token was issued for ${String(target)}, not ${agentId}`, 'wrong_audience');
    }

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
   * The token must be for `opts.agentId` (its target), by default the loaded
   * agent unless that agent is the token's initiator; `agentId: null` skips the
   * check. A token for another agent throws `AuthError` (`wrong_audience`).
   *
   * This checks the token, not who presents it. A target receiving a key-bound
   * token should also check the initiator's presentation proof (the A2A
   * extension does), or pass it to `verifyConsent({ presentationProof })`.
   */
  async verifyConsentLocally(
    consentToken: string,
    keys?: BrokerJwks | string,
    opts: { agentId?: string | null } = {}
  ): Promise<VerifyConsentLocalResult> {
    let key: jose.KeyLike | ReturnType<typeof jose.createLocalJWKSet>;
    if (typeof keys === 'string') {
      // Legacy: the base64 SPKI Ed25519 key. Wrap in PEM headers directly; don't re-encode the DER.
      if (jose.decodeProtectedHeader(consentToken).alg === 'ES256') {
        throw new ValidationError('This token is ES256 (broker 2026-09-30+); the legacy Ed25519 key cannot verify it. Omit the key (the JWKS is fetched) or pass getJwks().', 'validation_error');
      }
      const pemLines: string[] = [];
      for (let i = 0; i < keys.length; i += 64) pemLines.push(keys.slice(i, i + 64));
      key = await jose.importSPKI(`-----BEGIN PUBLIC KEY-----\n${pemLines.join('\n')}\n-----END PUBLIC KEY-----`, 'EdDSA');
    } else {
      key = jose.createLocalJWKSet((keys ?? (await this.getJwks(await this.unknownKid(consentToken, keys)))) as unknown as jose.JSONWebKeySet);
    }

    // A bad signature or a foreign issuer throws AuthError (invalid_signature,
    // invalid_token). An expired token doesn't: jose checks the signature before
    // the claims, so the payload on JWTExpired is authentic, and callers get
    // { valid: false, expired: true } as documented.
    let payload: jose.JWTPayload;
    try {
      ({ payload } = await jose.jwtVerify(consentToken, key as never, {
        algorithms: ['ES256', 'EdDSA'],
        issuer: 'parafe-trust-broker',
      }));
    } catch (err) {
      if (err instanceof jose.errors.JWTExpired && err.payload.iss === 'parafe-trust-broker') {
        payload = err.payload;
      } else {
        throw consentTokenError(err);
      }
    }
    if (payload.token_type !== 'consent') {
      throw new AuthError('Not a Parafe consent token', 'invalid_token');
    }
    // S-69: a token issued for another agent is refused (a valid token from one
    // session can't be replayed at a different target).
    const expected = this.expectedTarget(consentToken, opts.agentId);
    if (expected && payload.target_agent_id !== expected) {
      throw new AuthError(`This consent token was issued for ${String(payload.target_agent_id)}, not ${expected}`, 'wrong_audience');
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
      targetAgentId: typeof payload.target_agent_id === 'string' ? payload.target_agent_id : undefined,
      keyThumbprint: cnf?.jkt ?? null,
      initiatorProof: (payload.initiator_proof as 'pop' | 'credential') ?? null,
      tokenId: payload.jti,
      ...(payload.initiator_parties ? { initiatorParties: payload.initiator_parties as Parties } : {}),
      ...(payload.target_parties ? { targetParties: payload.target_parties as Parties } : {}),
    };
  }

  /**
   * The agent a consent token must be for: `agentId` when given (null: no check),
   * else the loaded agent unless it is the token's initiator (checking its own token).
   */
  private expectedTarget(consentToken: string, agentId: string | null | undefined): string | null {
    if (agentId !== undefined) return agentId;
    const loaded = this.credentials?.agentId;
    if (!loaded) return null;
    let sub: unknown;
    try { sub = jose.decodeJwt(consentToken).sub; } catch { return null; }
    return sub === loaded ? null : loaded;
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
   * True when we fetch the keys ourselves, have them cached, and the JWS names
   * a kid that isn't among them (the broker rotated or added a key).
   */
  private async unknownKid(jws: string, keys?: BrokerJwks): Promise<boolean> {
    if (keys || !this.jwksCache) return false;
    let kid: string | undefined;
    try { kid = jose.decodeProtectedHeader(jws).kid; } catch { return false; }
    return Boolean(kid) && !this.jwksCache.value.keys.some((k) => k.kid === kid);
  }

  /**
   * The broker's signing keys (JWKS): the active ES256 key and retired keys.
   * Cached for 5 minutes. Match a JWS's `kid` against it.
   */
  async getJwks(forceRefresh = false): Promise<BrokerJwks> {
    const age = this.jwksCache ? Date.now() - this.jwksCache.fetchedAt : Infinity;
    // A forced refresh (a token names a key we don't have) is allowed once a minute.
    if (this.jwksCache && age < 5 * 60 * 1000 && !(forceRefresh && age >= 60 * 1000)) return this.jwksCache.value;
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

  // ── Action receipts and the session index (B6) ───────────────────────────────

  private readonly didCache = new Map<string, string>();

  /** The loaded agent's DID: from its SD-JWT VC credential, else its DID document. */
  private async agentDid(): Promise<string> {
    const creds = this.requireCredentials();
    const cached = this.didCache.get(creds.agentId);
    if (cached) return cached;
    let did: string | undefined;
    if (creds.credentialSdJwt) {
      try {
        const sub = jose.decodeJwt(creds.credentialSdJwt.split('~')[0] as string).sub;
        if (typeof sub === 'string' && sub.endsWith(`:agents:${creds.agentId}`)) did = sub;
      } catch {
        // fall back to the DID document
      }
    }
    if (!did) {
      const doc = await request<{ id: string }>(`${this.brokerUrl}/agents/${encodeURIComponent(creds.agentId)}/did.json`, { ...this.httpOpts, method: 'GET' });
      did = doc.id;
    }
    this.didCache.set(creds.agentId, did);
    return did;
  }

  /**
   * Sign an action receipt as the loaded agent: the agent that performs or
   * refuses an action signs what happened, bound to the consent token it was
   * asked under. Sign one for refusals too (`result: 'error'`, `error:
   * 'excluded'` etc.). Returns the receipt (a JWS); file it with
   * `fileActionReceipt()` and return it to the other agent.
   */
  async signActionReceipt(opts: SignActionReceiptOptions): Promise<string> {
    const creds = this.requireCredentials();
    const result = opts.result ?? 'success';
    if (result === 'error' && !opts.error) throw new ValidationError("An 'error' receipt needs error (e.g. 'excluded')", 'validation_error');
    if (result === 'success' && opts.error) throw new ValidationError("A 'success' receipt has no error", 'validation_error');
    const requestRef = opts.requestRef ?? (opts.request !== undefined ? sha256b64u(opts.request) : null);
    return signActionReceiptJws(creds.privateKey, await this.agentDid(), {
      session_id: opts.sessionId,
      consent_ref: sha256b64u(opts.consentToken),
      action: opts.action,
      result,
      error: result === 'error' ? opts.error : null,
      error_description: opts.errorDescription ?? null,
      request_ref: requestRef,
      details_hash: opts.detailsHash ?? (opts.details !== undefined ? jsonHash(opts.details) : null),
      business_ref: opts.businessRef ?? null,
      mandate_ref: opts.mandateRef ?? null,
    });
  }

  /**
   * File a receipt in the session's index (either participant may file any
   * receipt of the session). Returns the broker's signed acknowledgment. A
   * receipt already filed (by you or the other agent) returns its original
   * acknowledgment with `duplicate: true`. File before the session is closed.
   * `kind` files an AP2 Checkout or Payment Receipt unchanged.
   */
  async fileActionReceipt(sessionId: string, receipt: string, opts: { kind?: ReceiptKind } = {}): Promise<ActionReceiptAck> {
    const url = `${this.brokerUrl}/sessions/${encodeURIComponent(sessionId)}/action-receipts`;
    try {
      const raw = await request<Record<string, unknown>>(url, {
        ...(await this.agentHttpOpts('POST', url, { session_id: sessionId })),
        method: 'POST',
        body: { receipt, ...(opts.kind ? { kind: opts.kind } : {}) },
      });
      return ackFromResponse(raw, false);
    } catch (err) {
      if (err instanceof ConflictError && err.code === 'duplicate_receipt' && err.body && typeof err.body.acknowledgment === 'string') {
        return ackFromResponse(err.body, true);
      }
      throw err;
    }
  }

  /**
   * Sign an action receipt as the loaded agent and file it: the one-call
   * replacement for `recordAction()`. Returns the receipt (send it back to the
   * other agent) and the broker's acknowledgment.
   */
  async recordActionReceipt(opts: SignActionReceiptOptions): Promise<RecordActionReceiptResult> {
    const receipt = await this.signActionReceipt(opts);
    const ack = await this.fileActionReceipt(opts.sessionId, receipt);
    return { receipt, ack };
  }

  /** The session's index: every receipt filed so far, as filed, with its acknowledgment. Either participant. */
  async getActionReceipts(sessionId: string): Promise<SessionIndex> {
    const url = `${this.brokerUrl}/sessions/${encodeURIComponent(sessionId)}/action-receipts`;
    const raw = await request<{ session_id: string; chain_head: string | null; entries: Record<string, unknown>[] }>(url, {
      ...(await this.agentHttpOpts('GET', url, { session_id: sessionId })),
      method: 'GET',
    });
    return {
      sessionId: raw.session_id,
      chainHead: raw.chain_head,
      entries: raw.entries.map((e) => ({
        seq: e.seq as number,
        kind: e.kind as string,
        receipt: e.receipt as string,
        receiptHash: e.receipt_hash as string,
        receiptIss: e.receipt_iss as string,
        issuerVerified: e.issuer_verified as boolean,
        action: e.action as string,
        result: e.result as 'success' | 'error',
        error: (e.error as string) ?? null,
        businessRef: (e.business_ref as string) ?? null,
        prev: (e.prev as string) ?? null,
        entryHash: e.entry_hash as string,
        indexedAt: e.indexed_at as string,
        filedBy: (e.filed_by as string) ?? null,
        acknowledgment: e.acknowledgment as string,
        ...mandateCheck(e),
      })),
    };
  }

  // ── AP2 mandates (broker A1) ─────────────────────────────────────────────────

  /**
   * Have the broker verify an AP2 mandate presented to you (you are the
   * merchant, or the credential provider): the Delegate SD-JWT chain against
   * the issuers you trust, every constraint, the checkout binding. Returns the
   * AP2 error code to put in your Checkout or Payment Receipt when it fails,
   * the receipt `reference` both ways, and the registered agent holding the
   * mandate's agent key. The broker records the redemption: presenting the
   * same mandate (or another for the same checkout) again gets
   * `alreadyRedeemed: true`. Authenticates as the loaded agent (credential and
   * proof); with only an API key, pass `agentId`.
   */
  async verifyMandate(opts: VerifyMandateOptions): Promise<VerifyMandateResult> {
    if (!opts.mandate) throw new ValidationError('mandate is required', 'validation_error');
    const url = `${this.brokerUrl}/ap2/mandates/verify`;
    const creds = this.credentials;
    const acting = opts.agentId ?? creds?.agentId;
    if (!acting) throw new ValidationError('Load the verifying agent (register() or loadCredentials()) or pass agentId', 'no_credentials');
    const body: Record<string, unknown> = { mandate: opts.mandate };
    if (opts.sessionId) body.session_id = opts.sessionId;
    if (opts.agentId) body.agent_id = opts.agentId;
    if (opts.checkoutJwt) body.checkout_jwt = opts.checkoutJwt;
    if (opts.checkoutHash) body.checkout_hash = opts.checkoutHash;
    if (opts.checkoutMandate) body.checkout_mandate = opts.checkoutMandate;
    if (opts.expectedAudience) body.expected_audience = opts.expectedAudience;
    if (opts.expectedNonce) body.expected_nonce = opts.expectedNonce;
    if (opts.trustedIssuers) body.trusted_issuers = opts.trustedIssuers;
    if (opts.context) {
      body.context = {
        ...(opts.context.totalAmount !== undefined ? { total_amount: opts.context.totalAmount } : {}),
        ...(opts.context.totalUses !== undefined ? { total_uses: opts.context.totalUses } : {}),
        ...(opts.context.lastUsedAt !== undefined ? { last_used_at: opts.context.lastUsedAt } : {}),
      };
    }
    if (opts.redeem !== undefined) body.redeem = opts.redeem;
    const claims = opts.sessionId ? { session_id: opts.sessionId } : { agent_id: acting };
    try {
      const raw = await request<Record<string, unknown>>(url, { ...(await this.agentHttpOpts('POST', url, claims, acting)), method: 'POST', body });
      return mandateResult(raw);
    } catch (err) {
      if (err instanceof ConflictError && err.body && err.body.reason === 'already_redeemed') return mandateResult(err.body);
      throw err;
    }
  }

  /**
   * Sign an AP2 Checkout or Payment Receipt as the loaded agent (AP2 change
   * request A3): once a merchant has accepted or rejected a mandate, AP2 says
   * it MUST return a receipt. ES256, so the agent needs a P-256 key.
   * `reference` is the AP2 SDK's form by default; `references` gives both.
   */
  async signAp2Receipt(opts: SignAp2ReceiptOptions): Promise<Ap2Receipt> {
    const creds = this.requireCredentials();
    let references = opts.references;
    try {
      references = references ?? (opts.mandate ? ap2MandateReferences(opts.mandate) : undefined);
    } catch (err) {
      throw new ValidationError((err as Error).message, 'validation_error');
    }
    if (!references) throw new ValidationError('Pass the mandate the receipt answers (mandate) or its references', 'validation_error');
    const reference = (opts.referenceForm ?? 'closed_jwt') === 'sd_hash' ? references.sdHash : references.closedJwt;
    const did = await this.agentDid();
    const claims = ap2ReceiptClaims(opts, opts.iss ?? did, reference);
    let receipt: string;
    try {
      receipt = await signAp2ReceiptJws(creds.privateKey, claims, `${did}#keys-1`);
    } catch (err) {
      throw new ValidationError((err as Error).message, 'validation_error');
    }
    return { receipt, kind: opts.kind === 'checkout' ? 'ap2.checkout_receipt' : 'ap2.payment_receipt', reference, references, claims };
  }

  /** Sign an AP2 receipt (see `signAp2Receipt`) and file it in the session's index. */
  async recordAp2Receipt(sessionId: string, opts: SignAp2ReceiptOptions): Promise<Ap2Receipt & { ack: ActionReceiptAck }> {
    const signed = await this.signAp2Receipt(opts);
    const ack = await this.fileActionReceipt(sessionId, signed.receipt, { kind: signed.kind });
    return { ...signed, ack };
  }

  // ── Interaction recording (before B6) ────────────────────────────────────────

  /**
   * @deprecated Use `recordActionReceipt()`: the acting agent signs what
   * happened and the broker indexes it. `/interaction/record` is being retired
   * (the broker will answer 410 Gone).
   *
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
      const keySet = jose.createLocalJWKSet((keys ?? (await this.getJwks(await this.unknownKid(jws, keys)))) as unknown as jose.JSONWebKeySet);
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
    let refreshHeaders: (() => Promise<Record<string, string>>) | undefined;
    if (this.credentials?.agentId === agentId && this.credentials.credential) {
      headers = { Authorization: `Bearer ${this.credentials.credential}`, ...(await this.proofHeader('POST', url, { agent_id: agentId })) };
      refreshHeaders = () => this.proofHeader('POST', url, { agent_id: agentId });
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
      ...(refreshHeaders ? { refreshHeaders } : {}),
      method: 'POST',
    });

    return {
      agentId: raw.agent_id,
      status: raw.status,
      revokedAt: raw.revoked_at,
    };
  }

  /**
   * Renew an agent's credential. The broker re-issues it when the principal's
   * verification tier changed, when the credential no longer shows the agent's
   * principal, operator or assurance (`identity_changed`, e.g. after a claim), or when it is
   * expired or within 7 days of expiry;
   * otherwise `renewed: false`. Authenticates with the API key; without one, the
   * loaded agent renews itself (credential + proof of possession), which is how
   * agents with no operator renew.
   */
  async renewCredential(agentId: string): Promise<RenewCredentialResult> {
    const url = `${this.brokerUrl}/agents/${agentId}/renew`;
    const selfOpts = () => this.agentHttpOpts('POST', url, { agent_id: agentId }, agentId);
    const send = async (opts: RequestOptions) => request<{
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
    let raw: Awaited<ReturnType<typeof send>>;
    if (!this.apiKey) {
      raw = await send(await selfOpts());
    } else {
      try {
        raw = await send(this.httpOpts);
      } catch (err) {
        // An agent with no operator renews only itself (the broker refuses the key):
        // if it is the loaded agent, renew it with its credential and a proof.
        if (!(err instanceof ConflictError && err.code === 'agent_renews_itself' && this.credentials?.agentId === agentId)) throw err;
        raw = await send(await selfOpts());
      }
    }

    // If renewed, update in-memory credential to the new one, and the file it came
    // from: the broker revoked the old credential, so a stale file locks the agent out.
    let saved: boolean | undefined;
    let saveError: string | undefined;
    if (raw.renewed && raw.credential && this.credentials?.agentId === agentId) {
      // Broker SPEC-002 decision 10: a self-registered agent's name became its
      // agent ID; the new credential says which name is current.
      let agentName = this.credentials.agentName;
      try {
        const name = jose.decodeJwt(raw.credential).name;
        if (typeof name === 'string' && name) agentName = name;
      } catch { /* keep the stored name */ }
      this.credentials = {
        ...this.credentials,
        agentName,
        credential: raw.credential,
        credentialSdJwt: raw.credential_sd_jwt ?? this.credentials.credentialSdJwt,
        issuedAt: raw.issued_at ?? this.credentials.issuedAt,
        expiresAt: raw.expires_at ?? this.credentials.expiresAt,
      };
      // Only the file that holds this agent (another agent may have been loaded from it).
      if (this.credentialFile && this.credentialFile.agentId === agentId) {
        try {
          await encryptCredentials(this.credentialFile.path, this.credentials, this.credentialFile.passphrase);
          saved = true;
        } catch (err) {
          saved = false;
          saveError = (err as Error).message;
        }
      }
    }

    return {
      ...(saved !== undefined ? { saved } : {}),
      ...(saveError ? { saveError } : {}),
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
      refreshHeaders: () => this.proofHeader('PUT', `${this.brokerUrl}/agents/${agentId}/scope-policies`, { agent_id: agentId }),
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
   * Retrieve reputation metrics (the track record) for one of your agents.
   * Returns raw trust signals computed from the agent's interaction history.
   * Only the agent's owner can read them (broker from 2026-10-08): with an API
   * key, an agent it manages; without one, the loaded agent itself (credential
   * and proof). Shops don't read other agents' signals: the broker checks their
   * reputation floors at the handshake.
   *
   * @throws {NotFoundError} 404 — agent not found
   * @throws {AuthError} 401 — no API key, and the agent isn't the loaded one
   * @throws {ForbiddenError} 403 — the API key doesn't manage this agent
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
      ...(!this.apiKey && this.credentials?.agentId === agentId
        ? await this.agentHttpOpts('GET', `${this.brokerUrl}/agents/${agentId}/metrics`, { agent_id: agentId }, agentId)
        : this.httpOpts),
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
