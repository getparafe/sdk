/**
 * Integration tests for ParafeClient.
 *
 * These tests run against a live broker instance.
 * Set PARAFE_TEST_BROKER_URL to point at your local or remote broker.
 * Default: http://localhost:3000
 *
 * No API key is needed — the tests create a fresh org and developer
 * at the start of each run via POST /auth/signup.
 *
 * Run the broker locally first:
 *   cd ../broker && npm start
 *
 * Then:
 *   npm run test:integration
 */

import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { rm } from 'node:fs/promises';
import {
  ParafeClient,
  ValidationError,
  ForbiddenError,
} from '../src/index.js';

const BROKER_URL =
  process.env.PARAFE_TEST_BROKER_URL ?? 'http://localhost:3000';

const RUN_ID = Date.now().toString(36);
let API_KEY = '';

// ─── Bootstrap ───────────────────────────────────────────────────────────────

async function bootstrapTestApiKey(brokerUrl: string): Promise<string> {
  const res = await fetch(`${brokerUrl}/auth/signup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      org_name: `SDK Test ${RUN_ID}`,
      email: `sdk-test-${RUN_ID}@example.com`,
      password: `sdk-test-password-${RUN_ID}`,
      name: 'SDK Test Developer',
    }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(`Test bootstrap failed: could not create test account on ${brokerUrl} (${res.status}): ${JSON.stringify(body)}`);
  }
  const body = await res.json() as { api_key: { key: string } };
  return body.api_key.key;
}

beforeAll(async () => {
  API_KEY = await bootstrapTestApiKey(BROKER_URL);
}, 30_000);

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeClient() {
  return new ParafeClient({
    brokerUrl: BROKER_URL,
    apiKey: API_KEY,
    timeout: 15_000,
    retries: 1,
  });
}

function uniqueName(prefix: string) {
  return `${prefix}-${Date.now()}-${Math.floor(Math.random() * 10000)}`;
}

// ─── Authorization helpers (static, no network) ───────────────────────────────

describe('ParafeClient.authorization helpers', () => {
  it('autonomous() returns correct shape', () => {
    const auth = ParafeClient.authorization.autonomous();
    expect(auth).toEqual({ modality: 'autonomous' });
  });

  it('attested() returns correct shape with auto-timestamp', () => {
    const auth = ParafeClient.authorization.attested({
      instruction: 'User requested X',
      platform: 'test-platform',
    });
    expect(auth.modality).toBe('attested');
    if (auth.modality === 'attested') {
      expect(auth.evidence.instruction).toBe('User requested X');
      expect(auth.evidence.platform).toBe('test-platform');
      expect(typeof auth.evidence.timestamp).toBe('string');
    }
  });

  it('attested() uses provided timestamp', () => {
    const ts = '2026-01-01T00:00:00.000Z';
    const auth = ParafeClient.authorization.attested({
      instruction: 'Test',
      platform: 'app',
      timestamp: ts,
    });
    if (auth.modality === 'attested') {
      expect(auth.evidence.timestamp).toBe(ts);
    }
  });

  it('attested() throws ValidationError when instruction is missing', () => {
    expect(() =>
      ParafeClient.authorization.attested({ instruction: '', platform: 'app' })
    ).toThrow(ValidationError);
  });

  it('attested() throws ValidationError when platform is missing', () => {
    expect(() =>
      ParafeClient.authorization.attested({ instruction: 'ok', platform: '' })
    ).toThrow(ValidationError);
  });

  it('verified() and delegated() carry the AP2 mandate as evidence (B8)', () => {
    const v = ParafeClient.authorization.verified({ mandate: 'root~', checkoutJwt: 'cj' });
    expect(v).toEqual({ modality: 'verified', evidence: { ap2_mandate: 'root~', checkout_jwt: 'cj' } });
    const d = ParafeClient.authorization.delegated({ mandate: 'open~~closed~', checkoutMandate: 'co~' });
    expect(d).toEqual({ modality: 'delegated', evidence: { ap2_mandate: 'open~~closed~', checkout_mandate: 'co~' } });
  });

  it('verified() refuses a bare signature string or a missing mandate', () => {
    expect(() =>
      // A pre-B8 caller: the broker never accepted this.
      ParafeClient.authorization.verified({ instruction: 'ok', platform: 'app', userSignature: 'sig' } as never)
    ).toThrow(/AP2 mandate/);
    expect(() => ParafeClient.authorization.delegated({ mandate: '' })).toThrow(ValidationError);
  });
});

// ─── credentialStatus() before loading ───────────────────────────────────────

describe('ParafeClient credential state', () => {
  it('credentialStatus() returns { loaded: false } initially', () => {
    const client = makeClient();
    expect(client.credentialStatus()).toEqual({ loaded: false });
  });

  it('exportKeys() throws ValidationError when no credentials loaded', () => {
    const client = makeClient();
    expect(() => client.exportKeys()).toThrow(ValidationError);
  });
});

// ─── Full integration flow ────────────────────────────────────────────────────

describe('Full integration flow', () => {
  // We register two agents: initiator and target
  let initiatorClient: ParafeClient;
  let targetClient: ParafeClient;

  let initiatorAgentId: string;
  let targetAgentId: string;
  let sessionId: string;
  let consentToken: string;
  let handshakeId: string;
  let challengeNonce: string;
  let receipt: Record<string, unknown>;

  beforeAll(async () => {
    initiatorClient = makeClient();
    targetClient = makeClient();
  });

  // ── 1. Register initiator agent ────────────────────────────────────────────

  test('register() — initiator agent', async () => {
    const result = await initiatorClient.register({
      name: uniqueName('sdk-initiator'),
      type: 'enterprise',
      principalName: 'SDK Test Suite',
    });

    expect(result.agentId).toMatch(/^prf_agent_/);
    expect(typeof result.credential).toBe('string');
    expect(typeof result.publicKey).toBe('string');
    expect(typeof result.privateKey).toBe('string');
    expect(Buffer.from(result.publicKey, 'base64').length).toBe(91); // P-256 SPKI, the default since 0.8.0
    expect(typeof result.issuedAt).toBe('string');
    expect(typeof result.expiresAt).toBe('string');

    initiatorAgentId = result.agentId;

    // credentialStatus should now be loaded
    const status = initiatorClient.credentialStatus();
    expect(status.loaded).toBe(true);
    if (status.loaded) {
      expect(status.agentId).toBe(initiatorAgentId);
      expect(status.expired).toBe(false);
    }
  });

  // ── 2. Register target agent (with scope policies) ─────────────────────────

  test('register() — target agent with scope policies', async () => {
    const result = await targetClient.register({
      name: uniqueName('sdk-target'),
      type: 'enterprise',
      principalName: 'SDK Test Suite',
      scopePolicies: {
        'sdk-test-scope': {
          permissions: ['read_data', 'write_data'],
          exclusions: ['delete_all'],
          minimum_authorization_modality: 'autonomous',
        },
      },
    });

    expect(result.agentId).toMatch(/^prf_agent_/);
    targetAgentId = result.agentId;
  });

  // ── 3. Credential round-trip: save + load ──────────────────────────────────

  test('saveCredentials() + loadCredentials() round-trip', async () => {
    const filePath = join(tmpdir(), `parafe-int-test-${Date.now()}.enc`);
    try {
      await initiatorClient.saveCredentials(filePath, 'integration-passphrase');

      // Load into a fresh client
      const freshClient = makeClient();
      await freshClient.loadCredentials(filePath, 'integration-passphrase');

      const status = freshClient.credentialStatus();
      expect(status.loaded).toBe(true);
      if (status.loaded) {
        expect(status.agentId).toBe(initiatorAgentId);
      }

      // exportKeys should work
      const keys = freshClient.exportKeys();
      expect(typeof keys.publicKey).toBe('string');
      expect(typeof keys.privateKey).toBe('string');
      expect(typeof keys.credential).toBe('string');
    } finally {
      await rm(filePath, { force: true });
    }
  });

  // ── 4. Handshake — initiate ────────────────────────────────────────────────

  test('handshake() — initiate', async () => {
    const result = await initiatorClient.handshake({
      targetAgentId,
      scope: 'sdk-test-scope',
      permissions: ['read_data'],
      authorization: ParafeClient.authorization.autonomous(),
    });

    expect(result.handshakeId).toMatch(/^hs_/);
    expect(typeof result.challengeForTarget).toBe('string');
    handshakeId = result.handshakeId;
    challengeNonce = result.challengeForTarget;
  });

  // ── 5. Handshake — complete ────────────────────────────────────────────────

  test('completeHandshake() — target side', async () => {
    const result = await targetClient.completeHandshake({ handshakeId, challengeNonce });

    expect(result.handshakeId).toBe(handshakeId);
    expect(result.sessionId).toMatch(/^sess_/);
    expect(result.consentToken.token).toBeTruthy();
    expect(result.consentToken.scope).toBe('sdk-test-scope');

    sessionId = result.sessionId;
    consentToken = result.consentToken.token;
  });

  // ── 6. Verify consent ─────────────────────────────────────────────────────

  test('verifyConsent() — permitted action', async () => {
    const result = await initiatorClient.verifyConsent({
      consentToken,
      action: 'read_data',
      sessionId,
    });

    expect(result.valid).toBe(true);
    expect(result.permitted).toBe(true);
    expect(result.action).toBe('read_data');
  });

  test('verifyConsent() — excluded action', async () => {
    const result = await initiatorClient.verifyConsent({
      consentToken,
      action: 'delete_all',
      sessionId,
    });

    expect(result.valid).toBe(true);
    expect(result.permitted).toBe(false);
  });

  // ── 7. Action receipts (B6) ───────────────────────────────────────────────

  let actionReceipt: string;
  let refusalReceipt: string;

  test('recordActionReceipt() — the target signs what it did and files it; the broker acknowledges it', async () => {
    const result = await targetClient.recordActionReceipt({
      sessionId, consentToken, action: 'read_data', details: { resource: 'booking/123' }, businessRef: 'booking/123',
    });
    expect(result.receipt.split('.')).toHaveLength(3);
    expect(result.ack.seq).toBe(1);
    expect(result.ack.duplicate).toBe(false);
    expect(result.ack.claims.receipt_iss).toMatch(/^did:web:.*:agents:/);
    actionReceipt = result.receipt;
  });

  test('fileActionReceipt() — the initiator filing the same receipt gets the original acknowledgment', async () => {
    const ack = await initiatorClient.fileActionReceipt(sessionId, actionReceipt);
    expect(ack.duplicate).toBe(true);
    expect(ack.seq).toBe(1);
  });

  test('signActionReceipt() — a refusal is receipted too; the initiator files it when the target does not', async () => {
    refusalReceipt = await targetClient.signActionReceipt({
      sessionId, consentToken, action: 'delete_all', result: 'error', error: 'excluded', errorDescription: 'delete_all is excluded',
    });
    const ack = await initiatorClient.fileActionReceipt(sessionId, refusalReceipt);
    expect(ack.seq).toBe(2);
    const index = await initiatorClient.getActionReceipts(sessionId);
    expect(index.entries.map((e) => [e.action, e.result, e.error])).toEqual([['read_data', 'success', null], ['delete_all', 'error', 'excluded']]);
    expect(index.chainHead).toBe(index.entries[1].entryHash);
  });

  test('verifyConsentLocally() — verifies against the broker JWKS; the token is key-bound', async () => {
    const local = await targetClient.verifyConsentLocally(consentToken);
    expect(local.valid).toBe(true);
    expect(local.initiatorAgentId).toBe(initiatorAgentId);
    expect(local.keyThumbprint).toBeTruthy();
    expect(local.initiatorProof).toBe('pop');
    expect(local.targetAgentId).toBe(targetAgentId);
  });

  test('a token checked for another agent is refused (S-69: wrong_audience)', async () => {
    await expect(initiatorClient.verifyConsentLocally(consentToken, undefined, { agentId: initiatorAgentId })).rejects.toMatchObject({ code: 'wrong_audience' });
    await expect(initiatorClient.verifyConsent({ consentToken, action: 'read_data', sessionId, agentId: initiatorAgentId })).rejects.toMatchObject({ code: 'wrong_audience' });
  });

  test('verifyConsent() with a presentation proof — the broker checks it against cnf.jkt', async () => {
    const proof = await initiatorClient.createPresentationProof(consentToken, 'msg-1');
    const result = await targetClient.verifyConsent({ consentToken, action: 'read_data', sessionId, presentationProof: proof });
    expect(result.permitted).toBe(true);
    expect(result.keyBound).toBe(true);
    expect(result.proofVerified).toBe(true);
    // A proof by another agent's key is refused.
    const forged = await targetClient.createPresentationProof(consentToken);
    await expect(targetClient.verifyConsent({ consentToken, action: 'read_data', sessionId, presentationProof: forged })).rejects.toThrow();
  });

  // ── 8. Close session ──────────────────────────────────────────────────────

  test('closeSession() — returns the signed receipt (a JWS) and its decoded view', async () => {
    const result = await initiatorClient.closeSession(sessionId);

    expect(result.formatVersion).toBe(2);
    expect(result.receiptId).toMatch(/^rcpt_/);
    expect(result.sessionId).toBe(sessionId);
    expect(result.receipt.split('.')).toHaveLength(3);
    expect(result.issuer).toMatch(/^did:web:/);
    expect(result.participants.initiator.agentId).toBe(initiatorAgentId);
    expect(result.participants.target.agentId).toBe(targetAgentId);
    expect(result.session.closedBy).toBe(initiatorAgentId);
    expect(result.consentTokens[0].initiatorProof).toBe('pop');
    expect(result.actions.map((a) => [a.seq, a.action, a.result, a.error])).toEqual([[1, 'read_data', 'success', null], [2, 'delete_all', 'error', 'excluded']]);
    expect(result.chainHead).toBeTruthy();

    receipt = result as unknown as Record<string, unknown>;
  });

  test('getReceipt() — the target gets the identical receipt (B5)', async () => {
    const got = await targetClient.getReceipt(sessionId);
    expect(got.formatVersion).toBe(2);
    expect((got as import('../src/types.js').SessionReceipt).receipt).toBe((receipt as { receipt: string }).receipt);
  });

  // ── 9. Verify receipt ─────────────────────────────────────────────────────

  test('verifyReceipt() / verifyReceiptLocally() — valid receipt', async () => {
    const typed = receipt as unknown as import('../src/types.js').SessionReceipt;
    const result = await initiatorClient.verifyReceipt(typed);
    expect(result.valid).toBe(true);
    expect(result.tamperDetected).toBe(false);
    expect(result.signedBy).toMatch(/^did:web:/);
    expect((await initiatorClient.verifyReceiptLocally(typed)).valid).toBe(true);
  });

  test('verifyReceipt() — tampered receipt returns tamper_detected=true', async () => {
    const jws = (receipt as { receipt: string }).receipt;
    const [h, p, sig] = jws.split('.');
    const claims = JSON.parse(Buffer.from(p, 'base64url').toString());
    claims.participants.initiator.agent_name = 'tampered-name';
    const tampered = `${h}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.${sig}`;

    const result = await initiatorClient.verifyReceipt(tampered);
    expect(result.valid).toBe(false);
    expect(result.tamperDetected).toBe(true);
    expect((await initiatorClient.verifyReceiptLocally(tampered)).valid).toBe(false);
  });

  // ── 10. Scope escalation ─────────────────────────────────────────────────

  test('escalateScope() — issues new consent token on existing session', async () => {
    // First, we need a new session (the previous one was closed)
    // Register fresh agents to run this isolated test
    const iniClient = makeClient();
    const tgtClient = makeClient();

    await iniClient.register({
      name: uniqueName('sdk-esc-ini'),
      type: 'enterprise',
      principalName: 'SDK Test Suite',
    });
    const tgtReg = await tgtClient.register({
      name: uniqueName('sdk-esc-tgt'),
      type: 'enterprise',
      principalName: 'SDK Test Suite',
      scopePolicies: {
        'base-scope': { permissions: ['read'] },
        'escalated-scope': { permissions: ['read', 'write'] },
      },
    });

    // Initiate + complete handshake for base-scope
    const hs = await iniClient.handshake({
      targetAgentId: tgtReg.agentId,
      scope: 'base-scope',
      permissions: ['read'],
    });
    const completed = await tgtClient.completeHandshake({
      handshakeId: hs.handshakeId,
      challengeNonce: hs.challengeForTarget,
    });

    // Now escalate scope without re-handshaking
    const escalated = await iniClient.escalateScope({
      sessionId: completed.sessionId,
      targetAgentId: tgtReg.agentId,
      scope: 'escalated-scope',
      permissions: ['read', 'write'],
      authorization: ParafeClient.authorization.attested({ instruction: 'User asked to update the booking', platform: 'sdk-tests' }),
    });

    expect(escalated.sessionId).toBe(completed.sessionId);
    expect(escalated.consentToken.scope).toBe('escalated-scope');
    expect(escalated.consentToken.token).toBeTruthy();
    // The receipt's evidence hash is salted; the salt comes with the token (none without evidence).
    expect(escalated.consentToken.evidenceSalt).toMatch(/^[A-Za-z0-9_-]{22}$/);
    expect(completed.consentToken.evidenceSalt).toBeNull();
    expect(hs.evidenceSalt).toBeNull();

    // Close the session
    await iniClient.closeSession(completed.sessionId);
  });

  test('an Ed25519 agent (no longer the default, still accepted) runs the whole flow', async () => {
    const ini = makeClient();
    const tgt = makeClient();
    const iniReg = await ini.register({ name: uniqueName('sdk-ed25519-ini'), type: 'enterprise', principalName: 'SDK Test Suite', keyAlgorithm: 'Ed25519' });
    expect(iniReg.credentialSdJwt).toBeTruthy();
    expect(Buffer.from(iniReg.publicKey, 'base64').length).toBe(44); // Ed25519 SPKI
    const tgtReg = await tgt.register({ name: uniqueName('sdk-ed25519-tgt'), type: 'enterprise', principalName: 'SDK Test Suite', keyAlgorithm: 'Ed25519', scopePolicies: { s: { permissions: ['read'], minimum_initiator_proof: 'pop' } } });
    const hs = await ini.handshake({ targetAgentId: tgtReg.agentId, scope: 's', permissions: ['read'] });
    const done = await tgt.completeHandshake({ handshakeId: hs.handshakeId, challengeNonce: hs.challengeForTarget });
    expect(done.consentToken.initiatorProof).toBe('pop');
    const r = await tgt.closeSession(done.sessionId);
    expect((await ini.verifyReceiptLocally(r)).valid).toBe(true);
  });

  // ── 11. updateScopePolicies() ────────────────────────────────────────────

  test('updateScopePolicies() — updates target agent scope policies', async () => {
    const newPolicies = {
      'updated-scope': {
        permissions: ['action_a', 'action_b'],
        exclusions: ['forbidden_action'],
        minimum_authorization_modality: 'attested' as const,
      },
    };

    const result = await targetClient.updateScopePolicies(targetAgentId, newPolicies);

    expect(result.agentId).toBe(targetAgentId);
    expect(result.scopePolicies).toEqual(newPolicies);
    expect(typeof result.updatedAt).toBe('string');
  });

  // ── 12. revokeAgent() ────────────────────────────────────────────────────

  test('revokeAgent() — revokes the initiator agent', async () => {
    const result = await initiatorClient.revokeAgent(initiatorAgentId);
    expect(result.agentId).toBe(initiatorAgentId);
    expect(result.status).toBe('revoked');
    expect(typeof result.revokedAt).toBe('string');
  });
});

// ─── Error handling ───────────────────────────────────────────────────────────

describe('Self-registered agents and claim links (Phase 1.5)', () => {
  // An agent registered with no API key gets a claim link for the person it acts for.
  const keyless = new ParafeClient({ brokerUrl: BROKER_URL, timeout: 15_000, retries: 1 });
  let firstCode = '';

  test('keyless register() returns claimLink', async () => {
    const result = await keyless.register({ name: uniqueName('sdk-claim'), type: 'assistant', principalName: 'SDK Test Person' });
    expect(result.identityAssurance).toBe('self_registered');
    expect(result.claimLink?.code).toMatch(/^[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{2}$/);
    expect(result.claimLink?.url).toContain('/claim?code=');
    firstCode = result.claimLink!.code;
  });

  test('createClaimLink() replaces the link; getClaimStatus() says unclaimed', async () => {
    const link = await keyless.createClaimLink();
    expect(link.code).not.toBe(firstCode);
    const status = await keyless.getClaimStatus();
    expect(status).toEqual({
      claimed: false, identityAssurance: 'self_registered', verificationTier: 'unverified', principalTier: null, operatorType: null, operatorId: null, principalType: null, principalRef: null, credentialCurrent: true,
      registeredAt: expect.any(String),
    });
  });

  test("getAgentMetrics() reads the agent's own track record (signed with its key); another agent's is refused", async () => {
    const own = await keyless.getAgentMetrics((keyless.credentialStatus() as { agentId: string }).agentId);
    expect(own.tenureDays).toBeGreaterThanOrEqual(0);
    const other = makeClient();
    const o = await other.register({ name: uniqueName('sdk-metrics-other'), type: 'enterprise', principalName: 'SDK Test Suite' });
    await expect(keyless.getAgentMetrics(o.agentId)).rejects.toMatchObject({ statusCode: 401 });
  });

  test('a handshake refused for tier carries the claim link', async () => {
    const target = makeClient();
    const t = await target.register({
      name: uniqueName('sdk-claim-target'), type: 'enterprise', principalName: 'SDK Test Suite',
      scopePolicies: { 'place-order': { permissions: ['create_order'], minimum_verification_tier: 'email_verified' } },
    });
    const err = await keyless.handshake({ targetAgentId: t.agentId, scope: 'place-order', permissions: ['create_order'] }).catch((e) => e);
    expect(err).toBeInstanceOf(ForbiddenError);
    expect(err.code).toBe('tier_insufficient');
    expect(err.claim?.url).toContain('/claim?code=');
    expect(typeof err.hint).toBe('string');
  });
});

describe('Error handling', () => {
  test('register() with invalid agent_name throws ValidationError', async () => {
    const client = makeClient();
    await expect(
      client.register({
        name: 'INVALID NAME WITH SPACES',
        type: 'enterprise',
        principalName: 'Test',
      })
    ).rejects.toThrow(ValidationError);
  });

  test('completeHandshake() with nonexistent handshake_id throws NotFoundError', async () => {
    const client = makeClient();
    await client.register({
      name: uniqueName('sdk-err-test'),
      type: 'enterprise',
      principalName: 'Test',
    });

    const { NotFoundError } = await import('../src/errors.js');
    await expect(
      client.completeHandshake({
        handshakeId: 'hs_nonexistent',
        challengeNonce: 'a'.repeat(64),
      })
    ).rejects.toThrow(NotFoundError);
  });

  test('verifyConsent() with invalid token throws AuthError', async () => {
    const client = makeClient();
    const { AuthError } = await import('../src/errors.js');

    await expect(
      client.verifyConsent({
        consentToken: 'not.a.valid.jwt',
        action: 'read',
        sessionId: 'sess_fake',
      })
    ).rejects.toThrow(AuthError);
  });
});

describe('operator and principal (broker SPEC-002)', () => {
  test('register() with actsFor: the key holder registers an agent acting for one of its users', async () => {
    const platform = makeClient();
    const ref = `sdk-user-${RUN_ID}`;
    const r = await platform.register({ name: uniqueName('sdk-acts-for'), type: 'personal', principalName: 'Platform user', actsFor: { ref } });
    expect(r).toMatchObject({ principalType: 'external', principalId: null, principalRef: ref, operatorType: 'personal', verificationTier: 'unverified', identityAssurance: 'registered' });
    const status = await platform.getClaimStatus();
    expect(status).toMatchObject({ claimed: false, principalType: 'external', principalRef: ref, operatorType: 'personal', principalTier: null });
  });

  test('register() with an email as actsFor.ref is refused (refs are opaque)', async () => {
    await expect(makeClient().register({ name: uniqueName('sdk-acts-for-email'), type: 'personal', principalName: 'X', actsFor: { ref: 'alex@example.com' } }))
      .rejects.toThrow(ValidationError);
  });
});
