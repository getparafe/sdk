/**
 * Integration tests for ParafeClient.
 *
 * These tests run against a live broker instance.
 * Set PARAFE_TEST_BROKER_URL to point at your local or remote broker.
 * Set PARAFE_TEST_API_KEY to a valid API key.
 * Set PARAFE_TEST_ADMIN_KEY for admin-level checks (optional).
 *
 * Run the broker locally first:
 *   cd ../  &&  npm start
 *
 * Then:
 *   PARAFE_TEST_API_KEY=prf_key_live_... npm run test:integration
 */

import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { rm } from 'node:fs/promises';
import {
  ParafeClient,
  ValidationError,
} from '../src/index.js';

const BROKER_URL =
  process.env.PARAFE_TEST_BROKER_URL ?? 'http://localhost:3000';

const API_KEY = process.env.PARAFE_TEST_API_KEY ?? '';

// Skip all integration tests if no API key is configured
const SKIP = !API_KEY;
const maybeDescribe = SKIP ? describe.skip : describe;

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

  it('verified() returns correct shape with snake_case user_signature', () => {
    const auth = ParafeClient.authorization.verified({
      instruction: 'User approved',
      platform: 'web',
      userSignature: 'sig-abc',
    });
    expect(auth.modality).toBe('verified');
    if (auth.modality === 'verified') {
      expect(auth.evidence.user_signature).toBe('sig-abc');
      expect(typeof auth.evidence.timestamp).toBe('string');
    }
  });

  it('verified() throws ValidationError when userSignature is missing', () => {
    expect(() =>
      ParafeClient.authorization.verified({
        instruction: 'ok',
        platform: 'app',
        userSignature: '',
      })
    ).toThrow(ValidationError);
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

maybeDescribe('Full integration flow', () => {
  // We register two agents: initiator and target
  let initiatorClient: ParafeClient;
  let targetClient: ParafeClient;

  let initiatorAgentId: string;
  let targetAgentId: string;
  let sessionId: string;
  let consentToken: string;
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
      owner: 'SDK Test Suite',
    });

    expect(result.agentId).toMatch(/^prf_agent_/);
    expect(typeof result.credential).toBe('string');
    expect(typeof result.publicKey).toBe('string');
    expect(typeof result.privateKey).toBe('string');
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
      owner: 'SDK Test Suite',
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
    // Store for next step
    (globalThis as Record<string, unknown>).__testHandshakeId = result.handshakeId;
    (globalThis as Record<string, unknown>).__testChallenge = result.challengeForTarget;
  });

  // ── 5. Handshake — complete ────────────────────────────────────────────────

  test('completeHandshake() — target side', async () => {
    const handshakeId = (globalThis as Record<string, unknown>).__testHandshakeId as string;
    const challengeNonce = (globalThis as Record<string, unknown>).__testChallenge as string;

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

  // ── 7. Record actions ─────────────────────────────────────────────────────

  test('recordAction() — within scope', async () => {
    const result = await initiatorClient.recordAction({
      sessionId,
      agentId: initiatorAgentId,
      action: 'read_data',
      details: { resource: 'booking/123' },
      consentToken,
    });

    expect(result.recorded).toBe(true);
    expect(result.withinScope).toBe(true);
    expect(result.actionId).toMatch(/^act_/);
    expect(result.action).toBe('read_data');
  });

  // ── 8. Close session ──────────────────────────────────────────────────────

  test('closeSession() — returns signed receipt', async () => {
    const result = await initiatorClient.closeSession(sessionId);

    expect(result.receipt_id).toMatch(/^rcpt_/);
    expect(result.session_id).toBe(sessionId);
    expect(typeof result.signature).toBe('string');
    expect(result.signed_by).toBe('parafe-broker');
    expect(result.participants.initiator.agent_id).toBe(initiatorAgentId);
    expect(result.participants.target.agent_id).toBe(targetAgentId);

    receipt = result as unknown as Record<string, unknown>;
  });

  // ── 9. Verify receipt ─────────────────────────────────────────────────────

  test('verifyReceipt() — valid receipt', async () => {
    // Need to import the SessionReceipt type — use the receipt object we got
    const result = await initiatorClient.verifyReceipt(
      receipt as Parameters<typeof initiatorClient.verifyReceipt>[0]
    );

    expect(result.valid).toBe(true);
    expect(result.tamperDetected).toBe(false);
    expect(result.signedBy).toBe('parafe-broker');
  });

  test('verifyReceipt() — tampered receipt returns tamper_detected=true', async () => {
    const tampered = {
      ...receipt,
      participants: {
        ...(receipt.participants as Record<string, unknown>),
        initiator: {
          ...((receipt.participants as Record<string, unknown>).initiator as Record<string, unknown>),
          agent_name: 'tampered-name',
        },
      },
    };

    const result = await initiatorClient.verifyReceipt(
      tampered as Parameters<typeof initiatorClient.verifyReceipt>[0]
    );
    expect(result.valid).toBe(false);
    expect(result.tamperDetected).toBe(true);
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
      owner: 'SDK Test Suite',
    });
    const tgtReg = await tgtClient.register({
      name: uniqueName('sdk-esc-tgt'),
      type: 'enterprise',
      owner: 'SDK Test Suite',
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
    });

    expect(escalated.sessionId).toBe(completed.sessionId);
    expect(escalated.consentToken.scope).toBe('escalated-scope');
    expect(escalated.consentToken.token).toBeTruthy();

    // Close the session
    await iniClient.closeSession(completed.sessionId);
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

maybeDescribe('Error handling', () => {
  test('register() with invalid agent_name throws ValidationError', async () => {
    const client = makeClient();
    await expect(
      client.register({
        name: 'INVALID NAME WITH SPACES',
        type: 'enterprise',
        owner: 'Test',
      })
    ).rejects.toThrow(ValidationError);
  });

  test('completeHandshake() with nonexistent handshake_id throws NotFoundError', async () => {
    const client = makeClient();
    await client.register({
      name: uniqueName('sdk-err-test'),
      type: 'enterprise',
      owner: 'Test',
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
