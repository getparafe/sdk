/**
 * Unit tests for SDK 0.3.2 (AP2 change request B1, B3). No network: fetch is stubbed.
 *
 * B1: verifyConsentLocally() reads the broker's `excluded` claim (it used to read
 *     `exclusions`, so it always reported nothing excluded) and pins the issuer.
 * B3: closeSession() keeps the receipt exactly as issued under `issued`, and
 *     verifyReceipt() sends that, so a field the SDK doesn't model can't break it.
 */

import { generateKeyPairSync } from 'node:crypto';
import { jest } from '@jest/globals';
import * as jose from 'jose';
import { ParafeClient } from '../src/index.js';
import type { SessionReceipt } from '../src/types.js';

// ─── B1: verifyConsentLocally ────────────────────────────────────────────────

const { privateKey, publicKey } = generateKeyPairSync('ed25519');
const PUBLIC_KEY_B64 = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

async function consentToken(claims: Record<string, unknown>, issuer = 'parafe-trust-broker'): Promise<string> {
  return new jose.SignJWT({ token_type: 'consent', scope: 'place-order', session_id: 'sess_1', ...claims })
    .setProtectedHeader({ alg: 'EdDSA' })
    .setIssuedAt()
    .setExpirationTime('5m')
    .setIssuer(issuer)
    .sign(privateKey);
}

describe('verifyConsentLocally() (B1)', () => {
  const client = new ParafeClient({ brokerUrl: 'https://broker.test', retries: 0 });

  it("reports the broker's `excluded` claim as exclusions", async () => {
    const token = await consentToken({ permissions: ['create_order'], excluded: ['issue_refund'] });
    const result = await client.verifyConsentLocally(token, PUBLIC_KEY_B64);
    expect(result.valid).toBe(true);
    expect(result.permissions).toEqual(['create_order']);
    expect(result.exclusions).toEqual(['issue_refund']);
  });

  it('also reads an `exclusions` claim', async () => {
    const token = await consentToken({ permissions: ['create_order'], exclusions: ['issue_refund'] });
    const result = await client.verifyConsentLocally(token, PUBLIC_KEY_B64);
    expect(result.exclusions).toEqual(['issue_refund']);
  });

  it('returns expired: true for an expired token instead of throwing', async () => {
    const token = await new jose.SignJWT({ token_type: 'consent', scope: 's', session_id: 'sess_1', permissions: [], excluded: ['x'] })
      .setProtectedHeader({ alg: 'EdDSA' })
      .setIssuedAt(Math.floor(Date.now() / 1000) - 600)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 300)
      .setIssuer('parafe-trust-broker')
      .sign(privateKey);
    const result = await client.verifyConsentLocally(token, PUBLIC_KEY_B64);
    expect(result.valid).toBe(false);
    expect(result.expired).toBe(true);
    expect(result.exclusions).toEqual(['x']);
  });

  it('rejects a broker JWT that is not a consent token (e.g. an agent credential)', async () => {
    const token = await consentToken({ token_type: undefined, sub: 'prf_agent_alex01' });
    await expect(client.verifyConsentLocally(token, PUBLIC_KEY_B64)).rejects.toThrow('Not a Parafe consent token');
  });

  it('rejects a token from another issuer, even with a valid signature', async () => {
    const token = await consentToken({ permissions: ['create_order'] }, 'someone-else');
    await expect(client.verifyConsentLocally(token, PUBLIC_KEY_B64)).rejects.toThrow();
  });
});

// ─── B3: receipts as issued ──────────────────────────────────────────────────

const ISSUED = {
  receipt_id: 'rcpt_1', session_id: 'sess_1', handshake_id: 'hs_1',
  participants: {
    initiator: { agent_id: 'prf_agent_alex01', agent_name: 'alex', identity_assurance: 'registered' },
    target: { agent_id: 'prf_agent_shop01', agent_name: 'shop', identity_assurance: 'registered' },
  },
  handshake: { handshake_id: 'hs_1', mutual_auth_completed: true, completed_at: '2026-09-28T00:00:00.000Z' },
  consent_tokens: [{
    scope: 'place-order', permissions: ['create_order'],
    authorization: { modality: 'attested', evidence: { instruction: 'order', platform: 'cli', timestamp: '2026-09-28T00:00:00.000Z' } },
    issued_at: '2026-09-28T00:00:00.000Z', expired_at: '2026-09-28T00:05:00.000Z',
  }],
  session: { started_at: '2026-09-28T00:00:00.000Z', closed_at: '2026-09-28T00:01:00.000Z', status: 'completed' },
  signed_by: 'parafe-broker', issued_at: '2026-09-28T00:01:00.000Z', signature: 'sig',
};

let verifyBodies: unknown[] = [];
const realFetch = globalThis.fetch;

beforeEach(() => {
  verifyBodies = [];
  globalThis.fetch = jest.fn(async (url: unknown, init?: RequestInit) => {
    let body: unknown;
    if (String(url).endsWith('/session/close')) {
      body = ISSUED;
    } else {
      verifyBodies.push(JSON.parse(String(init?.body)));
      body = { valid: true, signed_by: 'parafe-broker', receipt_id: 'rcpt_1', tamper_detected: false };
    }
    return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });
  }) as typeof fetch;
});
afterAll(() => {
  globalThis.fetch = realFetch;
});

describe('closeSession() / verifyReceipt() (B3)', () => {
  const client = new ParafeClient({ brokerUrl: 'https://broker.test', apiKey: 'prf_key_live_user_test', retries: 0 });

  it('keeps the receipt exactly as issued under `issued`', async () => {
    const receipt = await client.closeSession('sess_1');
    expect(receipt.receiptId).toBe('rcpt_1');
    expect(receipt.issued).toEqual(ISSUED);
  });

  it('verifies by sending the issued receipt, not a rebuilt one', async () => {
    const receipt = await client.closeSession('sess_1');
    const result = await client.verifyReceipt(receipt);
    expect(result.valid).toBe(true);
    expect(verifyBodies).toEqual([{ receipt: ISSUED }]);
  });

  it('survives a JSON round trip (a saved receipt)', async () => {
    const receipt = JSON.parse(JSON.stringify(await client.closeSession('sess_1'))) as SessionReceipt;
    const result = await client.verifyReceipt(receipt);
    expect(result.valid).toBe(true);
    expect(verifyBodies).toEqual([{ receipt: ISSUED }]);
  });

  it('reports tampering when the readable fields no longer match the issued receipt', async () => {
    const receipt = await client.closeSession('sess_1');
    const tampered: SessionReceipt = {
      ...receipt,
      participants: { ...receipt.participants, initiator: { ...receipt.participants.initiator, agentName: 'mallory' } },
    };
    const result = await client.verifyReceipt(tampered);
    expect(result.valid).toBe(false);
    expect(result.tamperDetected).toBe(true);
    expect(verifyBodies).toEqual([]);
  });

  it('still rebuilds receipts from SDK 0.3.1 and earlier (no `issued`)', async () => {
    const { issued: _issued, ...legacy } = await client.closeSession('sess_1');
    await client.verifyReceipt(legacy as SessionReceipt);
    expect(verifyBodies).toHaveLength(1);
    expect((verifyBodies[0] as { receipt: Record<string, unknown> }).receipt.receipt_id).toBe('rcpt_1');
  });
});
