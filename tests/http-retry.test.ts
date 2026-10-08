/**
 * Unit tests: a retried request carries a fresh proof of possession (P-49).
 * A `Parafe-PoP` jti is single use, so resending the same proof after a 502
 * that reached the broker would be refused as replayed. No network: fetch is stubbed.
 */

import { generateKeyPairSync } from 'node:crypto';
import { jest } from '@jest/globals';
import * as jose from 'jose';
import { ParafeClient } from '../src/index.js';
import type { StoredCredentials } from '../src/types.js';

const agentKeys = generateKeyPairSync('ed25519');
const CREDS: StoredCredentials = {
  agentId: 'prf_agent_alex01',
  agentName: 'alex',
  credential: 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJwcmZfYWdlbnRfYWxleDAxIn0.sig',
  publicKey: agentKeys.publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
  privateKey: agentKeys.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
  issuedAt: '2026-09-28T00:00:00.000Z',
  expiresAt: '2099-01-01T00:00:00.000Z',
};

function client(): ParafeClient {
  const c = new ParafeClient({ brokerUrl: 'https://broker.test', retries: 2 });
  (c as unknown as { credentials: StoredCredentials }).credentials = CREDS;
  return c;
}

const realFetch = globalThis.fetch;
afterEach(() => { globalThis.fetch = realFetch; });

function stubFetch(responses: Array<{ status: number; body: unknown }>) {
  const proofs: string[] = [];
  globalThis.fetch = jest.fn(async (_url: unknown, init?: RequestInit) => {
    proofs.push(String((init?.headers as Record<string, string>)['Parafe-PoP']));
    const next = responses.shift()!;
    return new Response(JSON.stringify(next.body), { status: next.status, headers: { 'Content-Type': 'application/json' } });
  }) as unknown as typeof fetch;
  return proofs;
}

describe('retries sign a new proof (P-49)', () => {
  it('after a 502, the retry carries a different, valid proof for the same request', async () => {
    const proofs = stubFetch([
      { status: 502, body: { error: 'bad_gateway' } },
      { status: 200, body: { session_id: 'sess_1', chain_head: null, entries: [] } },
    ]);
    await client().getActionReceipts('sess_1');
    expect(proofs).toHaveLength(2);
    expect(proofs[0]).not.toEqual(proofs[1]);
    const [first, second] = proofs.map((p) => jose.decodeJwt(p));
    expect(second.jti).not.toEqual(first.jti);
    expect(second).toMatchObject({ htm: 'GET', htu: 'https://broker.test/sessions/sess_1/action-receipts', session_id: 'sess_1' });
  });

  it('a state-changing request is not retried after a 504 or a dropped connection (it may have run)', async () => {
    stubFetch([{ status: 504, body: {} }, { status: 201, body: {} }]);
    await expect(client().createClaimLink()).rejects.toThrow();
    expect(globalThis.fetch).toHaveBeenCalledTimes(1);

    let calls = 0;
    globalThis.fetch = jest.fn(async () => { calls++; throw new TypeError('fetch failed', { cause: { code: 'ECONNRESET' } }); }) as unknown as typeof fetch;
    await expect(client().createClaimLink()).rejects.toThrow('fetch failed');
    expect(calls).toBe(1);

    // A connection that never opened is safe to retry.
    calls = 0;
    globalThis.fetch = jest.fn(async () => {
      calls++;
      if (calls === 1) throw new TypeError('fetch failed', { cause: { code: 'ECONNREFUSED' } });
      return new Response(JSON.stringify({ claim_url: 'u', code: 'AAAA-BBBB-CC', expires_at: 'e' }), { status: 201 });
    }) as unknown as typeof fetch;
    await client().createClaimLink();
    expect(calls).toBe(2);
  });

  it('a claim link retry is re-signed too', async () => {
    const proofs = stubFetch([
      { status: 503, body: {} },
      { status: 201, body: { claim_url: 'https://platform.parafe.ai/claim?code=AAAA-BBBB-CC', code: 'AAAA-BBBB-CC', expires_at: '2099-01-01T00:00:00Z' } },
    ]);
    await client().createClaimLink();
    expect(new Set(proofs).size).toBe(2);
  });
});
