/**
 * Unit tests for SDK 0.7.0 (AP2 change request A1): verifyMandate() calls the
 * broker's POST /ap2/mandates/verify. No network: fetch is stubbed.
 */

import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { rm } from 'node:fs/promises';
import { generateKeyPairSync, createPublicKey } from 'node:crypto';
import { jest } from '@jest/globals';
import * as jose from 'jose';
import { ParafeClient } from '../src/index.js';
import { encryptCredentials } from '../src/credentials.js';

const key = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey;
let calls: { url: string; headers: Record<string, string>; body?: Record<string, unknown> }[] = [];
let respond: () => { status: number; body: unknown } = () => ({ status: 200, body: {} });
const realFetch = globalThis.fetch;
beforeEach(() => {
  calls = [];
  globalThis.fetch = jest.fn(async (url: unknown, init?: RequestInit) => {
    calls.push({ url: String(url), headers: (init?.headers ?? {}) as Record<string, string>, body: init?.body ? JSON.parse(String(init.body)) : undefined });
    const r = respond();
    return new Response(JSON.stringify(r.body), { status: r.status, headers: { 'Content-Type': 'application/json' } });
  }) as typeof fetch;
});
afterAll(() => { globalThis.fetch = realFetch; });

async function loaded(): Promise<ParafeClient> {
  const file = join(tmpdir(), `parafe-ap2-${Date.now()}-${Math.random().toString(36).slice(2)}.enc`);
  const p = new ParafeClient({ brokerUrl: 'https://broker.test', retries: 0 });
  await encryptCredentials(file, {
    agentId: 'prf_agent_shop01', agentName: 'shop', credential: 'cred.jwt.sig',
    publicKey: createPublicKey(key).export({ type: 'spki', format: 'der' }).toString('base64'),
    privateKey: key.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
    issuedAt: '2026-09-30T00:00:00.000Z', expiresAt: '2099-01-01T00:00:00.000Z',
  }, 'pass');
  await p.loadCredentials(file, 'pass');
  await rm(file, { force: true });
  return p;
}

const valid = {
  valid: true, family: 'checkout', mode: 'human_not_present', references: { sd_hash: 's', closed_jwt: 'c' }, mandate_hash: 'c',
  issuer: { kid: 'k', jkt: 'j', source: 'request' }, audience: 'merchant', checkout_hash: 'h', agent_key_thumbprint: 't',
  agent: { agent_id: 'prf_agent_cust', did: 'did:web:x', agent_name: 'cust', identity_assurance: 'registered', verification_tier: 'email_verified', is_counterparty: true },
  redemption: { mandate_id: 'ap2m_1', family: 'checkout', mandate_hash: 'c', transaction_ref: 'h', verifier_agent_id: 'prf_agent_shop01', session_id: 'sess_1', via: 'verify_endpoint', redeemed_at: '2026-09-30T00:00:00Z' },
};

test('sends the mandate with a proof bound to the session; camelCases the result', async () => {
  respond = () => ({ status: 200, body: valid });
  const p = await loaded();
  const r = await p.verifyMandate({ mandate: 'a~~b~', sessionId: 'sess_1', checkoutJwt: 'cj', trustedIssuers: [{ jwk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' } }], context: { totalAmount: 5, totalUses: 1 } });
  expect(calls[0]!.url).toBe('https://broker.test/ap2/mandates/verify');
  expect(calls[0]!.body).toMatchObject({ mandate: 'a~~b~', session_id: 'sess_1', checkout_jwt: 'cj', context: { total_amount: 5, total_uses: 1 } });
  expect(calls[0]!.headers.Authorization).toBe('Bearer cred.jwt.sig');
  const proof = jose.decodeJwt(calls[0]!.headers['Parafe-PoP']!);
  expect(proof).toMatchObject({ htm: 'POST', htu: 'https://broker.test/ap2/mandates/verify', session_id: 'sess_1' });
  expect(r).toMatchObject({ valid: true, family: 'checkout', alreadyRedeemed: false, references: { sdHash: 's', closedJwt: 'c' }, agent: { agentId: 'prf_agent_cust', isCounterparty: true }, redemption: { mandateId: 'ap2m_1', sessionId: 'sess_1' }, checkoutHash: 'h' });
});

test('without a session the proof binds the verifying agent', async () => {
  respond = () => ({ status: 200, body: valid });
  const p = await loaded();
  await p.verifyMandate({ mandate: 'a~' });
  expect(jose.decodeJwt(calls[0]!.headers['Parafe-PoP']!)).toMatchObject({ agent_id: 'prf_agent_shop01' });
});

test('a refused mandate comes back with its AP2 error code, not as an exception', async () => {
  respond = () => ({ status: 200, body: { valid: false, error: 'invalid_mandate', reason: 'constraint_failed', message: 'amount', violations: ['amount'], references: { sd_hash: 's', closed_jwt: 'c' }, agent: null, redemption: null } });
  const r = await (await loaded()).verifyMandate({ mandate: 'a~' });
  expect(r).toMatchObject({ valid: false, error: 'invalid_mandate', reason: 'constraint_failed', violations: ['amount'], references: { closedJwt: 'c' } });
});

test('a second redemption (409) returns alreadyRedeemed with the earlier redemption', async () => {
  respond = () => ({ status: 409, body: { ...valid, valid: false, error: 'invalid_mandate', reason: 'already_redeemed', message: 'again' } });
  const r = await (await loaded()).verifyMandate({ mandate: 'a~' });
  expect(r).toMatchObject({ valid: false, alreadyRedeemed: true, redemption: { mandateId: 'ap2m_1' } });
});

test('with only an API key, agentId is required and sent', async () => {
  respond = () => ({ status: 200, body: valid });
  const p = new ParafeClient({ brokerUrl: 'https://broker.test', apiKey: 'prf_key_live_user_x', retries: 0 });
  await expect(p.verifyMandate({ mandate: 'a~' })).rejects.toThrow(/agentId/);
  await p.verifyMandate({ mandate: 'a~', agentId: 'prf_agent_shop01' });
  expect(calls[0]!.headers.Authorization).toBe('Bearer prf_key_live_user_x');
  expect(calls[0]!.body).toMatchObject({ agent_id: 'prf_agent_shop01' });
});
