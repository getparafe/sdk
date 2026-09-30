/**
 * Unit tests for SDK 0.7.0 (AP2 change request A1, B8, A3): verifyMandate()
 * (the broker's POST /ap2/mandates/verify), mandateRefs, AP2 receipts. No
 * network: fetch is stubbed. AP2 vectors: tests/fixtures/ap2-sdk-vectors.json.
 */

import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { rm } from 'node:fs/promises';
import { readFileSync } from 'node:fs';
import { generateKeyPairSync, createPublicKey, createPrivateKey, createHash } from 'node:crypto';
import { jest } from '@jest/globals';
import * as jose from 'jose';
import { ParafeClient, ap2MandateReferences, ValidationError } from '../src/index.js';
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

test('B8: consent tokens and receipts carry mandateRefs, camelCased', async () => {
  const p = await loaded();
  const ref = { family: 'payment', closed_jwt: 'c', sd_hash: 's' };
  respond = () => ({ status: 200, body: { status: 'scope_escalated', session_id: 'sess_1', consent_token: { token: 't', scope: 'pay', permissions: ['pay'], exclusions: [], authorization: { modality: 'delegated', evidence: { ap2_mandate: 'x~' }, mandate_refs: [ref] }, session_id: 'sess_1', issued_at: 'a', expires_at: 'b' } } });
  const r = await p.escalateScope({ sessionId: 'sess_1', targetAgentId: 'prf_agent_x', scope: 'pay', permissions: ['pay'], authorization: ParafeClient.authorization.delegated({ mandate: 'x~' }) });
  expect(calls[0]!.body).toMatchObject({ authorization: { modality: 'delegated', evidence: { ap2_mandate: 'x~' } } });
  expect(r.consentToken.mandateRefs).toEqual([{ family: 'payment', closedJwt: 'c', sdHash: 's' }]);
});

// ── A3: AP2 receipts ──

const fx = JSON.parse(readFileSync(new URL('./fixtures/ap2-sdk-vectors.json', import.meta.url), 'utf8'));
const checkoutVector = fx.vectors.find((v: { id: string }) => v.id === 'hnp-checkout');
const DID = 'did:web:broker.test:agents:prf_agent_shop01';

async function merchant(): Promise<ParafeClient> {
  const k = createPrivateKey({ key: fx.keys.merchant, format: 'jwk' });
  const file = join(tmpdir(), `parafe-ap2r-${Date.now()}-${Math.random().toString(36).slice(2)}.enc`);
  const p = new ParafeClient({ brokerUrl: 'https://broker.test', retries: 0 });
  await encryptCredentials(file, {
    agentId: 'prf_agent_shop01', agentName: 'shop', credential: 'cred.jwt.sig',
    credentialSdJwt: `${jose.base64url.encode('{"alg":"ES256"}')}.${jose.base64url.encode(JSON.stringify({ sub: DID }))}.sig~`,
    publicKey: createPublicKey(k).export({ type: 'spki', format: 'der' }).toString('base64'),
    privateKey: k.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
    issuedAt: '2026-09-30T00:00:00.000Z', expiresAt: '2099-01-01T00:00:00.000Z',
  }, 'pass');
  await p.loadCredentials(file, 'pass');
  await rm(file, { force: true });
  return p;
}

test("A3: ap2MandateReferences matches the AP2 SDK's reference on every vector", () => {
  for (const v of fx.vectors) {
    const refs = ap2MandateReferences(v.chain);
    expect(refs.closedJwt).toBe(v.sdk_reference);
    expect(refs.sdHash).toBe(createHash('sha256').update((v.chain as string).split('~~').pop() as string).digest('base64url'));
  }
});

test('A3: signAp2Receipt signs a checkout receipt as the agent (ES256, kid, iss = DID); rejections too', async () => {
  const p = await merchant();
  const ok = await p.signAp2Receipt({ kind: 'checkout', mandate: checkoutVector.chain, orderId: 'ord_1' });
  const { d: _d, ...pubJwk } = fx.keys.merchant;
  const { payload, protectedHeader } = await jose.jwtVerify(ok.receipt, await jose.importJWK(pubJwk, 'ES256'));
  expect(protectedHeader).toMatchObject({ alg: 'ES256', typ: 'JWT', kid: `${DID}#keys-1` });
  expect(payload).toMatchObject({ status: 'Success', iss: DID, reference: checkoutVector.sdk_reference, order_id: 'ord_1' });
  const err = await p.signAp2Receipt({ kind: 'checkout', mandate: checkoutVector.chain, error: 'invalid_mandate', errorDescription: 'no stock', referenceForm: 'sd_hash', iss: 'https://shop.example' });
  expect(err.claims).toMatchObject({ status: 'Error', iss: 'https://shop.example', reference: err.references.sdHash, error: 'invalid_mandate' });
  await expect(p.signAp2Receipt({ kind: 'payment', mandate: checkoutVector.chain, paymentId: 'p' })).rejects.toThrow(ValidationError);
});

test('A3: recordAp2Receipt files it with its kind', async () => {
  respond = () => ({ status: 201, body: { session_id: 'sess_1', seq: 3, receipt_hash: 'h', entry_hash: 'e', acknowledgment: 'x.eyJ9.y', claims: {} } });
  const p = await merchant();
  const r = await p.recordAp2Receipt('sess_1', { kind: 'checkout', mandate: checkoutVector.chain, orderId: 'ord_2' });
  expect(calls[0]!.url).toBe('https://broker.test/sessions/sess_1/action-receipts');
  expect(calls[0]!.body).toEqual({ receipt: r.receipt, kind: 'ap2.checkout_receipt' });
  expect(r.ack.seq).toBe(3);
});
