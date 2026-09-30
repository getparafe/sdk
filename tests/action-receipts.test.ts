/**
 * Unit tests for SDK 0.6.0 (AP2 change request B6): action receipts and the
 * session index. No network: fetch is stubbed.
 */

import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { rm } from 'node:fs/promises';
import { generateKeyPairSync, createPublicKey, createHash, type KeyObject } from 'node:crypto';
import { jest } from '@jest/globals';
import * as jose from 'jose';
import { ParafeClient, ConflictError, decodeReceipt, jcs, jsonHash } from '../src/index.js';
import { encryptCredentials } from '../src/credentials.js';
import type { StoredCredentials } from '../src/types.js';

const sha = (s: string) => createHash('sha256').update(s).digest('base64url');
const DID = 'did:web:broker.test:agents:prf_agent_shop01';
const TOKEN = 'eyJhbGciOiJFUzI1NiJ9.eyJzY29wZSI6Im9yZGVyIn0.sig';
const brokerKey = generateKeyPairSync('ec', { namedCurve: 'P-256' });

function creds(privateKey: KeyObject, withSdJwt: boolean): StoredCredentials {
  return {
    agentId: 'prf_agent_shop01',
    agentName: 'shop',
    credential: 'eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJwcmZfYWdlbnRfc2hvcDAxIn0.sig',
    ...(withSdJwt ? { credentialSdJwt: `${jose.base64url.encode('{"alg":"ES256"}')}.${jose.base64url.encode(JSON.stringify({ sub: DID }))}.sig~` } : {}),
    publicKey: createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).toString('base64'),
    privateKey: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
    issuedAt: '2026-09-30T00:00:00.000Z',
    expiresAt: '2099-01-01T00:00:00.000Z',
  };
}

async function client(c: StoredCredentials): Promise<ParafeClient> {
  const file = join(tmpdir(), `parafe-ar-test-${Date.now()}-${Math.random().toString(36).slice(2)}.enc`);
  const p = new ParafeClient({ brokerUrl: 'https://broker.test', retries: 0 });
  try {
    await encryptCredentials(file, c, 'pass');
    await p.loadCredentials(file, 'pass');
  } finally {
    await rm(file, { force: true });
  }
  return p;
}

let calls: { url: string; method: string; headers: Record<string, string>; body?: Record<string, unknown> }[] = [];
let respond: (url: string) => { status: number; body: unknown } = () => ({ status: 200, body: {} });
const realFetch = globalThis.fetch;
beforeEach(() => {
  calls = [];
  globalThis.fetch = jest.fn(async (url: unknown, init?: RequestInit) => {
    calls.push({ url: String(url), method: init?.method ?? 'GET', headers: (init?.headers ?? {}) as Record<string, string>, body: init?.body ? JSON.parse(String(init.body)) : undefined });
    const r = respond(String(url));
    return new Response(JSON.stringify(r.body), { status: r.status, headers: { 'Content-Type': 'application/json' } });
  }) as typeof fetch;
});
afterAll(() => {
  globalThis.fetch = realFetch;
});

async function ack(seq: number): Promise<Record<string, unknown>> {
  const acknowledgment = await new jose.SignJWT({ ver: 1, session_id: 'sess_1', seq, receipt_hash: 'rh', entry_hash: 'eh' })
    .setProtectedHeader({ alg: 'ES256', kid: 'k1', typ: 'parafe-index-ack+jwt' }).setIssuer('did:web:broker.test').sign(brokerKey.privateKey);
  return { session_id: 'sess_1', seq, receipt_hash: 'rh', entry_hash: 'eh', acknowledgment, claims: jose.decodeJwt(acknowledgment) };
}

describe('signActionReceipt()', () => {
  it('signs an ES256 receipt with the agent key: typ, kid = DID#keys-1, iss = DID, hashes of token, request and details', async () => {
    const key = generateKeyPairSync('ec', { namedCurve: 'P-256' }).privateKey;
    const p = await client(creds(key, true));
    const jws = await p.signActionReceipt({
      sessionId: 'sess_1', consentToken: TOKEN, action: 'create_order', request: 'raw request', details: { b: 2, a: 1 }, businessRef: 'ord_1',
    });
    const { payload, protectedHeader } = await jose.jwtVerify(jws, createPublicKey(key), { typ: 'parafe-action-receipt+jwt', issuer: DID });
    expect(protectedHeader).toMatchObject({ alg: 'ES256', kid: `${DID}#keys-1` });
    expect(payload).toMatchObject({
      ver: 1, session_id: 'sess_1', consent_ref: sha(TOKEN), action: 'create_order', result: 'success', error: null,
      request_ref: sha('raw request'), details_hash: sha('{"a":1,"b":2}'), business_ref: 'ord_1', mandate_ref: null,
    });
    expect(typeof payload.jti).toBe('string');
    expect(calls).toHaveLength(0); // DID from the SD-JWT credential: no fetch
  });

  it('signs EdDSA; without an SD-JWT credential it reads the DID from the DID document once', async () => {
    const key = generateKeyPairSync('ed25519').privateKey;
    respond = () => ({ status: 200, body: { id: DID } });
    const p = await client(creds(key, false));
    const refusal = await p.signActionReceipt({ sessionId: 'sess_1', consentToken: TOKEN, action: 'issue_refund', result: 'error', error: 'excluded' });
    await p.signActionReceipt({ sessionId: 'sess_1', consentToken: TOKEN, action: 'read_menu' });
    const { payload, protectedHeader } = await jose.jwtVerify(refusal, createPublicKey(key), { typ: 'parafe-action-receipt+jwt' });
    expect(protectedHeader.alg).toBe('EdDSA');
    expect(payload).toMatchObject({ iss: DID, result: 'error', error: 'excluded' });
    expect(calls.map((c) => c.url)).toEqual(['https://broker.test/agents/prf_agent_shop01/did.json']);
  });

  it('refuses an error receipt without a code, and a success receipt with one', async () => {
    const p = await client(creds(generateKeyPairSync('ed25519').privateKey, true));
    await expect(p.signActionReceipt({ sessionId: 's', consentToken: TOKEN, action: 'a', result: 'error' })).rejects.toThrow(/needs error/);
    await expect(p.signActionReceipt({ sessionId: 's', consentToken: TOKEN, action: 'a', error: 'failed' })).rejects.toThrow(/no error/);
  });
});

describe('fileActionReceipt() / recordActionReceipt() / getActionReceipts()', () => {
  it("files with the agent's credential and a session-bound proof and returns the acknowledgment", async () => {
    const key = generateKeyPairSync('ed25519').privateKey;
    const p = await client(creds(key, true));
    const body = await ack(1);
    respond = () => ({ status: 201, body });
    const { receipt, ack: a } = await p.recordActionReceipt({ sessionId: 'sess_1', consentToken: TOKEN, action: 'read_menu' });
    expect(a).toMatchObject({ seq: 1, duplicate: false, acknowledgment: body.acknowledgment });
    const call = calls[0]!;
    expect(call.url).toBe('https://broker.test/sessions/sess_1/action-receipts');
    expect(call.body).toEqual({ receipt });
    expect(call.headers.Authorization).toMatch(/^Bearer /);
    const { payload } = await jose.jwtVerify(call.headers['Parafe-PoP']!, createPublicKey(key), { typ: 'parafe-pop+jwt' });
    expect(payload).toMatchObject({ htm: 'POST', htu: call.url, session_id: 'sess_1' });
  });

  it('a duplicate returns the original acknowledgment; other conflicts throw', async () => {
    const p = await client(creds(generateKeyPairSync('ed25519').privateKey, true));
    const body = await ack(3);
    respond = () => ({ status: 409, body: { error: 'duplicate_receipt', message: 'already filed', ...body } });
    expect(await p.fileActionReceipt('sess_1', 'a.b.c')).toMatchObject({ seq: 3, duplicate: true });
    respond = () => ({ status: 409, body: { error: 'session_closed', message: 'closed' } });
    await expect(p.fileActionReceipt('sess_1', 'a.b.c')).rejects.toBeInstanceOf(ConflictError);
  });

  it('files an AP2 receipt with its kind', async () => {
    const p = await client(creds(generateKeyPairSync('ed25519').privateKey, true));
    const body = await ack(4);
    respond = () => ({ status: 201, body });
    await p.fileActionReceipt('sess_1', 'ap2.jws.sig', { kind: 'ap2.checkout_receipt' });
    expect(calls[0]!.body).toEqual({ receipt: 'ap2.jws.sig', kind: 'ap2.checkout_receipt' });
  });

  it('lists the index in camelCase', async () => {
    const p = await client(creds(generateKeyPairSync('ed25519').privateKey, true));
    respond = () => ({ status: 200, body: { session_id: 'sess_1', chain_head: 'e1', entries: [{ seq: 1, kind: 'parafe.action_receipt', receipt: 'r', receipt_hash: 'h', receipt_iss: DID, issuer_verified: true, action: 'read_menu', result: 'success', error: null, business_ref: null, prev: null, entry_hash: 'e1', indexed_at: 't', filed_by: 'prf_agent_shop01', acknowledgment: 'ack' }] } });
    const index = await p.getActionReceipts('sess_1');
    expect(index.chainHead).toBe('e1');
    expect(index.entries[0]).toMatchObject({ receiptHash: 'h', receiptIss: DID, issuerVerified: true, entryHash: 'e1', filedBy: 'prf_agent_shop01' });
    expect(calls[0]!.method).toBe('GET');
  });
});

describe('decodeReceipt() actions', () => {
  it('maps the session receipt actions and chain head', async () => {
    const jws = await new jose.SignJWT({
      ver: 2, receipt_id: 'rcpt_1', session_id: 'sess_1', participants: {}, handshake: {}, consent_tokens: [], session: {},
      actions: [{ seq: 1, receipt_hash: 'h1', kind: 'parafe.action_receipt', iss: DID, issuer_verified: true, action: 'issue_refund', result: 'error', error: 'excluded' }],
      chain_head: 'e1',
    }).setProtectedHeader({ alg: 'ES256', kid: 'k1', typ: 'parafe-session-receipt+jwt' }).sign(brokerKey.privateKey);
    const r = decodeReceipt(jws);
    expect(r.actions).toEqual([{ seq: 1, receiptHash: 'h1', kind: 'parafe.action_receipt', iss: DID, issuerVerified: true, action: 'issue_refund', result: 'error', error: 'excluded' }]);
    expect(r.chainHead).toBe('e1');
  });
});

describe('jcs() / jsonHash()', () => {
  it('sort keys by code unit, no whitespace, nested', () => {
    expect(jcs({ b: [1, { d: true, c: null }], a: 'x', é: 1, Z: 2 })).toBe('{"Z":2,"a":"x","b":[1,{"c":null,"d":true}],"é":1}');
    expect(jsonHash({ a: 1 })).toBe(sha('{"a":1}'));
  });
});
