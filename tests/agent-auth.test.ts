/**
 * Unit tests: how agent-authenticated calls authenticate. The broker requires the
 * caller to prove it is a session participant (S-47), and since B7 to prove it
 * holds the agent's key: a `Parafe-PoP` JWT signed with it, bound to the request.
 * No network: fetch is stubbed.
 */

import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { rm } from 'node:fs/promises';
import { generateKeyPairSync, createPublicKey } from 'node:crypto';
import { jest } from '@jest/globals';
import * as jose from 'jose';
import { ParafeClient } from '../src/index.js';
import { encryptCredentials } from '../src/credentials.js';
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

const brokerKey = generateKeyPairSync('ec', { namedCurve: 'P-256' });
let receiptJws = '';
beforeAll(async () => {
  receiptJws = await new jose.SignJWT({ ver: 2, receipt_id: 'rcpt_1', session_id: 'sess_1', participants: {}, handshake: {}, consent_tokens: [], session: {} })
    .setProtectedHeader({ alg: 'ES256', kid: 'k1', typ: 'parafe-session-receipt+jwt' })
    .setIssuer('did:web:broker.test').setIssuedAt().sign(brokerKey.privateKey);
});

let calls: { url: string; method: string; headers: Record<string, string> }[] = [];
const realFetch = globalThis.fetch;

beforeEach(() => {
  calls = [];
  globalThis.fetch = jest.fn(async (url: unknown, init?: RequestInit) => {
    calls.push({ url: String(url), method: init?.method ?? 'GET', headers: (init?.headers ?? {}) as Record<string, string> });
    const body = String(url).endsWith('/session/close') || String(url).endsWith('/receipt')
      ? { format_version: 2, receipt_id: 'rcpt_1', session_id: 'sess_1', receipt: receiptJws }
      : { recorded: true, within_scope: true, action_id: 'act_1', action: 'read_menu', timestamp: 'now' };
    return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });
  }) as typeof fetch;
});
afterAll(() => {
  globalThis.fetch = realFetch;
});

async function clientWithCredentials(apiKey?: string): Promise<ParafeClient> {
  const file = join(tmpdir(), `parafe-auth-test-${Date.now()}-${Math.random().toString(36).slice(2)}.enc`);
  const client = new ParafeClient({ brokerUrl: 'https://broker.test', apiKey, retries: 0 });
  try {
    await encryptCredentials(file, CREDS, 'pass');
    await client.loadCredentials(file, 'pass');
  } finally {
    await rm(file, { force: true });
  }
  return client;
}

/** Verify the proof with the agent's public key and return its claims. */
async function proofClaims(headers: Record<string, string>) {
  const proof = headers['Parafe-PoP'];
  expect(proof).toBeTruthy();
  const { payload, protectedHeader } = await jose.jwtVerify(proof, createPublicKey(agentKeys.privateKey), { typ: 'parafe-pop+jwt' });
  expect(protectedHeader.alg).toBe('EdDSA');
  expect(typeof payload.jti).toBe('string');
  expect(typeof payload.iat).toBe('number');
  return payload;
}

describe('agent-authenticated calls (S-47, B7)', () => {
  it("recordAction sends the loaded agent's credential and a session-bound proof, even when an API key is set", async () => {
    const client = await clientWithCredentials('prf_key_live_org_abc');
    await client.recordAction({ sessionId: 'sess_1', agentId: CREDS.agentId, action: 'read_menu' });
    expect(calls[0].headers.Authorization).toBe(`Bearer ${CREDS.credential}`);
    expect(await proofClaims(calls[0].headers)).toMatchObject({ htm: 'POST', htu: 'https://broker.test/interaction/record', session_id: 'sess_1' });
  });

  it('recordAction for a different agent falls back to the API key (no proof)', async () => {
    const client = await clientWithCredentials('prf_key_live_org_abc');
    await client.recordAction({ sessionId: 'sess_1', agentId: 'prf_agent_other', action: 'read_menu' });
    expect(calls[0].headers.Authorization).toBe('Bearer prf_key_live_org_abc');
    expect(calls[0].headers['Parafe-PoP']).toBeUndefined();
  });

  it('closeSession sends the credential and a proof, and decodes the v2 receipt', async () => {
    const client = await clientWithCredentials();
    const receipt = await client.closeSession('sess_1');
    expect(calls[0].headers.Authorization).toBe(`Bearer ${CREDS.credential}`);
    expect(await proofClaims(calls[0].headers)).toMatchObject({ htm: 'POST', session_id: 'sess_1' });
    expect(receipt.receiptId).toBe('rcpt_1');
    expect(receipt.receipt).toBe(receiptJws);
  });

  it('getReceipt (B5) sends a GET proof bound to the session', async () => {
    const client = await clientWithCredentials();
    const receipt = await client.getReceipt('sess_1');
    expect(calls[0].url).toBe('https://broker.test/sessions/sess_1/receipt');
    expect(await proofClaims(calls[0].headers)).toMatchObject({ htm: 'GET', htu: 'https://broker.test/sessions/sess_1/receipt', session_id: 'sess_1' });
    expect(receipt.formatVersion).toBe(2);
  });

  it('handshake and escalateScope bind the proof to target and scope (and session)', async () => {
    const client = await clientWithCredentials();
    globalThis.fetch = jest.fn(async (url: unknown, init?: RequestInit) => {
      calls.push({ url: String(url), method: init?.method ?? 'GET', headers: (init?.headers ?? {}) as Record<string, string> });
      return new Response(JSON.stringify({ handshake_id: 'hs_1', challenge_for_target: 'aa', expires_at: 'x', session_id: 'sess_1', consent_token: { token: 't', scope: 's', permissions: [], exclusions: [], session_id: 'sess_1' } }), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }) as typeof fetch;
    await client.handshake({ targetAgentId: 'prf_agent_shop01', scope: 'menu-browse', permissions: ['read_menu'] });
    expect(await proofClaims(calls[0].headers)).toMatchObject({ htm: 'POST', htu: 'https://broker.test/handshake/initiate', target_agent_id: 'prf_agent_shop01', requested_scope: 'menu-browse' });
    await client.escalateScope({ sessionId: 'sess_1', targetAgentId: 'prf_agent_shop01', scope: 'place-order', permissions: ['create_order'] });
    expect(await proofClaims(calls[1].headers)).toMatchObject({ requested_scope: 'place-order', session_id: 'sess_1' });
  });

  it('each request gets a fresh proof (new jti)', async () => {
    const client = await clientWithCredentials();
    await client.recordAction({ sessionId: 'sess_1', agentId: CREDS.agentId, action: 'a' });
    await client.recordAction({ sessionId: 'sess_1', agentId: CREDS.agentId, action: 'b' });
    const [a, b] = [await proofClaims(calls[0].headers), await proofClaims(calls[1].headers)];
    expect(a.jti).not.toBe(b.jti);
  });

  it('with neither a credential nor an API key, sends no Authorization header (not "Bearer undefined")', async () => {
    const client = new ParafeClient({ brokerUrl: 'https://broker.test', retries: 0 });
    await client.closeSession('sess_1');
    expect(calls[0].headers.Authorization).toBeUndefined();
  });
});
