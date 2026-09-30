/**
 * Unit tests: which Authorization header recordAction() and closeSession() send.
 * The broker requires the caller to prove it is a session participant (S-47),
 * so these must authenticate as the loaded agent. No network: fetch is stubbed.
 */

import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { rm } from 'node:fs/promises';
import { jest } from '@jest/globals';
import { ParafeClient } from '../src/index.js';
import { encryptCredentials } from '../src/credentials.js';
import type { StoredCredentials } from '../src/types.js';

const CREDS: StoredCredentials = {
  agentId: 'prf_agent_alex01',
  agentName: 'alex',
  credential: 'eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJwcmZfYWdlbnRfYWxleDAxIn0.sig',
  publicKey: 'MCowBQYDK2VwAyEAfakePublicKey==',
  privateKey: 'MC4CAQAwBQYDK2VwBCIEIfakePrivateKey==',
  issuedAt: '2026-09-28T00:00:00.000Z',
  expiresAt: '2099-01-01T00:00:00.000Z',
};

const RECEIPT = {
  receipt_id: 'rcpt_1', session_id: 'sess_1', handshake_id: 'hs_1',
  participants: {
    initiator: { agent_id: 'prf_agent_alex01', agent_name: 'alex', identity_assurance: 'registered' },
    target: { agent_id: 'prf_agent_shop01', agent_name: 'shop', identity_assurance: 'registered' },
  },
  handshake: { handshake_id: 'hs_1', mutual_auth_completed: true, completed_at: '2026-09-28T00:00:00.000Z' },
  consent_tokens: [],
  session: { started_at: '2026-09-28T00:00:00.000Z', closed_at: '2026-09-28T00:01:00.000Z', status: 'completed' },
  signed_by: 'parafe-broker', issued_at: '2026-09-28T00:01:00.000Z', signature: 'sig',
};

let calls: { url: string; headers: Record<string, string> }[] = [];
const realFetch = globalThis.fetch;

beforeEach(() => {
  calls = [];
  globalThis.fetch = jest.fn(async (url: unknown, init?: RequestInit) => {
    calls.push({ url: String(url), headers: (init?.headers ?? {}) as Record<string, string> });
    const body = String(url).endsWith('/session/close')
      ? RECEIPT
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

describe('agent-authenticated calls (S-47)', () => {
  it("recordAction sends the loaded agent's credential, even when an API key is set", async () => {
    const client = await clientWithCredentials('prf_key_live_org_abc');
    await client.recordAction({ sessionId: 'sess_1', agentId: CREDS.agentId, action: 'read_menu' });
    expect(calls[0].headers.Authorization).toBe(`Bearer ${CREDS.credential}`);
  });

  it('recordAction for a different agent falls back to the API key', async () => {
    const client = await clientWithCredentials('prf_key_live_org_abc');
    await client.recordAction({ sessionId: 'sess_1', agentId: 'prf_agent_other', action: 'read_menu' });
    expect(calls[0].headers.Authorization).toBe('Bearer prf_key_live_org_abc');
  });

  it("closeSession sends the loaded agent's credential", async () => {
    const client = await clientWithCredentials();
    const receipt = await client.closeSession('sess_1');
    expect(calls[0].headers.Authorization).toBe(`Bearer ${CREDS.credential}`);
    expect(receipt.receiptId).toBe('rcpt_1');
  });

  it('with neither a credential nor an API key, sends no Authorization header (not "Bearer undefined")', async () => {
    const client = new ParafeClient({ brokerUrl: 'https://broker.test', retries: 0 });
    await client.closeSession('sess_1');
    expect(calls[0].headers.Authorization).toBeUndefined();
  });
});
