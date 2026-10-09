/**
 * Unit tests for SDK 0.4.0 (AP2 change request Phase 1). No network: fetch is stubbed.
 *
 * verifyConsentLocally(): broker keys from the JWKS by kid (ES256 only: tokens
 * signed with the retired Ed25519 key are refused since 2026-10-09), `exclusions` and `excluded`,
 * key binding (cnf.jkt) and initiator_proof (B7, B14).
 * Receipts (B3, B4, B5): the receipt is the JWS; the SDK decodes a view,
 * verifies by sending the JWS, and can verify offline against the JWKS.
 */

import { generateKeyPairSync, createPublicKey } from 'node:crypto';
import { jest } from '@jest/globals';
import * as jose from 'jose';
import { ParafeClient, AuthError, createPresentationProof, publicKeyThumbprint, decodeReceipt } from '../src/index.js';

const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const ed = generateKeyPairSync('ed25519');
const ecJwk = { ...(ec.publicKey.export({ format: 'jwk' }) as Record<string, string>), kid: 'es-1', alg: 'ES256', status: 'active' };
const edJwk = { ...(ed.publicKey.export({ format: 'jwk' }) as Record<string, string>), kid: 'ed-1', alg: 'EdDSA', status: 'retired' };
const JWKS = { keys: [ecJwk, edJwk] } as never;
const LEGACY_B64 = ed.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

async function consentToken(claims: Record<string, unknown>, { issuer = 'parafe-trust-broker', legacy = false } = {}): Promise<string> {
  const jwt = new jose.SignJWT({ token_type: 'consent', scope: 'place-order', session_id: 'sess_1', ...claims })
    .setProtectedHeader(legacy ? { alg: 'EdDSA' } : { alg: 'ES256', kid: 'es-1' })
    .setIssuedAt().setExpirationTime('5m').setIssuer(issuer);
  return jwt.sign(legacy ? ed.privateKey : ec.privateKey);
}

describe('verifyConsentLocally()', () => {
  const client = new ParafeClient({ brokerUrl: 'https://broker.test', retries: 0 });

  it('verifies an ES256 token against the JWKS and reports v2 claims', async () => {
    const token = await consentToken({
      ver: 2, sub: 'prf_agent_alex01', aud: 'did:web:broker.test:agents:prf_agent_shop01',
      permissions: ['create_order'], exclusions: ['issue_refund'], excluded: ['issue_refund'],
      cnf: { jkt: 'thumb' }, initiator_proof: 'pop', jti: 'j1',
    });
    const r = await client.verifyConsentLocally(token, JWKS);
    expect(r).toMatchObject({
      valid: true, permissions: ['create_order'], exclusions: ['issue_refund'],
      initiatorAgentId: 'prf_agent_alex01', audience: 'did:web:broker.test:agents:prf_agent_shop01',
      keyThumbprint: 'thumb', initiatorProof: 'pop', tokenId: 'j1',
    });
  });

  it('refuses a token signed with the retired Ed25519 key (S-72), via the JWKS or the legacy key; still reads `excluded`', async () => {
    const token = await consentToken({ permissions: ['create_order'], excluded: ['issue_refund'] }, { legacy: true });
    await expect(client.verifyConsentLocally(token, { keys: [edJwk] } as never)).rejects.toMatchObject({ name: 'AuthError', code: 'invalid_signature' });
    await expect(client.verifyConsentLocally(token, LEGACY_B64)).rejects.toMatchObject({ code: 'validation_error' });
    const es = await consentToken({ permissions: ['create_order'], excluded: ['issue_refund'] });
    expect((await client.verifyConsentLocally(es, JWKS)).exclusions).toEqual(['issue_refund']);
  });

  it('fetches and caches the JWKS when no keys are given', async () => {
    const realFetch = globalThis.fetch;
    let fetches = 0;
    globalThis.fetch = jest.fn(async () => { fetches++; return new Response(JSON.stringify(JWKS), { status: 200, headers: { 'Content-Type': 'application/json' } }); }) as typeof fetch;
    try {
      const c = new ParafeClient({ brokerUrl: 'https://broker.test', retries: 0 });
      const token = await consentToken({ permissions: [] });
      await c.verifyConsentLocally(token);
      await c.verifyConsentLocally(token);
      expect(fetches).toBe(1);
    } finally {
      globalThis.fetch = realFetch;
    }
  });

  it('a broker without a JWKS (before 2026-09-30) has only the retired key: its tokens are refused', async () => {
    const realFetch = globalThis.fetch;
    globalThis.fetch = jest.fn(async (url: unknown) => String(url).endsWith('/jwks.json')
      ? new Response(JSON.stringify({ error: 'not_found' }), { status: 404, headers: { 'Content-Type': 'application/json' } })
      : new Response(JSON.stringify({ public_key: LEGACY_B64, algorithm: 'Ed25519' }), { status: 200, headers: { 'Content-Type': 'application/json' } })) as typeof fetch;
    try {
      const c = new ParafeClient({ brokerUrl: 'https://old-broker.test', retries: 0 });
      const token = await consentToken({ permissions: ['read'], excluded: ['x'] }, { legacy: true });
      // Its tokens are Ed25519, which are refused now (S-72).
      await expect(c.verifyConsentLocally(token)).rejects.toMatchObject({ code: 'invalid_signature' });
    } finally {
      globalThis.fetch = realFetch;
    }
  });

  it('refetches the JWKS once when a token names a key it does not have (a newly added broker key)', async () => {
    const realFetch = globalThis.fetch;
    const newKey = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const newJwk = { ...(newKey.publicKey.export({ format: 'jwk' }) as Record<string, string>), kid: 'es-2', alg: 'ES256', status: 'active' };
    let fetches = 0;
    globalThis.fetch = jest.fn(async () => {
      fetches++;
      const body = fetches === 1 ? JWKS : { keys: [newJwk, ...(JWKS as unknown as { keys: unknown[] }).keys] };
      return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }) as typeof fetch;
    const now = Date.now();
    const clock = jest.spyOn(Date, 'now');
    try {
      const c = new ParafeClient({ brokerUrl: 'https://broker.test', retries: 0 });
      await c.verifyConsentLocally(await consentToken({ permissions: [] }));
      const rotated = await new jose.SignJWT({ token_type: 'consent', scope: 's', session_id: 'sess_1', permissions: [] })
        .setProtectedHeader({ alg: 'ES256', kid: 'es-2' }).setIssuer('parafe-trust-broker').setIssuedAt().setExpirationTime('5m').sign(newKey.privateKey);
      clock.mockReturnValue(now + 2 * 60 * 1000); // past the one-minute refetch limit, inside the 5-minute cache
      expect((await c.verifyConsentLocally(rotated)).scope).toBe('s');
      expect(fetches).toBe(2);
    } finally {
      clock.mockRestore();
      globalThis.fetch = realFetch;
    }
  });

  it('returns expired: true for an expired token instead of throwing', async () => {
    const token = await new jose.SignJWT({ token_type: 'consent', scope: 's', session_id: 'sess_1', permissions: [], exclusions: ['x'] })
      .setProtectedHeader({ alg: 'ES256', kid: 'es-1' })
      .setIssuedAt(Math.floor(Date.now() / 1000) - 600).setExpirationTime(Math.floor(Date.now() / 1000) - 300)
      .setIssuer('parafe-trust-broker').sign(ec.privateKey);
    const r = await client.verifyConsentLocally(token, JWKS);
    expect(r.valid).toBe(false);
    expect(r.expired).toBe(true);
  });

  it('rejects a broker JWT that is not a consent token, a foreign issuer, and an unknown key', async () => {
    await expect(client.verifyConsentLocally(await consentToken({ token_type: undefined }), JWKS)).rejects.toThrow('Not a Parafe consent token');
    await expect(client.verifyConsentLocally(await consentToken({}, { issuer: 'someone-else' }), JWKS)).rejects.toMatchObject({ name: 'AuthError', code: 'invalid_token' });
    const other = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const forged = await new jose.SignJWT({ token_type: 'consent' }).setProtectedHeader({ alg: 'ES256', kid: 'es-1' }).setIssuer('parafe-trust-broker').sign(other.privateKey);
    // P-73: Parafé's own error, not jose's.
    const err = await client.verifyConsentLocally(forged, JWKS).catch((e) => e);
    expect(err).toBeInstanceOf(AuthError);
    expect(err.code).toBe('invalid_signature');
    const tampered = (await consentToken({})).replace(/\.([^.]+)\./, (_m, p) => `.${Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(p, 'base64url').toString()), scope: 'everything' })).toString('base64url')}.`);
    await expect(client.verifyConsentLocally(tampered, JWKS)).rejects.toMatchObject({ code: 'invalid_signature' });
    await expect(client.verifyConsentLocally('not.a.token', JWKS)).rejects.toMatchObject({ name: 'AuthError', code: 'invalid_token' });
  });
});

describe('presentation proofs (B7)', () => {
  it('binds the token hash, the audience and the message id, signed with the agent key', async () => {
    const agent = generateKeyPairSync('ed25519');
    const pkcs8 = agent.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
    const proof = await createPresentationProof(pkcs8, 'token.jws.here', 'did:web:x:agents:shop', 'msg-1');
    const { payload, protectedHeader } = await jose.jwtVerify(proof, createPublicKey(agent.privateKey), { typ: 'parafe-pop+jwt' });
    expect(protectedHeader.alg).toBe('EdDSA');
    expect(payload).toMatchObject({ aud: 'did:web:x:agents:shop', mid: 'msg-1' });
    expect(payload.ath).toBe(Buffer.from(await crypto.subtle.digest('SHA-256', new TextEncoder().encode('token.jws.here'))).toString('base64url'));
  });

  it('signs ES256 for a P-256 agent key; thumbprints match RFC 7638', async () => {
    const agent = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const pkcs8 = agent.privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
    const proof = await createPresentationProof(pkcs8, 't', 'aud');
    expect(jose.decodeProtectedHeader(proof).alg).toBe('ES256');
    const spki = agent.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
    expect(publicKeyThumbprint(spki)).toBe(await jose.calculateJwkThumbprint(agent.publicKey.export({ format: 'jwk' }) as jose.JWK));
  });
});

describe('receipts v2 (B3, B4, B5)', () => {
  const CLAIMS = {
    ver: 2, receipt_id: 'rcpt_1', session_id: 'sess_1', handshake_id: 'hs_1',
    participants: {
      initiator: { agent_id: 'prf_agent_alex01', did: 'did:web:x:agents:a', agent_name: 'alex', identity_assurance: 'registered', verification_tier: 'email_verified' },
      target: { agent_id: 'prf_agent_shop01', did: 'did:web:x:agents:b', agent_name: 'shop', identity_assurance: 'registered', verification_tier: 'unverified' },
    },
    handshake: { mutual_auth_completed: true, completed_at: 't0', context_hash: null },
    consent_tokens: [{ token_ref: 'ref', scope: 'place-order', permissions: ['create_order'], exclusions: ['issue_refund'], authorization: { modality: 'attested', evidence_hash: 'eh', mandate_refs: [] }, initiator_proof: 'pop', initiator_proof_at: 't1', issued_at: 't1', expires_at: 't2' }],
    actions: [], chain_head: null,
    session: { started_at: 't0', closed_at: 't3', closed_by: 'prf_agent_alex01', status: 'completed' },
  };
  let jws = '';
  let verifyBodies: unknown[] = [];
  const realFetch = globalThis.fetch;
  beforeAll(async () => {
    jws = await new jose.SignJWT(CLAIMS).setProtectedHeader({ alg: 'ES256', kid: 'es-1', typ: 'parafe-session-receipt+jwt' })
      .setIssuer('did:web:broker.test').setIssuedAt().setJti('r1').sign(ec.privateKey);
  });
  beforeEach(() => {
    verifyBodies = [];
    globalThis.fetch = jest.fn(async (url: unknown, init?: RequestInit) => {
      const u = String(url);
      let body: unknown;
      if (u.endsWith('/session/close')) body = { format_version: 2, receipt_id: 'rcpt_1', session_id: 'sess_1', receipt: jws, claims: { forged: true } };
      else if (u.endsWith('/receipt') && u.includes('sess_old')) body = { format_version: 1, receipt_id: 'rcpt_0', session_id: 'sess_old', receipt: { receipt_id: 'rcpt_0', session_id: 'sess_old', signature: 'sig' } };
      else { verifyBodies.push(JSON.parse(String(init?.body))); body = { valid: true, format_version: 2, signed_by: 'did:web:broker.test', receipt_id: 'rcpt_1', tamper_detected: false }; }
      return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } });
    }) as typeof fetch;
  });
  afterAll(() => { globalThis.fetch = realFetch; });
  const client = new ParafeClient({ brokerUrl: 'https://broker.test', apiKey: 'prf_key_live_user_test', retries: 0 });

  it('closeSession returns the JWS and a view decoded from it (not from the response claims)', async () => {
    const r = await client.closeSession('sess_1');
    expect(r.receipt).toBe(jws);
    expect(r.claims).not.toHaveProperty('forged');
    expect(r.consentTokens[0]).toMatchObject({ exclusions: ['issue_refund'], initiatorProof: 'pop', authorization: { evidenceHash: 'eh' } });
    expect(r.session.closedBy).toBe('prf_agent_alex01');
    expect(r.issuer).toBe('did:web:broker.test');
  });

  it('verifyReceipt sends only the JWS, so edited view fields change nothing', async () => {
    const r = await client.closeSession('sess_1');
    await client.verifyReceipt({ ...r, receiptId: 'rcpt_forged' });
    expect(verifyBodies).toEqual([{ receipt: jws }]);
    await client.verifyReceipt(jws);
    expect(verifyBodies[1]).toEqual({ receipt: jws });
  });

  it('verifyReceiptLocally checks the JWS against the JWKS and catches tampering', async () => {
    expect((await client.verifyReceiptLocally(jws, JWKS)).valid).toBe(true);
    const [h, p, s] = jws.split('.');
    const claims = JSON.parse(Buffer.from(p, 'base64url').toString());
    claims.consent_tokens[0].exclusions = [];
    const tampered = `${h}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.${s}`;
    const r = await client.verifyReceiptLocally(tampered, JWKS);
    expect(r.valid).toBe(false);
    expect(r.tamperDetected).toBe(true);
  });

  it('getReceipt returns v1 receipts as issued', async () => {
    const r = await client.getReceipt('sess_old');
    expect(r).toEqual({ formatVersion: 1, receiptId: 'rcpt_0', sessionId: 'sess_old', issued: { receipt_id: 'rcpt_0', session_id: 'sess_old', signature: 'sig' } });
  });

  it('decodeReceipt is exported for stored receipts', () => {
    expect(decodeReceipt(jws).receiptId).toBe('rcpt_1');
  });
});

describe('operator and principal (broker SPEC-002)', () => {
  const client = new ParafeClient({ brokerUrl: 'https://broker.test', retries: 0 });
  const userParties = { operator: { type: 'org' as const, id: 'prf_org_p' }, principal: { type: 'external' as const, ref: 'user-8f3a' } };
  const shopParties = { operator: { type: 'org' as const, id: 'prf_org_s' }, principal: { type: 'org' as const, id: 'prf_org_s' } };

  it('verifyConsentLocally() returns the parties the token names', async () => {
    const token = await consentToken({ permissions: ['create_order'], initiator_parties: userParties, target_parties: shopParties });
    const r = await client.verifyConsentLocally(token, JWKS);
    expect(r.initiatorParties).toEqual(userParties);
    expect(r.targetParties).toEqual(shopParties);
  });

  it('decodeReceipt() returns each participant\'s parties', async () => {
    const jws = await new jose.SignJWT({
      ver: 2, receipt_id: 'rcpt_1', session_id: 'sess_1', handshake_id: 'hs_1',
      participants: {
        initiator: { agent_id: 'prf_agent_u', agent_name: 'u', identity_assurance: 'registered', parties: userParties },
        target: { agent_id: 'prf_agent_s', agent_name: 's', identity_assurance: 'registered', parties: shopParties },
      },
      handshake: { mutual_auth_completed: true, completed_at: 'now', context_hash: null }, consent_tokens: [], actions: [], chain_head: null,
      session: { started_at: 'a', closed_at: 'b', closed_by: null, status: 'closed' },
    }).setProtectedHeader({ alg: 'ES256', kid: 'es-1' }).setIssuedAt().setIssuer('did:web:broker.test').sign(ec.privateKey);
    const r = decodeReceipt(jws);
    expect(r.participants.initiator.parties).toEqual(userParties);
    expect(r.participants.target.parties).toEqual(shopParties);
  });
});
