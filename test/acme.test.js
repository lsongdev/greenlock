import test from 'node:test';
import assert from 'node:assert/strict';

import { ACME } from '../acme.js';
import {
  base64url,
  createCSR,
  exportPrivateKey,
  generateKeyPair,
  importKeyPair,
  sha256,
} from '../crypto.js';

const directoryUrl = 'https://ca.test/directory';
const accountUrl = 'https://ca.test/account/1';

function decode(value) {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - base64.length % 4) % 4);
  return JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(padded), char => char.charCodeAt(0))));
}

function mockFetch(calls) {
  let nonce = 0;
  return async (url, init = {}) => {
    calls.push({ url, init });

    if (url === directoryUrl) {
      return new Response(JSON.stringify({
        newNonce: 'https://ca.test/nonce',
        newAccount: 'https://ca.test/account',
        newOrder: 'https://ca.test/order',
        revokeCert: 'https://ca.test/revoke',
      }), { headers: { 'Content-Type': 'application/json' } });
    }

    if (url === 'https://ca.test/nonce') {
      return new Response(null, {
        status: 200,
        headers: { 'Replay-Nonce': `nonce-${++nonce}` },
      });
    }

    if (url === 'https://ca.test/account') {
      return new Response(JSON.stringify({ status: 'valid' }), {
        status: 201,
        headers: {
          'Content-Type': 'application/json',
          Location: accountUrl,
          'Replay-Nonce': `nonce-${++nonce}`,
        },
      });
    }

    if (url === 'https://ca.test/order') {
      return new Response(JSON.stringify({
        status: 'pending',
        authorizations: [],
        finalize: 'https://ca.test/finalize/1',
      }), {
        status: 201,
        headers: {
          'Content-Type': 'application/json',
          Location: 'https://ca.test/order/1',
          'Replay-Nonce': `nonce-${++nonce}`,
        },
      });
    }

    throw new Error(`Unexpected request: ${url}`);
  };
}

test('one ACME client works with Web Platform APIs only', async () => {
  const calls = [];
  const acme = await ACME.create({ directoryUrl, fetch: mockFetch(calls) });
  await acme.setAccountKey(await generateKeyPair());

  const account = await acme.createAccount({
    contact: ['mailto:test@example.com'],
    termsOfServiceAgreed: true,
  });
  assert.equal(account.url, accountUrl);

  const accountRequest = JSON.parse(calls.find(call => call.url === 'https://ca.test/account').init.body);
  const accountHeader = decode(accountRequest.protected);
  assert.equal(accountHeader.alg, 'RS256');
  assert.equal(accountHeader.kid, undefined);
  assert.equal(accountHeader.jwk.kty, 'RSA');

  const order = await acme.createOrder({
    identifiers: [{ type: 'dns', value: 'example.com' }],
  });
  assert.equal(order.url, 'https://ca.test/order/1');

  const orderRequest = JSON.parse(calls.find(call => call.url === 'https://ca.test/order').init.body);
  const orderHeader = decode(orderRequest.protected);
  assert.equal(orderHeader.kid, accountUrl);
  assert.equal(orderHeader.jwk, undefined);
});

test('PKCS#8 account keys round-trip without node:crypto', async () => {
  const original = await generateKeyPair({ name: 'ECDSA', namedCurve: 'P-256' });
  const pem = await exportPrivateKey(original);
  const imported = await importKeyPair(pem);

  const before = await globalThis.crypto.subtle.exportKey('jwk', original.publicKey);
  const after = await globalThis.crypto.subtle.exportKey('jwk', imported.publicKey);
  assert.deepEqual(
    { kty: after.kty, crv: after.crv, x: after.x, y: after.y },
    { kty: before.kty, crv: before.crv, x: before.x, y: before.y },
  );

  const acme = new ACME({ directoryUrl });
  await acme.setAccountKey(pem);
  assert.equal(acme.publicJwk.kty, 'EC');
});

test('challenge keys match RFC 8555 shapes', async () => {
  const acme = new ACME({ directoryUrl });
  await acme.setAccountKey(await generateKeyPair());

  const http = await acme.getChallengeKey({ type: 'http-01', token: 'token' });
  assert.equal(http, `token.${acme.thumbprint}`);

  const dns = await acme.getChallengeKey({ type: 'dns-01', token: 'token' });
  assert.equal(dns, base64url(await sha256(http)));
});

test('CSR generation supports SANs with RSA and ECDSA keys', async () => {
  for (const options of [{}, { name: 'ECDSA', namedCurve: 'P-256' }]) {
    const csr = await createCSR(await generateKeyPair(options), [
      'example.com',
      'www.example.com',
      '*.example.net',
    ]);
    assert.match(csr.pem, /^-----BEGIN CERTIFICATE REQUEST-----/);
    const derText = new TextDecoder().decode(csr.der);
    assert.ok(derText.includes('example.com'));
    assert.ok(derText.includes('www.example.com'));
    assert.ok(derText.includes('*.example.net'));
  }
});


test('default fetch keeps the browser global receiver', async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = function (url) {
    assert.equal(this, globalThis);
    assert.equal(url, directoryUrl);
    return new Response(JSON.stringify({
      newNonce: 'https://ca.test/nonce',
      newAccount: 'https://ca.test/account',
      newOrder: 'https://ca.test/order',
      revokeCert: 'https://ca.test/revoke',
    }), { headers: { 'Content-Type': 'application/json' } });
  };

  try {
    const acme = new ACME({ directoryUrl });
    await acme.init();
    assert.equal(acme.directory.newOrder, 'https://ca.test/order');
  } finally {
    globalThis.fetch = originalFetch;
  }
});


test('newAccount does not imply terms agreement', async () => {
  const calls = [];
  const acme = await ACME.create({ directoryUrl, fetch: mockFetch(calls) });
  await acme.setAccountKey(await generateKeyPair());

  await acme.createAccount({
    contact: ['mailto:test@example.com'],
    termsOfServiceAgreed: false,
  });

  const request = JSON.parse(calls.find(call => call.url === 'https://ca.test/account').init.body);
  const payload = decode(request.payload);
  assert.equal(payload.termsOfServiceAgreed, false);
});
