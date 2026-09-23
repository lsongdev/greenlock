# Greenlock

A tiny RFC 8555 ACME client that runs from the same source in modern browsers and Node.js.

- native ESM
- no runtime dependencies
- no bundler or build step
- Web Crypto + fetch only
- RSA and ECDSA account keys
- HTTP-01, DNS-01 and TLS-ALPN-01 key authorization
- browser CSR generation with DNS subjectAltName support

The repository is both a static web app and a reusable JavaScript module.

## Browser

Serve the repository as static files and open `index.html`.

The UI uses Preact + htm directly from ESM CDN imports. The ACME and crypto modules themselves have no external dependencies.

You can also use the client directly from a browser module:

```js
import { ACME } from './acme.js';
import { generateKeyPair } from './crypto.js';

const acme = await ACME.create({
  directoryUrl: 'https://acme-staging-v02.api.letsencrypt.org/directory',
});

await acme.setAccountKey(await generateKeyPair({ name: 'ECDSA' }));

const account = await acme.createAccount({
  contact: ['mailto:you@example.com'],
  termsOfServiceAgreed: true,
});

console.log(account.url);
```

## Node.js

Node.js 18+ provides the same `fetch` and Web Crypto APIs used by the browser version.

```js
import { readFile } from 'node:fs/promises';
import { ACME } from '@lsongdev/greenlock';

const accountKey = await readFile('./account-key.pem', 'utf8');

const acme = await ACME.create({
  directoryUrl: 'https://acme-staging-v02.api.letsencrypt.org/directory',
  accountUrl: 'https://acme-staging-v02.api.letsencrypt.org/acme/acct/...',
  accountKey,
});

const order = await acme.createOrder({
  identifiers: [
    { type: 'dns', value: 'example.com' },
    { type: 'dns', value: 'www.example.com' },
  ],
});

const authorizations = await acme.getAuthorizations(order);
console.log(authorizations);
```

`accountKey` is a PKCS#8 `PRIVATE KEY` PEM. RSA and P-256/P-384/P-521 EC keys are supported.

The package can also be imported directly from the repository without publishing:

```js
import { ACME } from './acme.js';
```

## API

The small core intentionally mirrors ACME resources rather than wrapping them in a framework:

```js
await ACME.create(options)
await acme.setAccountKey(keyPairOrPem)
await acme.createAccount(payload)
await acme.updateAccount(payload)
await acme.deactivateAccount()
await acme.createOrder(payload)
await acme.getOrder(orderOrUrl)
await acme.getAuthorization(authOrUrl)
await acme.getAuthorizations(order)
await acme.deactivateAuthorization(authOrUrl)
await acme.getChallengeKey(challenge)
await acme.completeChallenge(challengeOrUrl)
await acme.finalizeOrder(orderOrFinalizeUrl, csr)
await acme.getCertificate(orderOrCertificateUrl)
await acme.revokeCertificate(certificate, reason)
```

All protocol requests use RFC 8555 POST-as-GET where required. Nonces are reused correctly and a `badNonce` response is retried once.

## Crypto

`./crypto.js` contains the cross-runtime helpers used by both the web app and ACME client:

```js
import {
  createCSR,
  exportPrivateKey,
  generateKeyPair,
  importKeyPair,
} from '@lsongdev/greenlock/crypto';
```

They are deliberately implemented on Web Crypto instead of Node's `node:crypto`, which is what allows the exact same modules to run unchanged in both environments.
