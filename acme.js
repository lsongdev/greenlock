import { base64url, sha256 } from './crypto.js';

export class AcmeClient {
  constructor(directoryUrl) {
    this.directoryUrl = directoryUrl;
    this.directory = null;
    this.nonce = null;
    this.accountUrl = null;
    this.keyPair = null;
    this.publicJwk = null;
    this.thumbprint = null;
  }

  async init() {
    const response = await fetch(this.directoryUrl);
    if (!response.ok) throw new Error(`Unable to load ACME directory (${response.status})`);
    this.directory = await response.json();
    return this.directory;
  }

  async setKeyPair(keyPair) {
    this.keyPair = keyPair;
    this.publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
    const canonical = JSON.stringify({
      e: this.publicJwk.e,
      kty: this.publicJwk.kty,
      n: this.publicJwk.n,
    });
    this.thumbprint = base64url(await sha256(canonical));
  }

  keyAuthorization(token) {
    if (!this.thumbprint) throw new Error('Account key is not initialized');
    return `${token}.${this.thumbprint}`;
  }

  async createAccount(email, termsOfServiceAgreed = true) {
    const response = await this.#post(this.directory.newAccount, {
      contact: email ? [`mailto:${email}`] : [],
      termsOfServiceAgreed,
    });
    this.accountUrl = response.headers.get('Location');
    if (!this.accountUrl) throw new Error('ACME server did not return an account URL');
    return response.json();
  }

  async createOrder(domains) {
    const response = await this.#post(this.directory.newOrder, {
      identifiers: domains.map(value => ({ type: 'dns', value })),
    });
    const order = await response.json();
    order.url = response.headers.get('Location');
    return order;
  }

  async getOrder(url) {
    return (await this.#post(url, null)).json();
  }

  async getAuthorization(url) {
    return (await this.#post(url, null)).json();
  }

  async respondToChallenge(url) {
    return (await this.#post(url, {})).json();
  }

  async finalizeOrder(url, csr) {
    return (await this.#post(url, { csr: base64url(csr) })).json();
  }

  async getCertificate(url) {
    return (await this.#post(url, null, {
      Accept: 'application/pem-certificate-chain',
    })).text();
  }

  async #getNonce() {
    if (this.nonce) {
      const nonce = this.nonce;
      this.nonce = null;
      return nonce;
    }
    const response = await fetch(this.directory.newNonce, { method: 'HEAD' });
    if (!response.ok) throw new Error(`Unable to obtain ACME nonce (${response.status})`);
    const nonce = response.headers.get('Replay-Nonce');
    if (!nonce) throw new Error('ACME server did not return a nonce');
    return nonce;
  }

  async #jws(url, payload) {
    if (!this.keyPair || !this.publicJwk) throw new Error('Account key is not initialized');
    const protectedHeader = {
      alg: 'RS256',
      nonce: await this.#getNonce(),
      url,
      ...(this.accountUrl ? { kid: this.accountUrl } : { jwk: this.publicJwk }),
    };
    const protectedValue = base64url(JSON.stringify(protectedHeader));
    const payloadValue = payload === null ? '' : base64url(JSON.stringify(payload));
    const data = new TextEncoder().encode(`${protectedValue}.${payloadValue}`);
    const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', this.keyPair.privateKey, data);
    return {
      protected: protectedValue,
      payload: payloadValue,
      signature: base64url(signature),
    };
  }

  async #post(url, payload, headers = {}, retry = true) {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/jose+json',
        ...headers,
      },
      body: JSON.stringify(await this.#jws(url, payload)),
    });

    this.nonce = response.headers.get('Replay-Nonce') || this.nonce;
    if (response.ok) return response;

    const body = await response.text();
    let problem;
    try { problem = JSON.parse(body); } catch { problem = { detail: body }; }

    if (retry && problem.type?.endsWith(':badNonce')) {
      return this.#post(url, payload, headers, false);
    }
    throw new Error(problem.detail || problem.title || `ACME request failed (${response.status})`);
  }
}
