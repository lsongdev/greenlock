import { base64url, decodePEM, importKeyPair, sha256 } from './crypto.js';

function urlOf(value, field = 'url') {
  if (typeof value === 'string') return value;
  if (value?.[field]) return value[field];
  throw new TypeError(`Missing ${field}`);
}

function jwsAlgorithm(key) {
  if (key.algorithm.name === 'RSASSA-PKCS1-v1_5') {
    return { alg: 'RS256', sign: 'RSASSA-PKCS1-v1_5' };
  }
  if (key.algorithm.name === 'ECDSA') {
    const algorithms = {
      'P-256': ['ES256', 'SHA-256'],
      'P-384': ['ES384', 'SHA-384'],
      'P-521': ['ES512', 'SHA-512'],
    };
    const pair = algorithms[key.algorithm.namedCurve];
    if (!pair) throw new TypeError(`Unsupported EC curve: ${key.algorithm.namedCurve}`);
    return { alg: pair[0], sign: { name: 'ECDSA', hash: pair[1] } };
  }
  throw new TypeError(`Unsupported account key algorithm: ${key.algorithm.name}`);
}

function canonicalJwk(jwk) {
  if (jwk.kty === 'RSA') {
    return { e: jwk.e, kty: jwk.kty, n: jwk.n };
  }
  if (jwk.kty === 'EC') {
    return { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
  }
  throw new TypeError(`Unsupported JWK type: ${jwk.kty}`);
}

export class ACME {
  constructor(options = {}) {
    if (typeof options === 'string') options = { directoryUrl: options };
    this.directoryUrl = options.directoryUrl;
    this.accountUrl = options.accountUrl || null;
    this.fetch = options.fetch || globalThis.fetch?.bind(globalThis);
    this.directory = null;
    this.nonce = null;
    this.keyPair = null;
    this.publicJwk = null;
    this.thumbprint = null;
  }

  static async create(options) {
    const client = new this(options);
    await client.init();
    if (options?.accountKey) await client.setAccountKey(options.accountKey);
    else if (options?.keyPair) await client.setAccountKey(options.keyPair);
    return client;
  }

  async init() {
    if (!this.directoryUrl) throw new Error('directoryUrl is required');
    if (!this.fetch) throw new Error('fetch is not available');
    const response = await this.fetch(this.directoryUrl);
    if (!response.ok) throw new Error(`Unable to load ACME directory (${response.status})`);
    this.directory = await response.json();
    return this.directory;
  }

  async setAccountKey(value) {
    const keyPair = typeof value === 'string' ? await importKeyPair(value) : value;
    if (!keyPair?.privateKey || !keyPair?.publicKey) throw new TypeError('A CryptoKeyPair or PKCS#8 private key is required');
    this.keyPair = keyPair;
    this.publicJwk = await globalThis.crypto.subtle.exportKey('jwk', keyPair.publicKey);
    this.thumbprint = base64url(await sha256(JSON.stringify(canonicalJwk(this.publicJwk))));
    return keyPair;
  }

  setKeyPair(value) {
    return this.setAccountKey(value);
  }

  keyAuthorization(token) {
    if (!this.thumbprint) throw new Error('Account key is not initialized');
    return `${token}.${this.thumbprint}`;
  }

  async getChallengeKey(challenge) {
    const value = this.keyAuthorization(challenge.token);
    if (challenge.type === 'http-01') return value;
    if (challenge.type === 'dns-01' || challenge.type === 'tls-alpn-01') {
      return base64url(await sha256(value));
    }
    throw new Error(`Unsupported challenge: ${challenge.type}`);
  }

  async createAccount(payload) {
    const response = await this.#post(this.#resource('newAccount'), payload);
    this.accountUrl = response.headers.get('Location');
    if (!this.accountUrl) throw new Error('ACME server did not return an account URL');
    const account = await response.json();
    account.url = this.accountUrl;
    return account;
  }

  async updateAccount(payload) {
    return (await this.#post(urlOf(this.accountUrl), payload)).json();
  }

  deactivateAccount() {
    return this.updateAccount({ status: 'deactivated' });
  }

  async createOrder(payload) {
    const response = await this.#post(this.#resource('newOrder'), payload);
    const order = await response.json();
    order.url = response.headers.get('Location');
    return order;
  }

  async getOrder(order) {
    const url = urlOf(order);
    const result = await (await this.#post(url, null)).json();
    result.url = url;
    return result;
  }

  async getAuthorization(authorization) {
    const url = urlOf(authorization);
    const result = await (await this.#post(url, null)).json();
    result.url = url;
    return result;
  }

  getAuthorizations(order) {
    return Promise.all((order.authorizations || []).map(url => this.getAuthorization(url)));
  }

  async deactivateAuthorization(authorization) {
    const url = urlOf(authorization);
    const result = await (await this.#post(url, { status: 'deactivated' })).json();
    result.url = url;
    return result;
  }

  async completeChallenge(challenge) {
    const url = urlOf(challenge);
    return (await this.#post(url, {})).json();
  }

  respondToChallenge(challenge) {
    return this.completeChallenge(challenge);
  }

  async finalizeOrder(order, csr) {
    const url = typeof order === 'string' ? order : urlOf(order, 'finalize');
    const der = typeof csr === 'string' ? decodePEM(csr).bytes : (csr?.der || csr);
    return (await this.#post(url, { csr: base64url(der) })).json();
  }

  async getCertificate(order) {
    const url = typeof order === 'string' ? order : urlOf(order, 'certificate');
    return (await this.#post(url, null, {
      Accept: 'application/pem-certificate-chain',
    })).text();
  }

  async revokeCertificate(certificate, reason) {
    const der = typeof certificate === 'string' ? decodePEM(certificate).bytes : certificate;
    const payload = { certificate: base64url(der) };
    if (reason !== undefined) payload.reason = reason;
    return this.#post(this.#resource('revokeCert'), payload);
  }

  #resource(name) {
    if (!this.directory) throw new Error('ACME client is not initialized');
    const url = this.directory[name];
    if (!url) throw new Error(`ACME directory does not contain ${name}`);
    return url;
  }

  async #nonce() {
    if (this.nonce) {
      const value = this.nonce;
      this.nonce = null;
      return value;
    }
    const response = await this.fetch(this.#resource('newNonce'), { method: 'HEAD' });
    if (!response.ok) throw new Error(`Unable to obtain ACME nonce (${response.status})`);
    const nonce = response.headers.get('Replay-Nonce');
    if (!nonce) throw new Error('ACME server did not return a nonce');
    return nonce;
  }

  async #jws(url, payload) {
    if (!this.keyPair || !this.publicJwk) throw new Error('Account key is not initialized');
    const algorithm = jwsAlgorithm(this.keyPair.privateKey);
    const header = {
      alg: algorithm.alg,
      nonce: await this.#nonce(),
      url,
      ...(this.accountUrl ? { kid: this.accountUrl } : { jwk: canonicalJwk(this.publicJwk) }),
    };
    const protectedValue = base64url(JSON.stringify(header));
    const payloadValue = payload === null ? '' : base64url(JSON.stringify(payload));
    const input = new TextEncoder().encode(`${protectedValue}.${payloadValue}`);
    const signature = await globalThis.crypto.subtle.sign(algorithm.sign, this.keyPair.privateKey, input);
    return {
      protected: protectedValue,
      payload: payloadValue,
      signature: base64url(signature),
    };
  }

  async #post(url, payload, headers = {}, retry = true) {
    const response = await this.fetch(url, {
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

export { ACME as AcmeClient };
