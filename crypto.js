const encoder = new TextEncoder();

function subtle() {
  if (!globalThis.crypto?.subtle) throw new Error('Web Crypto is not available');
  return globalThis.crypto.subtle;
}

export function bytes(value) {
  if (typeof value === 'string') return encoder.encode(value);
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  throw new TypeError('Expected string or binary data');
}

function binaryString(value) {
  const data = bytes(value);
  let result = '';
  for (let i = 0; i < data.length; i += 0x8000) {
    result += String.fromCharCode(...data.subarray(i, i + 0x8000));
  }
  return result;
}

export function base64url(value) {
  return btoa(binaryString(value)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

export async function sha256(value) {
  return subtle().digest('SHA-256', bytes(value));
}

export function encodePEM(label, value) {
  const body = btoa(binaryString(value)).match(/.{1,64}/g)?.join('\n') || '';
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----`;
}

export function decodePEM(value) {
  const match = /^-----BEGIN ([A-Z0-9 ]+)-----\s+([A-Za-z0-9+/=\s]+?)\s+-----END \1-----$/u.exec(value.trim());
  if (!match) throw new SyntaxError('Invalid PEM block');
  const raw = atob(match[2].replace(/\s/g, ''));
  return {
    label: match[1],
    bytes: Uint8Array.from(raw, char => char.charCodeAt(0)),
  };
}

export function generateKeyPair({
  name = 'RSASSA-PKCS1-v1_5',
  modulusLength = 2048,
  namedCurve = 'P-256',
} = {}) {
  const algorithm = name === 'ECDSA'
    ? { name, namedCurve }
    : {
        name,
        modulusLength,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: 'SHA-256',
      };
  return subtle().generateKey(algorithm, true, ['sign', 'verify']);
}

export async function exportPrivateKey(keyPair) {
  return encodePEM('PRIVATE KEY', await subtle().exportKey('pkcs8', keyPair.privateKey));
}

function publicJwk(jwk) {
  if (jwk.kty === 'RSA') {
    const { e, kty, n } = jwk;
    return { e, kty, n };
  }
  if (jwk.kty === 'EC') {
    const { crv, kty, x, y } = jwk;
    return { crv, kty, x, y };
  }
  throw new TypeError(`Unsupported key type: ${jwk.kty}`);
}

/** Import an RSA or NIST-curve PKCS#8 private key as a Web Crypto key pair. */
export async function importKeyPair(pem) {
  const { label, bytes: der } = decodePEM(pem);
  if (label !== 'PRIVATE KEY') throw new SyntaxError('Expected a PKCS#8 PRIVATE KEY');

  const candidates = [
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    { name: 'ECDSA', namedCurve: 'P-256' },
    { name: 'ECDSA', namedCurve: 'P-384' },
    { name: 'ECDSA', namedCurve: 'P-521' },
  ];

  for (const algorithm of candidates) {
    try {
      const privateKey = await subtle().importKey('pkcs8', der, algorithm, true, ['sign']);
      const jwk = await subtle().exportKey('jwk', privateKey);
      const publicKey = await subtle().importKey('jwk', publicJwk(jwk), algorithm, true, ['verify']);
      return { privateKey, publicKey };
    } catch {
      // Try the next supported key algorithm.
    }
  }
  throw new TypeError('Unsupported PKCS#8 private key');
}

const concat = (...parts) => {
  const size = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(size);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};

function lengthBytes(length) {
  if (length < 0x80) return Uint8Array.of(length);
  const out = [];
  for (let value = length; value; value >>>= 8) out.unshift(value & 0xff);
  return Uint8Array.of(0x80 | out.length, ...out);
}

const der = (tag, content) => concat(Uint8Array.of(tag), lengthBytes(content.length), content);
const sequence = (...parts) => der(0x30, concat(...parts));
const set = (...parts) => der(0x31, concat(...parts));
const text = (tag, value) => der(tag, encoder.encode(value));
const nullValue = () => der(0x05, new Uint8Array());

function base128(value) {
  const out = [value & 0x7f];
  for (value = Math.floor(value / 128); value; value = Math.floor(value / 128)) {
    out.unshift((value & 0x7f) | 0x80);
  }
  return out;
}

function oid(value) {
  const parts = value.split('.').map(Number);
  return der(0x06, Uint8Array.from([
    ...base128(parts[0] * 40 + parts[1]),
    ...parts.slice(2).flatMap(base128),
  ]));
}

function integer(value) {
  if (Number.isSafeInteger(value)) {
    const out = [];
    do {
      out.unshift(value & 0xff);
      value >>>= 8;
    } while (value);
    return der(0x02, Uint8Array.from(out));
  }

  let data = bytes(value);
  while (data.length > 1 && data[0] === 0) data = data.slice(1);
  if (data[0] & 0x80) data = concat(Uint8Array.of(0), data);
  return der(0x02, data);
}

function csrSignature(key) {
  if (key.algorithm.name === 'RSASSA-PKCS1-v1_5') {
    return {
      sign: 'RSASSA-PKCS1-v1_5',
      identifier: sequence(oid('1.2.840.113549.1.1.11'), nullValue()),
      encode: bytes,
    };
  }
  if (key.algorithm.name === 'ECDSA') {
    const params = {
      'P-256': ['SHA-256', '1.2.840.10045.4.3.2'],
      'P-384': ['SHA-384', '1.2.840.10045.4.3.3'],
      'P-521': ['SHA-512', '1.2.840.10045.4.3.4'],
    }[key.algorithm.namedCurve];
    if (!params) throw new TypeError(`Unsupported EC curve: ${key.algorithm.namedCurve}`);
    const [hash, signatureOid] = params;
    return {
      sign: { name: 'ECDSA', hash },
      identifier: sequence(oid(signatureOid)),
      encode(value) {
        const raw = bytes(value);
        const half = raw.length / 2;
        return sequence(integer(raw.slice(0, half)), integer(raw.slice(half)));
      },
    };
  }
  throw new TypeError(`Unsupported CSR key algorithm: ${key.algorithm.name}`);
}

/** Build a minimal PKCS#10 CSR with DNS subjectAltName entries. */
export async function createCSR(keyPair, domains) {
  if (!domains.length) throw new TypeError('At least one domain is required');

  const spki = new Uint8Array(await subtle().exportKey('spki', keyPair.publicKey));
  const subject = sequence(set(sequence(oid('2.5.4.3'), text(0x0c, domains[0]))));
  const names = sequence(...domains.map(domain => text(0x82, domain)));
  const extensions = sequence(sequence(oid('2.5.29.17'), der(0x04, names)));
  const extensionRequest = sequence(oid('1.2.840.113549.1.9.14'), set(extensions));
  const requestInfo = sequence(integer(0), subject, spki, der(0xa0, extensionRequest));

  const plan = csrSignature(keyPair.privateKey);
  const rawSignature = await subtle().sign(plan.sign, keyPair.privateKey, requestInfo);
  const signature = plan.encode(rawSignature);
  const request = sequence(
    requestInfo,
    plan.identifier,
    der(0x03, concat(Uint8Array.of(0), signature)),
  );

  return {
    der: request.buffer,
    pem: encodePEM('CERTIFICATE REQUEST', request),
  };
}
