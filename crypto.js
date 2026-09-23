const encoder = new TextEncoder();

export function bytes(value) {
  if (typeof value === 'string') return encoder.encode(value);
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  throw new TypeError('Expected string or binary data');
}

export function base64url(value) {
  const data = bytes(value);
  let binary = '';
  for (let i = 0; i < data.length; i += 0x8000) {
    binary += String.fromCharCode(...data.subarray(i, i + 0x8000));
  }
  return btoa(binary).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

export async function sha256(value) {
  return crypto.subtle.digest('SHA-256', bytes(value));
}

export function generateKeyPair() {
  return crypto.subtle.generateKey({
    name: 'RSASSA-PKCS1-v1_5',
    modulusLength: 2048,
    publicExponent: new Uint8Array([1, 0, 1]),
    hash: 'SHA-256',
  }, true, ['sign', 'verify']);
}

function pem(label, value) {
  const binary = bytes(value);
  let raw = '';
  for (let i = 0; i < binary.length; i += 0x8000) {
    raw += String.fromCharCode(...binary.subarray(i, i + 0x8000));
  }
  const body = btoa(raw).match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${label}-----\n${body}\n-----END ${label}-----`;
}

export async function exportPrivateKey(keyPair) {
  return pem('PRIVATE KEY', await crypto.subtle.exportKey('pkcs8', keyPair.privateKey));
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
  const out = [];
  do {
    out.unshift(value & 0xff);
    value >>>= 8;
  } while (value);
  return der(0x02, Uint8Array.from(out));
}

/** Build a minimal PKCS#10 CSR with DNS subjectAltName entries. */
export async function createCSR(keyPair, domains) {
  if (!domains.length) throw new TypeError('At least one domain is required');

  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', keyPair.publicKey));
  const subject = sequence(set(sequence(oid('2.5.4.3'), text(0x0c, domains[0]))));
  const names = sequence(...domains.map(domain => text(0x82, domain)));
  const san = sequence(oid('2.5.29.17'), der(0x04, names));
  const extensions = sequence(san);
  const extensionRequest = sequence(
    oid('1.2.840.113549.1.9.14'),
    set(extensions),
  );
  const requestInfo = sequence(
    integer(0),
    subject,
    spki,
    der(0xa0, extensionRequest),
  );

  const signature = new Uint8Array(await crypto.subtle.sign(
    'RSASSA-PKCS1-v1_5',
    keyPair.privateKey,
    requestInfo,
  ));
  const algorithm = sequence(oid('1.2.840.113549.1.1.11'), nullValue());
  const request = sequence(requestInfo, algorithm, der(0x03, concat(Uint8Array.of(0), signature)));

  return {
    der: request.buffer,
    pem: pem('CERTIFICATE REQUEST', request),
  };
}
