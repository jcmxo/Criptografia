import nacl from 'tweetnacl';
import * as naclUtil from 'tweetnacl-util';
import { webcrypto as nodeWebcrypto } from 'crypto';

const cryptoApi: Crypto = (globalThis as any).crypto ?? (nodeWebcrypto as unknown as Crypto);

function toArrayBuffer(input: Uint8Array): ArrayBuffer {
  const ab = new ArrayBuffer(input.byteLength);
  new Uint8Array(ab).set(input);
  return ab;
}

function normalizeU8(input: Uint8Array): Uint8Array {
  // Ensure the returned Uint8Array is backed by a standard ArrayBuffer (not ArrayBufferLike)
  return new Uint8Array(input);
}

export type Sha256Hex = string;

export async function sha256Hex(message: string | Uint8Array): Promise<Sha256Hex> {
  const raw = typeof message === 'string' ? new TextEncoder().encode(message) : message;
  const data = normalizeU8(raw);
  const digest = await cryptoApi.subtle.digest('SHA-256', toArrayBuffer(data));
  const bytes = new Uint8Array(digest);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export interface AesGcmCiphertext {
  iv: string; // base64
  ciphertext: string; // base64
}

export async function aesGcmEncrypt(plaintext: Uint8Array | string, key: Uint8Array): Promise<AesGcmCiphertext> {
  const rawPt = typeof plaintext === 'string' ? new TextEncoder().encode(plaintext) : plaintext;
  const pt = normalizeU8(rawPt);
  const iv = cryptoApi.getRandomValues(new Uint8Array(12));
  const cryptoKey = await cryptoApi.subtle.importKey('raw', toArrayBuffer(normalizeU8(key)), { name: 'AES-GCM' }, false, ['encrypt']);
  const ivBuf = toArrayBuffer(iv);
  const ctBuf = await cryptoApi.subtle.encrypt({ name: 'AES-GCM', iv: ivBuf }, cryptoKey, toArrayBuffer(pt) as unknown as ArrayBuffer);
  return {
    iv: naclUtil.encodeBase64(iv),
    ciphertext: naclUtil.encodeBase64(new Uint8Array(ctBuf)),
  };
}

export async function aesGcmDecrypt(payload: AesGcmCiphertext, key: Uint8Array): Promise<Uint8Array> {
  const iv = normalizeU8(naclUtil.decodeBase64(payload.iv));
  const ct = normalizeU8(naclUtil.decodeBase64(payload.ciphertext));
  const cryptoKey = await cryptoApi.subtle.importKey('raw', toArrayBuffer(normalizeU8(key)), { name: 'AES-GCM' }, false, ['decrypt']);
  const ctBuffer: ArrayBuffer = toArrayBuffer(ct);
  const ivBuf2: ArrayBuffer = toArrayBuffer(iv);
  const ptBuf = await cryptoApi.subtle.decrypt({ name: 'AES-GCM', iv: ivBuf2 }, cryptoKey, ctBuffer);
  return new Uint8Array(ptBuf);
}

export interface Ed25519Keypair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export function ed25519GenerateKeypair(): Ed25519Keypair {
  return nacl.sign.keyPair();
}

export function ed25519Sign(message: Uint8Array | string, secretKey: Uint8Array): Uint8Array {
  const msg = typeof message === 'string' ? new TextEncoder().encode(message) : message;
  return nacl.sign.detached(msg, secretKey);
}

export function ed25519Verify(message: Uint8Array | string, signature: Uint8Array, publicKey: Uint8Array): boolean {
  const msg = typeof message === 'string' ? new TextEncoder().encode(message) : message;
  return nacl.sign.detached.verify(msg, signature, publicKey);
}

export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  return cryptoApi.getRandomValues(out);
}


