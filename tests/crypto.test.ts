import { sha256Hex, aesGcmEncrypt, aesGcmDecrypt, ed25519GenerateKeypair, ed25519Sign, ed25519Verify, randomBytes } from '../src';

describe('hashing - sha256Hex', () => {
  it('hashes a known string to expected hex length', async () => {
    const hex = await sha256Hex('hola');
    expect(hex).toHaveLength(64);
  });
});

describe('AES-GCM encryption/decryption', () => {
  it('roundtrips the plaintext', async () => {
    const key = randomBytes(32); // 256-bit key
    const plaintext = 'mensaje secreto';
    const enc = await aesGcmEncrypt(plaintext, key);
    const dec = await aesGcmDecrypt(enc, key);
    expect(new TextDecoder().decode(dec)).toBe(plaintext);
  });
});

describe('Ed25519 sign/verify', () => {
  it('verifies a valid signature and rejects a modified message', () => {
    const { publicKey, secretKey } = ed25519GenerateKeypair();
    const message = 'prueba de firma';
    const sig = ed25519Sign(message, secretKey);
    expect(ed25519Verify(message, sig, publicKey)).toBe(true);
    expect(ed25519Verify(message + 'x', sig, publicKey)).toBe(false);
  });
});


