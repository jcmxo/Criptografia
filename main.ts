import { sha256Hex, randomBytes, aesGcmEncrypt, aesGcmDecrypt, ed25519GenerateKeypair, ed25519Sign, ed25519Verify } from './src';

async function runDemo() {
  console.log('=== Demo Librería Criptográfica ===');

  const mensaje = 'Juan Carlos Martin Murcia!';
  const hash = await sha256Hex(mensaje);
  console.log('SHA-256:', hash);

  const key = randomBytes(32);
  const enc = await aesGcmEncrypt(mensaje, key);
  console.log('AES-GCM cifrado (base64):', enc);
  const dec = await aesGcmDecrypt(enc, key);
  console.log('AES-GCM descifrado:', new TextDecoder().decode(dec));

  const { publicKey, secretKey } = ed25519GenerateKeypair();
  const firma = ed25519Sign(mensaje, secretKey);
  console.log('Firma (hex):', Buffer.from(firma).toString('hex'));
  console.log('Verificación:', ed25519Verify(mensaje, firma, publicKey));
}

runDemo().catch(err => {
  console.error(err);
  process.exit(1);
});


