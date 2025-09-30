# Librería Criptográfica (TypeScript)

Funciones incluidas:
- Hash: SHA-256 (`sha256Hex`)
- Cifrado simétrico: AES-GCM (`aesGcmEncrypt`/`aesGcmDecrypt`)
- Firmas Ed25519 (`ed25519GenerateKeypair`, `ed25519Sign`, `ed25519Verify`)

## Requisitos
- Node.js 18+

## Scripts
- `npm test` - ejecuta tests con Jest
- `npm run build` - compila TypeScript a `dist/`
- `npm start` - ejecuta `main.ts` con ts-node (demo)

## Uso rápido
```ts
import { sha256Hex, randomBytes, aesGcmEncrypt, aesGcmDecrypt, ed25519GenerateKeypair, ed25519Sign, ed25519Verify } from './src';

async function demo() {
  const msg = 'Hola';
  console.log(await sha256Hex(msg));

  const key = randomBytes(32);
  const enc = await aesGcmEncrypt(msg, key);
  const dec = await aesGcmDecrypt(enc, key);
  console.log(new TextDecoder().decode(dec));

  const { publicKey, secretKey } = ed25519GenerateKeypair();
  const sig = ed25519Sign(msg, secretKey);
  console.log(ed25519Verify(msg, sig, publicKey));
}
```
