// scripts/generateKeys.js
import { writeFileSync, mkdirSync, existsSync } from 'fs';
import { generateKeyPairSync }               from 'crypto';
import path                                 from 'path';

// Ensure a “keys” folder exists
const keyDir = path.resolve(process.cwd(), '..', 'keys');
if (!existsSync(keyDir)) mkdirSync(keyDir);


// Generate a 2048-bit RSA key pair
const { publicKey, privateKey } = generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: {
    type:   'pkcs1',    // `"pkcs1"` for RSA keys
    format: 'pem',
  },
  privateKeyEncoding: {
    type:   'pkcs1',    // `"pkcs1"` for RSA keys
    format: 'pem',
  }
});

// Write them to disk
writeFileSync(path.join(keyDir, 'private.key'), privateKey);
writeFileSync(path.join(keyDir, 'public.key'),  publicKey);

console.log('keys generated ✅');
