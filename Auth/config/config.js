// config/config.js
import dotenv from 'dotenv';
import fs      from 'fs';
import path    from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

// derive __dirname in an ES module
const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

// keys live alongside config/ in ../keys
const KEY_DIR = path.resolve(__dirname, '../keys');

function loadKey(name) {
  const fullPath = path.join(KEY_DIR, name);
  if (!fs.existsSync(fullPath)) {
    throw new Error(`Missing key file: ${fullPath}`);
  }
  return fs.readFileSync(fullPath, 'utf8');
}

export default {
  port:       process.env.PORT     || 3000,
  jwtSecret:  process.env.JWT_SECRET,
  privateKey: loadKey('private.key'),
  publicKey:  loadKey('public.key'),
  db: {
    url: process.env.DATABASE_URL,
  },
  googleClientId:     process.env.GOOGLE_CLIENT_ID,
  googleClientSecret: process.env.GOOGLE_CLIENT_SECRET,
  googleRedirectUri:  process.env.GOOGLE_REDIRECT_URI
};
