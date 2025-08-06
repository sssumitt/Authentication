import dotenv from 'dotenv';

dotenv.config();

export default {
  port: process.env.PORT || 3000,

  privateKey: process.env.JWT_PRIVATE_KEY,
  publicKey: process.env.JWT_PUBLIC_KEY,

  db: {
    url: process.env.DATABASE_URL,
  },

  googleClientId: process.env.GOOGLE_CLIENT_ID,
  googleClientSecret: process.env.GOOGLE_CLIENT_SECRET,
  googleRedirectUri: process.env.GOOGLE_REDIRECT_URI,
};
