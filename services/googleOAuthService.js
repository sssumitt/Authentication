import { OAuth2Client } from 'google-auth-library';
import config from '../config/config.js';

// Initialize OAuth2 client with your Google credentials
const client = new OAuth2Client(
  config.googleClientId,
  config.googleClientSecret,
  config.googleRedirectUri 
);

/**
 * Generate the Google OAuth2 consent page URL
 * @returns {string}
 */
export function getGoogleAuthURL() {
  return client.generateAuthUrl({
    access_type: 'offline',       // to get a refresh_token from Google
    scope: [
      'openid',
      'email',
      'profile'
    ],
    prompt: 'consent'
  });
}

/**
 * Exchange authorization code for tokens and verify ID token
 * @param {string} code - Authorization code from Google
 * @returns {Promise<object>} - Decoded ID token payload (contains email, sub, name, picture, etc.)
 */

export async function getGoogleUser(code) {
  try {
    const { tokens } = await client.getToken(code);
    client.setCredentials(tokens);

    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token,
      audience: config.googleClientId,
    });
    return ticket.getPayload();
  } catch (err) {
    console.error('Failed to exchange code for token:', err.response?.data || err.message);
    throw err;
  }
}
