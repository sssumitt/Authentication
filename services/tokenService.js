import jwt    from 'jsonwebtoken';
import config from '../config/config.js';

export function signAccessToken(payload) {
  return jwt.sign(payload, config.privateKey, {
    algorithm: 'RS256',
    expiresIn: '15m',
  });
}
export function signRefreshToken(payload) {
  return jwt.sign(payload, config.privateKey, {
    algorithm: 'RS256',
    expiresIn: '7d',
  });
}

export function issueTokensJSON(res, payload) {
  const accessToken  = signAccessToken(payload);
  const refreshToken = signRefreshToken(payload);

  // refresh token in httpOnly cookie
  res.cookie('refresh_token', refreshToken, {
    httpOnly : true,
    secure   : process.env.NODE_ENV === 'production',
    sameSite : process.env.NODE_ENV === 'production' ? 'None' : 'Lax',
    path     : '/auth/refresh',
    maxAge   : 7 * 24 * 60 * 60 * 1000,
  });

  /*  ⬅⬅⬅  RETURN **both**  */
  return { accessToken, refreshToken };
}
