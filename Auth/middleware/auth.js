// middleware/auth.js
import jwt    from 'jsonwebtoken';
import config from '../config/config.js';

export default function authMiddleware(req, res, next) {
  // grab the cookie, not the header
  const token = req.cookies.access_token;
  if (!token) {
    return res.status(401).json({ error: 'Access token missing' });
  }

  try {
    const payload = jwt.verify(token, config.publicKey, {
      algorithms: ['RS256']
    });
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}
