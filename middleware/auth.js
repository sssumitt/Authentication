// middleware/auth.js
import jwt    from 'jsonwebtoken';
import config from '../config/config.js';

export default function authMiddleware(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'No token' });
  }
  const token = auth.slice(7);


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
