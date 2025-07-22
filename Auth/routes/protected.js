import { Router } from 'express';
import authMiddleware from '../middleware/auth.js';


const router = Router();

router.use(authMiddleware);

router.get('/', (req, res) => {
  res.json({ message: `Hello ${req.user.username}, you’re authenticated!` });
});

export default router;
