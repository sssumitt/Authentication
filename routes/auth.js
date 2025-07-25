import { Router } from 'express';
import csurf from 'csurf';

import {
  getCsrfToken,
  registerUser,
  loginUser,
  refreshToken,
  logoutUser
} from '../controllers/auth.js';
import { googleAuth, googleCallback } from '../controllers/auth.js';

const csrfProtection = csurf({ cookie: true });

const router = Router();
// ─── GOOGLE OAUTH ROUTES ────────────────────────────────────────────────────────// Kick off the OAuth flow
router.get('/google', googleAuth);

// Handle Google’s callback
router.get('/google/callback', csrfProtection, googleCallback);


// ─── CSRF TOKEN ENDPOINT ───────────────────────────────────────────────────────
router.get('/csrf-token', csrfProtection, getCsrfToken);

// ─── REGISTER ───────────────────────────────────────────────────────────────────
router.post('/register', csrfProtection, registerUser);

// ─── LOGIN ──────────────────────────────────────────────────────────────────────
router.post('/login', csrfProtection, loginUser);

// ─── REFRESH ────────────────────────────────────────────────────────────────────
router.post('/refresh', csrfProtection, refreshToken);

// ─── LOGOUT ─────────────────────────────────────────────────────────────────────
router.post('/logout', csrfProtection, logoutUser);

export default router;
