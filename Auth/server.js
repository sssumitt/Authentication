// server.js
import express      from 'express';
import cors         from 'cors';
import config       from './config/config.js';
import cookieParser from 'cookie-parser';

import authRoutes      from './routes/auth.js';
import protectedRoutes from './routes/protected.js';
import { pool }        from './db.js';

const app = express();

// middleware
app.use(express.json());
app.use(cookieParser());
app.use(
  cors({
    origin: process.env.FRONTEND_URL || 'https://your-frontend.vercel.app',
    credentials: true,
  })
);

// routes
app.use('/auth', authRoutes);
app.use('/protected', protectedRoutes);

// Prepare DB connection once (runs on cold start)
const ready = (async () => {
  await pool.query('SELECT 1');
  console.log('✅ Database connection OK');
})().catch(err => {
  console.error('❌ Database connection failed:', err.message);
});

// Export a handler Vercel can invoke
export default async function handler(req, res) {
  await ready;          // ensure DB check finished
  return app(req, res); // delegate to Express
}
