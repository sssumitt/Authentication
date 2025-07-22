// server.js
import express      from 'express';
import config       from './config/config.js';
import cookieParser from 'cookie-parser';
import path         from 'path';

import authRoutes       from './routes/auth.js';
import protectedRoutes  from './routes/protected.js';
import { pool }         from './db.js';  


const app  = express();

const PORT = config.port;
console.log()

// Serve frontend
app.use(express.static(path.resolve(process.cwd(), 'public')));

// Global middleware
app.use(express.json());
app.use(cookieParser());

// API routes
app.use('/auth', authRoutes);
app.use('/protected', protectedRoutes);


// Before listening, verify DB connectivity
const startApp = async () => {
  try {
    // A simple test query
    await pool.query('SELECT 1');
    console.log('✅ Database connection OK');

    // Only start the HTTP server after the DB check passes
    app.listen(PORT, () => {
      console.log(`🚀 Server listening on port ${PORT}`);
    });

  } catch (err) {
    console.error('❌ Database connection failed:', err.message);
    process.exit(1);  // stop the process if we can’t reach the DB
  }
};

startApp();
