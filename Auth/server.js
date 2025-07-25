// server.js
import express      from 'express'
import cors         from 'cors'
import cookieParser from 'cookie-parser'

import config         from './config/config.js'
import authRoutes     from './routes/auth.js'
import protectedRoutes from './routes/protected.js'
import { sql }        from './db.js'
import csurf from 'csurf'

const app = express()
const PORT = config.port || 3000



// Middleware
app.use(express.json())
app.use(cookieParser())
app.use(csurf({ cookie: { httpOnly: true, sameSite: 'strict' } }))
app.use(
  cors({
    origin: process.env.FRONTEND_URL || config.frontendUrl,
    credentials: true,
  })
)

// Routes
app.use('/auth', authRoutes)
app.use('/protected', protectedRoutes)



const startApp = async () => {
  try {
    // A simple test query
    await sql`SELECT 1`
    console.log('✅ Database connection OK')

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
