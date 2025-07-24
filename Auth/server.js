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

// Verify DB on cold start
const ready = (async () => {
  await sql`SELECT 1`
  console.log('✅ Database connection OK')
})().catch(err => {
  console.error('❌ Database connection failed:', err.message)
})

// === LOCAL DEV: listen when run directly ===
if (!process.env.VERCEL) {
  // only call listen when not running in Vercel’s serverless environment
  app.listen(PORT, () => {
    console.log(`🚀 Dev server listening on http://localhost:${PORT}`)
  })
}

// === VERCEL: export a handler for Serverless ===
export default async function handler(req, res) {
  await ready
  return app(req, res)
}
