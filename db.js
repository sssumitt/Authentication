// db.js
import { neon } from '@neondatabase/serverless'
import config     from './config/config.js'

// Grab the URL from your config (which reads process.env.DATABASE_URL)
const connectionString = config.db.url
if (!connectionString) {
  throw new Error('Missing DATABASE_URL - set it in your env or Vercel dashboard')
}

// Initialize the Neon client
export const sql = neon(connectionString)
