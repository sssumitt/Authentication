// db.js
import { createClient } from '@neondatabase/serverless'
import config           from './config/config.js'

// Pick up the Neon URL from config
const connectionString = config.db.url
if (!connectionString) {
  throw new Error('Missing DATABASE_URL – set it in your env or Vercel dashboard')
}

export const sql = createClient({ connectionString })
