// db.js
import mysql from 'mysql2/promise';
import config from './config/config.js';

export const pool = mysql.createPool({
  host:            config.db.host,
  user:            config.db.user,
  password:        config.db.password,
  database:        config.db.database,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit:      0,
});
