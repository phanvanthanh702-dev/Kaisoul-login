const { Pool } = require("pg");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false
});

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      kaisoul_id VARCHAR(30) UNIQUE NOT NULL,
      username VARCHAR(30) UNIQUE NOT NULL,
      display_name VARCHAR(100) NOT NULL,
      email VARCHAR(255) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      avatar TEXT DEFAULT '',
      bio TEXT DEFAULT '',
      status VARCHAR(20) DEFAULT 'active',
      email_verified BOOLEAN DEFAULT FALSE,
      two_factor_enabled BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS sessions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      session_token TEXT UNIQUE NOT NULL,
      device_name VARCHAR(255) DEFAULT '',
      ip_address VARCHAR(100) DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
      last_active TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS login_history (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      ip_address VARCHAR(100) DEFAULT '',
      device_name VARCHAR(255) DEFAULT '',
      success BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS connected_apps (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      app_name VARCHAR(100) NOT NULL,
      app_key VARCHAR(100) NOT NULL,
      connected_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(user_id, app_key)
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title VARCHAR(255) NOT NULL,
      message TEXT DEFAULT '',
      type VARCHAR(50) DEFAULT 'system',
      is_read BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
    );
  `);

  console.log("KAISOUL ID database initialized.");
}

module.exports = {
  pool,
  initDatabase
};
