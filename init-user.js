#!/usr/bin/env node
/**
 * Initialize Claude Code UI with a default user
 * Uses bcrypt (12 rounds) to match the UI's auth system
 */

const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');

const DB_PATH = process.env.DATABASE_PATH || '/root/.claude-code-ui/auth.db';
const DEFAULT_USER = process.env.CLAUDE_UI_USER || 'admin';
const DEFAULT_PASS = process.env.CLAUDE_UI_PASSWORD || 'admin';
const SALT_ROUNDS = 12;

// Ensure directory exists
const dbDir = path.dirname(DB_PATH);
if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
}

// Initialize database
const db = new Database(DB_PATH);
db.pragma('foreign_keys = ON');

// Create tables
db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login DATETIME,
        is_active BOOLEAN DEFAULT 1,
        git_name TEXT,
        git_email TEXT,
        has_completed_onboarding BOOLEAN DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        key_name TEXT NOT NULL,
        key_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_used DATETIME,
        is_active BOOLEAN DEFAULT 1,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS user_credentials (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        credential_type TEXT NOT NULL,
        credential_value TEXT NOT NULL,
        description TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT 1,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
    CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active);
    CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
    CREATE INDEX IF NOT EXISTS idx_credentials_user ON user_credentials(user_id);
`);

// Check if users exist
const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();

if (userCount.count === 0) {
    console.log(`Creating default user: ${DEFAULT_USER}`);

    const passwordHash = bcrypt.hashSync(DEFAULT_PASS, SALT_ROUNDS);

    const stmt = db.prepare(`
        INSERT INTO users (username, password_hash, has_completed_onboarding, git_name, git_email)
        VALUES (?, ?, 1, ?, ?)
    `);

    stmt.run(
        DEFAULT_USER,
        passwordHash,
        process.env.GIT_USER_NAME || '',
        process.env.GIT_USER_EMAIL || ''
    );

    console.log(`Default user '${DEFAULT_USER}' created successfully`);
    console.log(`Database: ${DB_PATH}`);
} else {
    console.log(`Users already exist in database, skipping initialization`);
}

db.close();
