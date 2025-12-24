#!/usr/bin/env node
/**
 * Initialize Claude Code UI with a default user
 * Waits for the UI to create the database, then adds a default user
 */

const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');

const DB_PATH = process.env.DATABASE_PATH || '/root/.claude-code-ui/auth.db';
const DEFAULT_USER = process.env.CLAUDE_UI_USER || 'admin';
const DEFAULT_PASS = process.env.CLAUDE_UI_PASSWORD || 'admin';
const SALT_ROUNDS = 12;
const MAX_RETRIES = 30;
const RETRY_DELAY = 2000; // 2 seconds

async function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

async function waitForDatabase() {
    for (let i = 0; i < MAX_RETRIES; i++) {
        if (fs.existsSync(DB_PATH)) {
            try {
                const db = new Database(DB_PATH, { readonly: true });
                // Check if users table exists and has the right structure
                const tableInfo = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='users'").get();
                db.close();

                if (tableInfo) {
                    console.log(`Database found at ${DB_PATH}`);
                    return true;
                }
            } catch (e) {
                // Database might be locked or not ready
            }
        }
        console.log(`Waiting for database... (${i + 1}/${MAX_RETRIES})`);
        await sleep(RETRY_DELAY);
    }
    return false;
}

async function createDefaultUser() {
    try {
        const db = new Database(DB_PATH);

        // Check if users exist
        const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();

        if (userCount.count === 0) {
            console.log(`Creating default user: ${DEFAULT_USER}`);

            const passwordHash = bcrypt.hashSync(DEFAULT_PASS, SALT_ROUNDS);

            // Get column info to handle schema variations
            const columns = db.prepare("PRAGMA table_info(users)").all();
            const columnNames = columns.map(c => c.name);

            // Build insert statement based on available columns
            const insertCols = ['username', 'password_hash'];
            const insertVals = [DEFAULT_USER, passwordHash];

            if (columnNames.includes('has_completed_onboarding')) {
                insertCols.push('has_completed_onboarding');
                insertVals.push(1);
            }
            if (columnNames.includes('is_active')) {
                insertCols.push('is_active');
                insertVals.push(1);
            }
            if (columnNames.includes('git_name') && process.env.GIT_USER_NAME) {
                insertCols.push('git_name');
                insertVals.push(process.env.GIT_USER_NAME);
            }
            if (columnNames.includes('git_email') && process.env.GIT_USER_EMAIL) {
                insertCols.push('git_email');
                insertVals.push(process.env.GIT_USER_EMAIL);
            }

            const placeholders = insertCols.map(() => '?').join(', ');
            const stmt = db.prepare(`INSERT INTO users (${insertCols.join(', ')}) VALUES (${placeholders})`);
            stmt.run(...insertVals);

            console.log(`Default user '${DEFAULT_USER}' created successfully`);
        } else {
            console.log(`Users already exist in database, skipping initialization`);
        }

        db.close();
        return true;
    } catch (e) {
        console.error('Failed to create default user:', e.message);
        return false;
    }
}

async function main() {
    console.log('Waiting for Claude Code UI to initialize database...');

    const dbReady = await waitForDatabase();

    if (dbReady) {
        await createDefaultUser();
    } else {
        console.log('Database not ready after timeout, skipping user creation');
        console.log('You may need to complete the first-time setup manually');
    }
}

main();
