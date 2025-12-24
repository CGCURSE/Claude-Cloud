#!/usr/bin/env node
/**
 * Initialize Claude Code UI with a default user
 * Waits for the UI to create the database, then adds a default user
 *
 * Production-ready features:
 * - Robust database waiting with exponential backoff
 * - Proper error handling and logging
 * - Signal file to indicate completion status
 */

const Database = require('better-sqlite3');
const bcrypt = require('bcrypt');
const path = require('path');
const fs = require('fs');

// Configuration
const DB_PATH = process.env.DATABASE_PATH || '/root/.claude-code-ui/auth.db';
const DEFAULT_USER = process.env.CLAUDE_UI_USER || 'admin';
const DEFAULT_PASS = process.env.CLAUDE_UI_PASSWORD || 'admin';
const SALT_ROUNDS = 12;
const MAX_RETRIES = 60; // Extended to 2 minutes
const INITIAL_RETRY_DELAY = 1000; // 1 second
const MAX_RETRY_DELAY = 5000; // Max 5 seconds between retries
const STATUS_FILE = '/tmp/init-user-status';

// Structured logging
function log(level, message, meta = {}) {
    const entry = {
        timestamp: new Date().toISOString(),
        level,
        component: 'init-user',
        message,
        ...meta
    };
    console.log(JSON.stringify(entry));
}

async function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function writeStatus(status, error = null) {
    try {
        const data = JSON.stringify({ status, error, timestamp: new Date().toISOString() });
        fs.writeFileSync(STATUS_FILE, data);
    } catch (e) {
        // Ignore status file write errors
    }
}

async function waitForDatabase() {
    let retryDelay = INITIAL_RETRY_DELAY;

    for (let i = 0; i < MAX_RETRIES; i++) {
        if (fs.existsSync(DB_PATH)) {
            try {
                const db = new Database(DB_PATH, { readonly: true });

                // Check if users table exists and has the right structure
                const tableInfo = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='users'").get();

                if (tableInfo) {
                    // Also verify the table has the required columns
                    const columns = db.prepare("PRAGMA table_info(users)").all();
                    const columnNames = columns.map(c => c.name);

                    if (columnNames.includes('username') && columnNames.includes('password_hash')) {
                        db.close();
                        log('info', 'Database ready', { path: DB_PATH, columns: columnNames.length });
                        return true;
                    }
                }
                db.close();
            } catch (e) {
                // Database might be locked or not ready - this is expected
                if (e.code !== 'SQLITE_BUSY' && e.code !== 'SQLITE_LOCKED') {
                    log('debug', 'Database check failed', { error: e.message, attempt: i + 1 });
                }
            }
        }

        log('info', `Waiting for database... (${i + 1}/${MAX_RETRIES})`);
        await sleep(retryDelay);

        // Exponential backoff with max limit
        retryDelay = Math.min(retryDelay * 1.5, MAX_RETRY_DELAY);
    }

    return false;
}

async function createDefaultUser() {
    let db = null;

    try {
        db = new Database(DB_PATH);

        // Use a transaction for safety
        const transaction = db.transaction(() => {
            // Check if users exist
            const userCount = db.prepare('SELECT COUNT(*) as count FROM users').get();

            if (userCount.count === 0) {
                log('info', `Creating default user: ${DEFAULT_USER}`);

                // Validate password strength
                if (DEFAULT_PASS.length < 8) {
                    log('warn', 'Password is shorter than recommended 8 characters');
                }

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
                if (columnNames.includes('created_at')) {
                    insertCols.push('created_at');
                    insertVals.push(new Date().toISOString());
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

                log('info', `Default user '${DEFAULT_USER}' created successfully`, {
                    columnsUsed: insertCols.length
                });
                return true;
            } else {
                log('info', 'Users already exist in database, skipping initialization', {
                    existingUsers: userCount.count
                });
                return true;
            }
        });

        transaction();
        return true;

    } catch (e) {
        log('error', 'Failed to create default user', { error: e.message, code: e.code });
        return false;
    } finally {
        if (db) {
            try {
                db.close();
            } catch (e) {
                // Ignore close errors
            }
        }
    }
}

async function main() {
    log('info', 'Starting user initialization', {
        dbPath: DB_PATH,
        username: DEFAULT_USER
    });

    writeStatus('starting');

    const dbReady = await waitForDatabase();

    if (dbReady) {
        const success = await createDefaultUser();
        if (success) {
            writeStatus('success');
            log('info', 'User initialization completed successfully');
            process.exit(0);
        } else {
            writeStatus('failed', 'Failed to create user');
            log('error', 'User initialization failed');
            process.exit(1);
        }
    } else {
        writeStatus('timeout', 'Database not ready after timeout');
        log('warn', 'Database not ready after timeout, skipping user creation');
        log('info', 'You may need to complete the first-time setup manually');
        process.exit(0); // Exit 0 to not block container startup
    }
}

// Handle signals gracefully
process.on('SIGTERM', () => {
    log('info', 'Received SIGTERM, exiting');
    writeStatus('interrupted');
    process.exit(0);
});

process.on('SIGINT', () => {
    log('info', 'Received SIGINT, exiting');
    writeStatus('interrupted');
    process.exit(0);
});

main().catch(e => {
    log('error', 'Unexpected error', { error: e.message, stack: e.stack });
    writeStatus('error', e.message);
    process.exit(1);
});
