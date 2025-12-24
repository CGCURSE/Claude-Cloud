const http = require('http');
const https = require('https');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ============================================
// Configuration
// ============================================
const PORT = process.env.WEBHOOK_PORT || 8080;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || '';
const CREDENTIALS_PATH = '/root/.claude/credentials.json';
const TOKEN_REFRESH_BUFFER = 5 * 60 * 1000; // Refresh 5 minutes before expiry
const TASK_DB_PATH = process.env.TASK_DB_PATH || '/root/.claude-flow/tasks.db';

// Task configuration
const DEFAULT_TASK_TIMEOUT = parseInt(process.env.TASK_TIMEOUT_MS) || 10 * 60 * 1000; // 10 minutes default
const MAX_PROMPT_LENGTH = parseInt(process.env.MAX_PROMPT_LENGTH) || 50000;
const MAX_TASKS_HISTORY = parseInt(process.env.MAX_TASKS_HISTORY) || 1000;

// Rate limiting configuration
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute window
const RATE_LIMIT_MAX_REQUESTS = parseInt(process.env.RATE_LIMIT_MAX) || 60; // 60 requests per minute per IP
const rateLimitStore = new Map();

// ============================================
// Logging
// ============================================
const LOG_LEVELS = { error: 0, warn: 1, info: 2, debug: 3 };
const LOG_LEVEL = LOG_LEVELS[process.env.LOG_LEVEL] ?? LOG_LEVELS.info;

function log(level, message, meta = {}) {
    if (LOG_LEVELS[level] > LOG_LEVEL) return;

    const entry = {
        timestamp: new Date().toISOString(),
        level,
        message,
        ...meta
    };
    console.log(JSON.stringify(entry));
}

// ============================================
// SQLite Task Persistence
// ============================================
let db = null;

function initDatabase() {
    try {
        const Database = require('better-sqlite3');

        // Ensure directory exists
        const dbDir = path.dirname(TASK_DB_PATH);
        if (!fs.existsSync(dbDir)) {
            fs.mkdirSync(dbDir, { recursive: true, mode: 0o700 });
        }

        db = new Database(TASK_DB_PATH);

        // Create tasks table with indexes
        db.exec(`
            CREATE TABLE IF NOT EXISTS tasks (
                task_id TEXT PRIMARY KEY,
                status TEXT NOT NULL DEFAULT 'pending',
                prompt TEXT,
                type TEXT DEFAULT 'task',
                cwd TEXT,
                callback_url TEXT,
                stdout TEXT,
                stderr TEXT,
                error TEXT,
                exit_code INTEGER,
                started_at TEXT,
                completed_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
            CREATE INDEX IF NOT EXISTS idx_tasks_created ON tasks(created_at);
        `);

        // Cleanup old tasks periodically (keep last MAX_TASKS_HISTORY)
        setInterval(cleanupOldTasks, 60 * 60 * 1000); // Every hour

        log('info', 'Task database initialized', { path: TASK_DB_PATH });
        return true;
    } catch (e) {
        log('warn', 'SQLite not available, using in-memory storage', { error: e.message });
        return false;
    }
}

function cleanupOldTasks() {
    if (!db) return;
    try {
        const result = db.prepare(`
            DELETE FROM tasks WHERE task_id NOT IN (
                SELECT task_id FROM tasks ORDER BY created_at DESC LIMIT ?
            )
        `).run(MAX_TASKS_HISTORY);
        if (result.changes > 0) {
            log('info', 'Cleaned up old tasks', { deleted: result.changes });
        }
    } catch (e) {
        log('error', 'Failed to cleanup tasks', { error: e.message });
    }
}

// In-memory fallback
const taskResultsMemory = new Map();

function saveTask(taskId, data) {
    if (db) {
        try {
            const stmt = db.prepare(`
                INSERT INTO tasks (task_id, status, prompt, type, cwd, callback_url, stdout, stderr, error, exit_code, started_at, completed_at)
                VALUES (@task_id, @status, @prompt, @type, @cwd, @callback_url, @stdout, @stderr, @error, @exit_code, @started_at, @completed_at)
                ON CONFLICT(task_id) DO UPDATE SET
                    status = @status,
                    stdout = @stdout,
                    stderr = @stderr,
                    error = @error,
                    exit_code = @exit_code,
                    completed_at = @completed_at
            `);
            stmt.run({
                task_id: taskId,
                status: data.status || 'pending',
                prompt: data.prompt || null,
                type: data.type || 'task',
                cwd: data.cwd || null,
                callback_url: data.callbackUrl || null,
                stdout: data.stdout || null,
                stderr: data.stderr || null,
                error: data.error || null,
                exit_code: data.exitCode ?? null,
                started_at: data.startedAt || null,
                completed_at: data.completedAt || null
            });
        } catch (e) {
            log('error', 'Failed to save task to database', { taskId, error: e.message });
            taskResultsMemory.set(taskId, data);
        }
    } else {
        taskResultsMemory.set(taskId, data);
    }
}

function getTask(taskId) {
    if (db) {
        try {
            const row = db.prepare('SELECT * FROM tasks WHERE task_id = ?').get(taskId);
            if (row) {
                return {
                    taskId: row.task_id,
                    status: row.status,
                    prompt: row.prompt,
                    type: row.type,
                    cwd: row.cwd,
                    callbackUrl: row.callback_url,
                    stdout: row.stdout,
                    stderr: row.stderr,
                    error: row.error,
                    exitCode: row.exit_code,
                    startedAt: row.started_at,
                    completedAt: row.completed_at
                };
            }
        } catch (e) {
            log('error', 'Failed to get task from database', { taskId, error: e.message });
        }
    }
    return taskResultsMemory.get(taskId);
}

function getRecentTasks(limit = 50) {
    if (db) {
        try {
            const rows = db.prepare('SELECT * FROM tasks ORDER BY created_at DESC LIMIT ?').all(limit);
            return rows.map(row => ({
                taskId: row.task_id,
                status: row.status,
                type: row.type,
                startedAt: row.started_at,
                completedAt: row.completed_at
            }));
        } catch (e) {
            log('error', 'Failed to get recent tasks', { error: e.message });
        }
    }
    return Array.from(taskResultsMemory.values()).slice(-limit);
}

function getTaskStats() {
    if (db) {
        try {
            const stats = db.prepare(`
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN status = 'running' THEN 1 ELSE 0 END) as running,
                    SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as completed,
                    SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
                    SUM(CASE WHEN status = 'timeout' THEN 1 ELSE 0 END) as timeout
                FROM tasks
            `).get();
            return stats;
        } catch (e) {
            log('error', 'Failed to get task stats', { error: e.message });
        }
    }
    const tasks = Array.from(taskResultsMemory.values());
    return {
        total: tasks.length,
        running: tasks.filter(t => t.status === 'running').length,
        completed: tasks.filter(t => t.status === 'completed').length,
        failed: tasks.filter(t => t.status === 'failed').length,
        timeout: tasks.filter(t => t.status === 'timeout').length
    };
}

// ============================================
// Input Validation
// ============================================
function validatePrompt(prompt) {
    if (typeof prompt !== 'string') {
        return { valid: false, error: 'Prompt must be a string' };
    }
    if (prompt.trim().length === 0) {
        return { valid: false, error: 'Prompt cannot be empty' };
    }
    if (prompt.length > MAX_PROMPT_LENGTH) {
        return { valid: false, error: `Prompt exceeds maximum length of ${MAX_PROMPT_LENGTH} characters` };
    }
    return { valid: true };
}

function validateCwd(cwd) {
    if (!cwd) return { valid: true, value: '/workspace' };

    if (typeof cwd !== 'string') {
        return { valid: false, error: 'cwd must be a string' };
    }

    // Prevent path traversal attacks
    const resolved = path.resolve(cwd);
    const allowedPaths = ['/workspace', '/tmp', '/home'];

    if (!allowedPaths.some(allowed => resolved.startsWith(allowed))) {
        return { valid: false, error: 'cwd must be within allowed directories' };
    }

    return { valid: true, value: resolved };
}

function validateCallbackUrl(url) {
    if (!url) return { valid: true, value: null };

    try {
        const parsed = new URL(url);
        if (!['http:', 'https:'].includes(parsed.protocol)) {
            return { valid: false, error: 'Callback URL must use http or https' };
        }
        return { valid: true, value: url };
    } catch (e) {
        return { valid: false, error: 'Invalid callback URL' };
    }
}

// ============================================
// Rate Limiting
// ============================================
function getRateLimitKey(req) {
    // Use X-Forwarded-For if behind a proxy, otherwise use socket address
    const forwarded = req.headers['x-forwarded-for'];
    if (forwarded) {
        return forwarded.split(',')[0].trim();
    }
    return req.socket.remoteAddress || 'unknown';
}

function checkRateLimit(req) {
    const key = getRateLimitKey(req);
    const now = Date.now();

    let record = rateLimitStore.get(key);
    if (!record || now - record.windowStart > RATE_LIMIT_WINDOW) {
        record = { windowStart: now, count: 0 };
    }

    record.count++;
    rateLimitStore.set(key, record);

    const remaining = Math.max(0, RATE_LIMIT_MAX_REQUESTS - record.count);
    const reset = Math.ceil((record.windowStart + RATE_LIMIT_WINDOW - now) / 1000);

    return {
        allowed: record.count <= RATE_LIMIT_MAX_REQUESTS,
        remaining,
        reset,
        limit: RATE_LIMIT_MAX_REQUESTS
    };
}

// Clean up old rate limit entries periodically
setInterval(() => {
    const now = Date.now();
    for (const [key, record] of rateLimitStore.entries()) {
        if (now - record.windowStart > RATE_LIMIT_WINDOW * 2) {
            rateLimitStore.delete(key);
        }
    }
}, RATE_LIMIT_WINDOW);

// ============================================
// OAuth Token Management
// ============================================
function readCredentials() {
    try {
        if (fs.existsSync(CREDENTIALS_PATH)) {
            return JSON.parse(fs.readFileSync(CREDENTIALS_PATH, 'utf8'));
        }
    } catch (e) {
        log('error', 'Failed to read credentials', { error: e.message });
    }
    return null;
}

function writeCredentials(credentials) {
    try {
        fs.writeFileSync(CREDENTIALS_PATH, JSON.stringify(credentials, null, 2), { mode: 0o600 });
        return true;
    } catch (e) {
        log('error', 'Failed to write credentials', { error: e.message });
        return false;
    }
}

function isTokenExpiringSoon() {
    const creds = readCredentials();
    if (!creds?.claudeAiOauth?.expiresAt) return false;

    const expiresAt = creds.claudeAiOauth.expiresAt;
    const now = Date.now();
    return expiresAt > 0 && (expiresAt - now) < TOKEN_REFRESH_BUFFER;
}

async function refreshOAuthToken() {
    const creds = readCredentials();
    if (!creds?.claudeAiOauth?.refreshToken) {
        log('warn', 'No refresh token available');
        return false;
    }

    const refreshToken = creds.claudeAiOauth.refreshToken;

    return new Promise((resolve) => {
        const postData = JSON.stringify({
            grant_type: 'refresh_token',
            refresh_token: refreshToken,
            client_id: process.env.OAUTH_CLIENT_ID || 'claude-code'
        });

        const options = {
            hostname: 'console.anthropic.com',
            port: 443,
            path: '/v1/oauth/token',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(postData)
            }
        };

        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    if (res.statusCode === 200) {
                        const tokens = JSON.parse(data);
                        const newCreds = {
                            claudeAiOauth: {
                                accessToken: tokens.access_token,
                                refreshToken: tokens.refresh_token || refreshToken,
                                expiresAt: Date.now() + (tokens.expires_in * 1000)
                            }
                        };
                        writeCredentials(newCreds);
                        log('info', 'OAuth token refreshed successfully');
                        resolve(true);
                    } else {
                        log('error', 'Token refresh failed', { statusCode: res.statusCode });
                        resolve(false);
                    }
                } catch (e) {
                    log('error', 'Token refresh parse error', { error: e.message });
                    resolve(false);
                }
            });
        });

        req.on('error', (e) => {
            log('error', 'Token refresh request error', { error: e.message });
            resolve(false);
        });

        req.write(postData);
        req.end();
    });
}

async function checkAndRefreshToken() {
    if (isTokenExpiringSoon()) {
        log('info', 'Token expiring soon, attempting refresh...');
        await refreshOAuthToken();
    }
}

// Run token check every minute
setInterval(checkAndRefreshToken, 60 * 1000);

// ============================================
// Webhook Callback System
// ============================================
async function sendCallback(callbackUrl, payload, retries = 3) {
    for (let attempt = 1; attempt <= retries; attempt++) {
        try {
            const url = new URL(callbackUrl);
            const isHttps = url.protocol === 'https:';
            const client = isHttps ? https : http;

            const postData = JSON.stringify(payload);

            const options = {
                hostname: url.hostname,
                port: url.port || (isHttps ? 443 : 80),
                path: url.pathname + url.search,
                method: 'POST',
                timeout: 30000, // 30 second timeout for callbacks
                headers: {
                    'Content-Type': 'application/json',
                    'Content-Length': Buffer.byteLength(postData),
                    'User-Agent': 'Claude-Cloud-Webhook/1.0'
                }
            };

            await new Promise((resolve, reject) => {
                const req = client.request(options, (res) => {
                    let data = '';
                    res.on('data', chunk => data += chunk);
                    res.on('end', () => {
                        if (res.statusCode >= 200 && res.statusCode < 300) {
                            log('info', 'Callback sent successfully', { url: callbackUrl, statusCode: res.statusCode });
                            resolve();
                        } else {
                            reject(new Error(`Callback failed: ${res.statusCode}`));
                        }
                    });
                });

                req.on('timeout', () => {
                    req.destroy();
                    reject(new Error('Callback request timeout'));
                });

                req.on('error', reject);
                req.write(postData);
                req.end();
            });

            return true;
        } catch (e) {
            log('warn', `Callback attempt ${attempt}/${retries} failed`, { url: callbackUrl, error: e.message });
            if (attempt < retries) {
                await new Promise(r => setTimeout(r, Math.pow(2, attempt - 1) * 1000));
            }
        }
    }
    log('error', 'All callback attempts failed', { url: callbackUrl });
    return false;
}

// ============================================
// Task Execution
// ============================================
function generateTaskId() {
    return `task_${Date.now()}_${crypto.randomBytes(4).toString('hex')}`;
}

// Track running processes for cleanup
const runningProcesses = new Map();

function runTask(taskId, prompt, options = {}) {
    return new Promise((resolve, reject) => {
        checkAndRefreshToken();

        const timeout = options.timeout || DEFAULT_TASK_TIMEOUT;
        const args = ['--dangerously-skip-permissions'];

        const cwd = options.cwd || '/workspace';

        log('info', 'Starting task', { taskId, cwd, timeout });

        const claude = spawn('claude', args, {
            cwd,
            env: { ...process.env, ...options.env }
        });

        runningProcesses.set(taskId, claude);

        let stdout = '';
        let stderr = '';
        let timedOut = false;

        // Set up timeout
        const timeoutHandle = setTimeout(() => {
            timedOut = true;
            log('warn', 'Task timeout, killing process', { taskId, timeout });
            claude.kill('SIGTERM');

            // Force kill after 5 seconds if still running
            setTimeout(() => {
                if (!claude.killed) {
                    claude.kill('SIGKILL');
                }
            }, 5000);
        }, timeout);

        claude.stdin.write(prompt);
        claude.stdin.end();

        claude.stdout.on('data', (data) => {
            stdout += data.toString();
        });

        claude.stderr.on('data', (data) => {
            stderr += data.toString();
        });

        claude.on('close', async (code) => {
            clearTimeout(timeoutHandle);
            runningProcesses.delete(taskId);

            const result = {
                taskId,
                status: timedOut ? 'timeout' : (code === 0 ? 'completed' : 'failed'),
                exitCode: code,
                stdout,
                stderr,
                completedAt: new Date().toISOString()
            };

            saveTask(taskId, result);

            log('info', 'Task completed', { taskId, status: result.status, exitCode: code });

            if (options.callbackUrl) {
                result.callbackSent = await sendCallback(options.callbackUrl, result);
            }

            resolve(result);
        });

        claude.on('error', async (err) => {
            clearTimeout(timeoutHandle);
            runningProcesses.delete(taskId);

            const result = {
                taskId,
                status: 'error',
                error: err.message,
                completedAt: new Date().toISOString()
            };

            saveTask(taskId, result);

            log('error', 'Task error', { taskId, error: err.message });

            if (options.callbackUrl) {
                result.callbackSent = await sendCallback(options.callbackUrl, result);
            }

            reject(result);
        });
    });
}

// Graceful shutdown - cleanup running processes
process.on('SIGTERM', () => {
    log('info', 'Received SIGTERM, cleaning up...');
    for (const [taskId, proc] of runningProcesses.entries()) {
        log('info', 'Killing running task', { taskId });
        proc.kill('SIGTERM');
    }
    setTimeout(() => process.exit(0), 5000);
});

// ============================================
// HTTP Server
// ============================================
function parseBody(req) {
    return new Promise((resolve, reject) => {
        let body = '';
        const maxBodySize = 1024 * 1024; // 1MB max body size

        req.on('data', chunk => {
            body += chunk;
            if (body.length > maxBodySize) {
                reject(new Error('Request body too large'));
            }
        });

        req.on('end', () => {
            try {
                resolve(body ? JSON.parse(body) : {});
            } catch (e) {
                reject(new Error('Invalid JSON'));
            }
        });
    });
}

function sendJSON(res, status, data, rateLimit = null) {
    const headers = { 'Content-Type': 'application/json' };

    if (rateLimit) {
        headers['X-RateLimit-Limit'] = rateLimit.limit;
        headers['X-RateLimit-Remaining'] = rateLimit.remaining;
        headers['X-RateLimit-Reset'] = rateLimit.reset;
    }

    res.writeHead(status, headers);
    res.end(JSON.stringify(data));
}

function validateSecret(req) {
    if (!WEBHOOK_SECRET) return true;
    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.replace('Bearer ', '');
    // Use timing-safe comparison to prevent timing attacks
    try {
        return crypto.timingSafeEqual(Buffer.from(token), Buffer.from(WEBHOOK_SECRET));
    } catch {
        return false;
    }
}

function getAuthStatus() {
    const creds = readCredentials();
    if (creds?.claudeAiOauth?.accessToken) {
        const expiresAt = creds.claudeAiOauth.expiresAt || 0;
        const hasRefreshToken = !!creds.claudeAiOauth.refreshToken;
        return {
            method: 'oauth',
            expiresAt: expiresAt > 0 ? new Date(expiresAt).toISOString() : null,
            expiringSoon: isTokenExpiringSoon(),
            canRefresh: hasRefreshToken
        };
    } else if (process.env.ANTHROPIC_API_KEY) {
        return { method: 'api_key' };
    }
    return { method: 'none' };
}

const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://localhost:${PORT}`);
    const requestId = crypto.randomBytes(4).toString('hex');

    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        return res.end();
    }

    // Apply rate limiting to all endpoints except health
    let rateLimit = null;
    if (url.pathname !== '/health') {
        rateLimit = checkRateLimit(req);
        if (!rateLimit.allowed) {
            log('warn', 'Rate limit exceeded', { ip: getRateLimitKey(req), path: url.pathname });
            return sendJSON(res, 429, {
                error: 'Too many requests',
                retryAfter: rateLimit.reset
            }, rateLimit);
        }
    }

    // Health check (includes auth status and task stats)
    if (url.pathname === '/health') {
        return sendJSON(res, 200, {
            status: 'healthy',
            timestamp: new Date().toISOString(),
            version: '2.0.0',
            storage: db ? 'sqlite' : 'memory',
            taskStats: getTaskStats(),
            auth: getAuthStatus()
        });
    }

    // Validate auth for other endpoints
    if (!validateSecret(req)) {
        log('warn', 'Unauthorized request', { path: url.pathname, ip: getRateLimitKey(req) });
        return sendJSON(res, 401, { error: 'Unauthorized' }, rateLimit);
    }

    // Manual token refresh endpoint
    if (url.pathname === '/auth/refresh' && req.method === 'POST') {
        const success = await refreshOAuthToken();
        return sendJSON(res, success ? 200 : 500, {
            success,
            auth: getAuthStatus()
        }, rateLimit);
    }

    // Submit task
    if (url.pathname === '/task' && req.method === 'POST') {
        try {
            const body = await parseBody(req);

            // Validate prompt
            const promptValidation = validatePrompt(body.prompt);
            if (!promptValidation.valid) {
                return sendJSON(res, 400, { error: promptValidation.error }, rateLimit);
            }

            // Validate cwd
            const cwdValidation = validateCwd(body.cwd);
            if (!cwdValidation.valid) {
                return sendJSON(res, 400, { error: cwdValidation.error }, rateLimit);
            }

            // Validate callback URL
            const callbackValidation = validateCallbackUrl(body.callback_url);
            if (!callbackValidation.valid) {
                return sendJSON(res, 400, { error: callbackValidation.error }, rateLimit);
            }

            const taskId = generateTaskId();
            const timeout = Math.min(
                parseInt(body.timeout) || DEFAULT_TASK_TIMEOUT,
                30 * 60 * 1000 // Max 30 minutes
            );

            const options = {
                cwd: cwdValidation.value,
                env: body.env || {},
                callbackUrl: callbackValidation.value,
                timeout
            };

            // Store initial task status
            saveTask(taskId, {
                taskId,
                status: 'running',
                prompt: body.prompt,
                callbackUrl: options.callbackUrl,
                cwd: options.cwd,
                startedAt: new Date().toISOString()
            });

            log('info', 'Task submitted', { taskId, async: !!body.async, requestId });

            // Run async (fire and forget if async: true)
            if (body.async) {
                runTask(taskId, body.prompt, options).catch(e => {
                    log('error', 'Async task failed', { taskId, error: e.message || e.error });
                });
                return sendJSON(res, 202, {
                    taskId,
                    status: 'accepted',
                    callbackUrl: options.callbackUrl
                }, rateLimit);
            }

            // Run sync (wait for completion)
            const result = await runTask(taskId, body.prompt, options);
            return sendJSON(res, 200, result, rateLimit);

        } catch (e) {
            log('error', 'Task submission error', { error: e.message, requestId });
            return sendJSON(res, 500, { error: e.message }, rateLimit);
        }
    }

    // Get task status
    if (url.pathname.startsWith('/task/') && req.method === 'GET') {
        const taskId = url.pathname.replace('/task/', '');

        // Validate task ID format
        if (!/^task_\d+_[a-f0-9]+$/.test(taskId)) {
            return sendJSON(res, 400, { error: 'Invalid task ID format' }, rateLimit);
        }

        const result = getTask(taskId);

        if (!result) {
            return sendJSON(res, 404, { error: 'Task not found' }, rateLimit);
        }

        return sendJSON(res, 200, result, rateLimit);
    }

    // List recent tasks
    if (url.pathname === '/tasks' && req.method === 'GET') {
        const limit = Math.min(parseInt(url.searchParams.get('limit')) || 50, 100);
        const tasks = getRecentTasks(limit);
        return sendJSON(res, 200, { tasks, stats: getTaskStats() }, rateLimit);
    }

    // Swarm command
    if (url.pathname === '/swarm' && req.method === 'POST') {
        try {
            const body = await parseBody(req);

            if (!body.task || typeof body.task !== 'string' || body.task.trim().length === 0) {
                return sendJSON(res, 400, { error: 'Missing or invalid task' }, rateLimit);
            }

            const cwdValidation = validateCwd(body.cwd);
            if (!cwdValidation.valid) {
                return sendJSON(res, 400, { error: cwdValidation.error }, rateLimit);
            }

            const callbackValidation = validateCallbackUrl(body.callback_url);
            if (!callbackValidation.valid) {
                return sendJSON(res, 400, { error: callbackValidation.error }, rateLimit);
            }

            const taskId = generateTaskId();
            const callbackUrl = callbackValidation.value;

            saveTask(taskId, {
                taskId,
                type: 'swarm',
                status: 'running',
                prompt: body.task,
                cwd: cwdValidation.value,
                callbackUrl,
                startedAt: new Date().toISOString()
            });

            log('info', 'Swarm task submitted', { taskId });

            const swarm = spawn('claude-flow', ['swarm', body.task, '--claude'], {
                cwd: cwdValidation.value
            });

            runningProcesses.set(taskId, swarm);

            let output = '';
            swarm.stdout.on('data', d => output += d);
            swarm.stderr.on('data', d => output += d);

            swarm.on('close', async (code) => {
                runningProcesses.delete(taskId);

                const result = {
                    taskId,
                    type: 'swarm',
                    status: code === 0 ? 'completed' : 'failed',
                    stdout: output,
                    exitCode: code,
                    completedAt: new Date().toISOString()
                };

                saveTask(taskId, result);

                if (callbackUrl) {
                    result.callbackSent = await sendCallback(callbackUrl, result);
                }
            });

            if (body.async) {
                return sendJSON(res, 202, {
                    taskId,
                    status: 'accepted',
                    callbackUrl
                }, rateLimit);
            }

            await new Promise(resolve => swarm.on('close', resolve));
            return sendJSON(res, 200, getTask(taskId), rateLimit);

        } catch (e) {
            log('error', 'Swarm submission error', { error: e.message });
            return sendJSON(res, 500, { error: e.message }, rateLimit);
        }
    }

    // 404 for unknown routes
    sendJSON(res, 404, { error: 'Not found' }, rateLimit);
});

// Initialize database and start server
initDatabase();

server.listen(PORT, () => {
    log('info', 'Webhook server started', { port: PORT });
    console.log(`Webhook server listening on port ${PORT}`);
    console.log(`Endpoints:`);
    console.log(`  GET  /health       - Health check (includes auth status & task stats)`);
    console.log(`  POST /auth/refresh - Manually refresh OAuth token`);
    console.log(`  POST /task         - Submit Claude task (supports callback_url, timeout)`);
    console.log(`  GET  /task/:id     - Get task status`);
    console.log(`  GET  /tasks        - List recent tasks`);
    console.log(`  POST /swarm        - Run swarm task (supports callback_url)`);
    console.log('');
    console.log('Configuration:');
    console.log(`  Storage: ${db ? 'SQLite' : 'In-memory'}`);
    console.log(`  Rate limit: ${RATE_LIMIT_MAX_REQUESTS} req/min`);
    console.log(`  Task timeout: ${DEFAULT_TASK_TIMEOUT / 1000}s`);
    console.log(`  Max prompt length: ${MAX_PROMPT_LENGTH} chars`);
    console.log('');
    console.log('Auth status:', JSON.stringify(getAuthStatus()));

    checkAndRefreshToken();
});
