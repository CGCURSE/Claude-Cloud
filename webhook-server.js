const http = require('http');
const https = require('https');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

const PORT = process.env.WEBHOOK_PORT || 8080;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || '';
const CREDENTIALS_PATH = '/root/.claude/credentials.json';
const TOKEN_REFRESH_BUFFER = 5 * 60 * 1000; // Refresh 5 minutes before expiry

// Task queue
const taskResults = new Map();
let taskIdCounter = 1;

// ============================================
// OAuth Token Management
// ============================================

function readCredentials() {
    try {
        if (fs.existsSync(CREDENTIALS_PATH)) {
            return JSON.parse(fs.readFileSync(CREDENTIALS_PATH, 'utf8'));
        }
    } catch (e) {
        console.error('Failed to read credentials:', e.message);
    }
    return null;
}

function writeCredentials(credentials) {
    try {
        fs.writeFileSync(CREDENTIALS_PATH, JSON.stringify(credentials, null, 2));
        return true;
    } catch (e) {
        console.error('Failed to write credentials:', e.message);
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
        console.log('No refresh token available');
        return false;
    }

    const refreshToken = creds.claudeAiOauth.refreshToken;

    return new Promise((resolve) => {
        const postData = JSON.stringify({
            grant_type: 'refresh_token',
            refresh_token: refreshToken,
            client_id: 'claude-code'
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
                        console.log('OAuth token refreshed successfully');
                        resolve(true);
                    } else {
                        console.error('Token refresh failed:', res.statusCode, data);
                        resolve(false);
                    }
                } catch (e) {
                    console.error('Token refresh parse error:', e.message);
                    resolve(false);
                }
            });
        });

        req.on('error', (e) => {
            console.error('Token refresh request error:', e.message);
            resolve(false);
        });

        req.write(postData);
        req.end();
    });
}

// Check and refresh token periodically
async function checkAndRefreshToken() {
    if (isTokenExpiringSoon()) {
        console.log('Token expiring soon, attempting refresh...');
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
                            console.log(`Callback sent to ${callbackUrl}: ${res.statusCode}`);
                            resolve();
                        } else {
                            reject(new Error(`Callback failed: ${res.statusCode}`));
                        }
                    });
                });

                req.on('error', reject);
                req.write(postData);
                req.end();
            });

            return true; // Success
        } catch (e) {
            console.error(`Callback attempt ${attempt}/${retries} failed:`, e.message);
            if (attempt < retries) {
                // Exponential backoff: 1s, 2s, 4s
                await new Promise(r => setTimeout(r, Math.pow(2, attempt - 1) * 1000));
            }
        }
    }
    console.error(`All callback attempts to ${callbackUrl} failed`);
    return false;
}

// ============================================
// Task Execution
// ============================================

function generateTaskId() {
    return `task_${Date.now()}_${taskIdCounter++}`;
}

function runTask(taskId, prompt, options = {}) {
    return new Promise((resolve, reject) => {
        // Check token before running task
        checkAndRefreshToken();

        const args = ['--dangerously-skip-permissions'];

        if (options.cwd) {
            process.chdir(options.cwd);
        }

        const claude = spawn('claude', args, {
            cwd: options.cwd || '/workspace',
            env: { ...process.env, ...options.env }
        });

        let stdout = '';
        let stderr = '';

        // Send prompt to Claude
        claude.stdin.write(prompt);
        claude.stdin.end();

        claude.stdout.on('data', (data) => {
            stdout += data.toString();
        });

        claude.stderr.on('data', (data) => {
            stderr += data.toString();
        });

        claude.on('close', async (code) => {
            const result = {
                taskId,
                status: code === 0 ? 'completed' : 'failed',
                exitCode: code,
                stdout,
                stderr,
                completedAt: new Date().toISOString()
            };
            taskResults.set(taskId, result);

            // Send callback if URL was provided
            if (options.callbackUrl) {
                result.callbackSent = await sendCallback(options.callbackUrl, result);
            }

            resolve(result);
        });

        claude.on('error', async (err) => {
            const result = {
                taskId,
                status: 'error',
                error: err.message,
                completedAt: new Date().toISOString()
            };
            taskResults.set(taskId, result);

            // Send callback on error too
            if (options.callbackUrl) {
                result.callbackSent = await sendCallback(options.callbackUrl, result);
            }

            reject(result);
        });
    });
}

// ============================================
// HTTP Server
// ============================================

function parseBody(req) {
    return new Promise((resolve, reject) => {
        let body = '';
        req.on('data', chunk => body += chunk);
        req.on('end', () => {
            try {
                resolve(body ? JSON.parse(body) : {});
            } catch (e) {
                reject(new Error('Invalid JSON'));
            }
        });
    });
}

function sendJSON(res, status, data) {
    res.writeHead(status, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data));
}

function validateSecret(req) {
    if (!WEBHOOK_SECRET) return true;
    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.replace('Bearer ', '');
    return token === WEBHOOK_SECRET;
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

    // CORS headers
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        return res.end();
    }

    // Health check (includes auth status)
    if (url.pathname === '/health') {
        return sendJSON(res, 200, {
            status: 'healthy',
            timestamp: new Date().toISOString(),
            pendingTasks: 0,
            auth: getAuthStatus()
        });
    }

    // Validate auth for other endpoints
    if (!validateSecret(req)) {
        return sendJSON(res, 401, { error: 'Unauthorized' });
    }

    // Manual token refresh endpoint
    if (url.pathname === '/auth/refresh' && req.method === 'POST') {
        const success = await refreshOAuthToken();
        return sendJSON(res, success ? 200 : 500, {
            success,
            auth: getAuthStatus()
        });
    }

    // Submit task
    if (url.pathname === '/task' && req.method === 'POST') {
        try {
            const body = await parseBody(req);

            if (!body.prompt || typeof body.prompt !== 'string' || body.prompt.trim() === '') {
                return sendJSON(res, 400, { error: 'Missing prompt or invalid prompt format' });
            }

            const taskId = generateTaskId();
            const options = {
                cwd: body.cwd || '/workspace',
                env: body.env || {},
                callbackUrl: body.callback_url || null
            };

            // Store initial task status
            taskResults.set(taskId, {
                taskId,
                status: 'running',
                prompt: body.prompt,
                callbackUrl: options.callbackUrl,
                startedAt: new Date().toISOString()
            });

            // Run async (fire and forget if async: true)
            if (body.async) {
                runTask(taskId, body.prompt, options).catch(console.error);
                return sendJSON(res, 202, {
                    taskId,
                    status: 'accepted',
                    callbackUrl: options.callbackUrl
                });
            }

            // Run sync (wait for completion)
            const result = await runTask(taskId, body.prompt, options);
            return sendJSON(res, 200, result);

        } catch (e) {
            return sendJSON(res, 500, { error: e.message });
        }
    }

    // Get task status
    if (url.pathname.startsWith('/task/') && req.method === 'GET') {
        const taskId = url.pathname.replace('/task/', '');
        const result = taskResults.get(taskId);

        if (!result) {
            return sendJSON(res, 404, { error: 'Task not found' });
        }

        return sendJSON(res, 200, result);
    }

    // List recent tasks
    if (url.pathname === '/tasks' && req.method === 'GET') {
        const tasks = Array.from(taskResults.values()).slice(-50);
        return sendJSON(res, 200, { tasks });
    }

    // Swarm command
    if (url.pathname === '/swarm' && req.method === 'POST') {
        try {
            const body = await parseBody(req);

            if (!body.task) {
                return sendJSON(res, 400, { error: 'Missing task' });
            }

            const taskId = generateTaskId();
            const callbackUrl = body.callback_url || null;

            const swarm = spawn('claude-flow', ['swarm', body.task, '--claude'], {
                cwd: body.cwd || '/workspace'
            });

            let output = '';
            swarm.stdout.on('data', d => output += d);
            swarm.stderr.on('data', d => output += d);

            swarm.on('close', async (code) => {
                const result = {
                    taskId,
                    type: 'swarm',
                    status: code === 0 ? 'completed' : 'failed',
                    output,
                    completedAt: new Date().toISOString()
                };
                taskResults.set(taskId, result);

                // Send callback if URL was provided
                if (callbackUrl) {
                    result.callbackSent = await sendCallback(callbackUrl, result);
                }
            });

            if (body.async) {
                return sendJSON(res, 202, {
                    taskId,
                    status: 'accepted',
                    callbackUrl
                });
            }

            await new Promise(resolve => swarm.on('close', resolve));
            return sendJSON(res, 200, taskResults.get(taskId));

        } catch (e) {
            return sendJSON(res, 500, { error: e.message });
        }
    }

    // 404 for unknown routes
    sendJSON(res, 404, { error: 'Not found' });
});

server.listen(PORT, () => {
    console.log(`Webhook server listening on port ${PORT}`);
    console.log(`Endpoints:`);
    console.log(`  GET  /health       - Health check (includes auth status)`);
    console.log(`  POST /auth/refresh - Manually refresh OAuth token`);
    console.log(`  POST /task         - Submit Claude task (supports callback_url)`);
    console.log(`  GET  /task/:id     - Get task status`);
    console.log(`  GET  /tasks        - List recent tasks`);
    console.log(`  POST /swarm        - Run swarm task (supports callback_url)`);
    console.log('');
    console.log('Auth status:', JSON.stringify(getAuthStatus()));

    // Initial token check
    checkAndRefreshToken();
});
