const http = require(‘http’);
const { spawn } = require(‘child_process’);
const fs = require(‘fs’);

const PORT = process.env.WEBHOOK_PORT || 8080;
const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET || ‘’;

// Task queue
const taskQueue = [];
const taskResults = new Map();
let taskIdCounter = 1;

function generateTaskId() {
return `task_${Date.now()}_${taskIdCounter++}`;
}

function runTask(taskId, prompt, options = {}) {
return new Promise((resolve, reject) => {
const args = [’–dangerously-skip-permissions’];

```
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
    
    claude.on('close', (code) => {
        const result = {
            taskId,
            status: code === 0 ? 'completed' : 'failed',
            exitCode: code,
            stdout,
            stderr,
            completedAt: new Date().toISOString()
        };
        taskResults.set(taskId, result);
        resolve(result);
    });
    
    claude.on('error', (err) => {
        const result = {
            taskId,
            status: 'error',
            error: err.message,
            completedAt: new Date().toISOString()
        };
        taskResults.set(taskId, result);
        reject(result);
    });
});
```

}

function parseBody(req) {
return new Promise((resolve, reject) => {
let body = ‘’;
req.on(‘data’, chunk => body += chunk);
req.on(‘end’, () => {
try {
resolve(body ? JSON.parse(body) : {});
} catch (e) {
reject(new Error(‘Invalid JSON’));
}
});
});
}

function sendJSON(res, status, data) {
res.writeHead(status, { ‘Content-Type’: ‘application/json’ });
res.end(JSON.stringify(data));
}

function validateSecret(req) {
if (!WEBHOOK_SECRET) return true;
const authHeader = req.headers[‘authorization’] || ‘’;
const token = authHeader.replace(’Bearer ’, ‘’);
return token === WEBHOOK_SECRET;
}

const server = http.createServer(async (req, res) => {
const url = new URL(req.url, `http://localhost:${PORT}`);

```
// CORS headers
res.setHeader('Access-Control-Allow-Origin', '*');
res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

if (req.method === 'OPTIONS') {
    res.writeHead(204);
    return res.end();
}

// Health check
if (url.pathname === '/health') {
    return sendJSON(res, 200, { 
        status: 'healthy',
        timestamp: new Date().toISOString(),
        pendingTasks: taskQueue.length
    });
}

// Validate auth for other endpoints
if (!validateSecret(req)) {
    return sendJSON(res, 401, { error: 'Unauthorized' });
}

// Submit task
if (url.pathname === '/task' && req.method === 'POST') {
    try {
        const body = await parseBody(req);
        
        if (!body.prompt) {
            return sendJSON(res, 400, { error: 'Missing prompt' });
        }
        
        const taskId = generateTaskId();
        const options = {
            cwd: body.cwd || '/workspace',
            env: body.env || {}
        };
        
        // Store initial task status
        taskResults.set(taskId, {
            taskId,
            status: 'running',
            prompt: body.prompt,
            startedAt: new Date().toISOString()
        });
        
        // Run async (fire and forget if async: true)
        if (body.async) {
            runTask(taskId, body.prompt, options).catch(console.error);
            return sendJSON(res, 202, { taskId, status: 'accepted' });
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
        
        const swarm = spawn('claude-flow', ['swarm', body.task, '--claude'], {
            cwd: body.cwd || '/workspace'
        });
        
        let output = '';
        swarm.stdout.on('data', d => output += d);
        swarm.stderr.on('data', d => output += d);
        
        swarm.on('close', (code) => {
            taskResults.set(taskId, {
                taskId,
                type: 'swarm',
                status: code === 0 ? 'completed' : 'failed',
                output,
                completedAt: new Date().toISOString()
            });
        });
        
        if (body.async) {
            return sendJSON(res, 202, { taskId, status: 'accepted' });
        }
        
        await new Promise(resolve => swarm.on('close', resolve));
        return sendJSON(res, 200, taskResults.get(taskId));
        
    } catch (e) {
        return sendJSON(res, 500, { error: e.message });
    }
}

// 404 for unknown routes
sendJSON(res, 404, { error: 'Not found' });
```

});

server.listen(PORT, () => {
console.log(`Webhook server listening on port ${PORT}`);
console.log(`Endpoints:`);
console.log(`  GET  /health      - Health check`);
console.log(`  POST /task        - Submit Claude task`);
console.log(`  GET  /task/:id    - Get task status`);
console.log(`  GET  /tasks       - List recent tasks`);
console.log(`  POST /swarm       - Run swarm task`);
});