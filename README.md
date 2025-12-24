# Claude-Flow Container for Bunny.net

Fully autonomous Claude Code with a beautiful web UI, GitHub integration, and webhook API.

## What’s Included

|Component         |Description                                               |
|------------------|----------------------------------------------------------|
|**Claude Code UI**|Full web interface with chat, file explorer, git, sessions|
|**Claude Code**   |Runs in `--dangerously-skip-permissions` mode             |
|**claude-flow**   |Multi-agent swarm orchestration                           |
|**GitHub CLI**    |Full repo operations with token auth                      |
|**Webhook API**   |Submit tasks via HTTP                                     |
|**Python 3**      |For scripts and tools                                     |

## Quick Start

```bash
# 1. Copy environment template
cp .env.example .env

# 2. Edit .env with your keys
#    - ANTHROPIC_API_KEY (required)
#    - GH_TOKEN (required for GitHub ops)

# 3. Build and run
docker-compose up -d --build

# 4. Open browser
open http://localhost:3001
```

## Ports

|Port|Service                       |
|----|------------------------------|
|3001|Claude Code UI (web interface)|
|8080|Webhook API                   |

## Environment Variables

|Variable           |Required|Description                 |
|-------------------|--------|----------------------------|
|`ANTHROPIC_API_KEY`|Yes     |Claude API key              |
|`GH_TOKEN`         |Yes     |GitHub personal access token|
|`GIT_USER_NAME`    |No      |Git commit author           |
|`GIT_USER_EMAIL`   |No      |Git commit email            |
|`CLONE_REPO`       |No      |Repo to clone on startup    |
|`STARTUP_TASK`     |No      |Task to run automatically   |
|`WEBHOOK_SECRET`   |No      |Bearer token for webhook API|

## Claude Code UI Features

Access at `http://localhost:3001`:

- **Interactive Chat** - Stream responses from Claude
- **File Explorer** - Browse, edit, create files with syntax highlighting
- **Git Integration** - View changes, stage, commit, switch branches
- **Session Management** - Resume conversations, track history
- **Shell Terminal** - Direct CLI access
- **Mobile Support** - Responsive design, works on phones

## Webhook API

Submit tasks programmatically without using the UI.

### Endpoints

|Method|Path       |Description          |
|------|-----------|---------------------|
|GET   |`/health`  |Health check         |
|POST  |`/task`    |Submit Claude task   |
|GET   |`/task/:id`|Get task result      |
|GET   |`/tasks`   |List recent tasks    |
|POST  |`/swarm`   |Run claude-flow swarm|

### Examples

```bash
# Simple task (synchronous)
curl -X POST http://localhost:8080/task \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Create a hello world script"}'

# Async task (returns immediately)
curl -X POST http://localhost:8080/task \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Build a REST API", "async": true}'

# With authentication
curl -X POST http://localhost:8080/task \
  -H "Authorization: Bearer your-secret" \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Fix the bug"}'

# Swarm task
curl -X POST http://localhost:8080/swarm \
  -H "Content-Type: application/json" \
  -d '{"task": "build authentication system"}'

# Check task status
curl http://localhost:8080/task/task_1234567890_1
```

## Startup Options

### Auto-Clone Repository

```bash
# In .env
CLONE_REPO=owner/repo
```

### Run Task on Startup

```bash
# In .env
STARTUP_TASK=analyze this codebase and create a comprehensive README
```

## Bunny.net Deployment

1. Create Magic Container in Bunny dashboard
1. Upload all files:
- `Dockerfile`
- `docker-compose.yml`
- `entrypoint.sh`
- `webhook-server.js`
1. Set environment variables in Bunny UI
1. Expose ports: `3001`, `8080`
1. Deploy

## Volumes

|Path                |Purpose                      |
|--------------------|-----------------------------|
|`/workspace`        |Your project files           |
|`/root/.claude`     |Claude Code config & projects|
|`/root/.claude-flow`|claude-flow state            |
|`/root/.config/gh`  |GitHub CLI auth              |

## Resource Requirements

- **RAM**: 2GB recommended
- **CPU**: 1 core minimum
- **Storage**: 10GB (npm packages + projects)

## Files

```
├── Dockerfile           # Container image
├── docker-compose.yml   # Single container setup
├── entrypoint.sh        # Startup script
├── webhook-server.js    # HTTP API server
├── .env.example         # Environment template
└── README.md            # This file
```

## Autonomous Mode

Claude runs with full permissions:

- No prompts for file operations
- No confirmation for shell commands
- Complete GitHub access (clone, push, PR)
- Ideal for unattended automation

## Tools Included

- `claude` - Claude Code CLI
- `claude-flow` - Multi-agent orchestration
- `gh` - GitHub CLI
- `git` - Version control
- `python3` / `pip` - Python runtime
- `node` / `npm` - Node.js runtime
- `curl` / `jq` - HTTP & JSON tools
- `tmux` - Terminal multiplexer