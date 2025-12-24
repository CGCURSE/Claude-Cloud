#!/bin/bash
set -e

echo "=== Claude-Flow Container Starting ==="

# Configure GitHub CLI if token provided
if [ -n "$GH_TOKEN" ]; then
    echo "Authenticating GitHub CLI..."
    echo "$GH_TOKEN" | gh auth login --with-token
    gh auth setup-git
    echo "GitHub CLI authenticated"
fi

# Configure git identity
if [ -n "$GIT_USER_NAME" ]; then
    git config --global user.name "$GIT_USER_NAME"
fi
if [ -n "$GIT_USER_EMAIL" ]; then
    git config --global user.email "$GIT_USER_EMAIL"
fi

# Initialize claude-flow
echo "Initializing claude-flow..."
claude-flow init --force 2>/dev/null || true

# Start webhook server in background
echo "Starting webhook server on port ${WEBHOOK_PORT:-8080}..."
node /app/webhook-server.js &

# Clone repo if specified
if [ -n "$CLONE_REPO" ]; then
    echo "Cloning repository: $CLONE_REPO"
    cd /workspace
    if [ -n "$GH_TOKEN" ]; then
        gh repo clone "$CLONE_REPO" repo 2>/dev/null || git clone "$CLONE_REPO" repo
    else
        git clone "$CLONE_REPO" repo
    fi
    cd repo
    
    # Initialize as Claude project
    claude --dangerously-skip-permissions -p "Initialize" 2>/dev/null || true
fi

# Execute startup task if specified (runs in background after UI starts)
if [ -n "$STARTUP_TASK" ]; then
    echo "=== Startup Task Queued ==="
    echo "Task: $STARTUP_TASK"
    (
        sleep 15  # Wait for UI to fully start
        cd /workspace
        [ -d "repo" ] && cd repo
        echo "$STARTUP_TASK" | claude --dangerously-skip-permissions
    ) &
fi

echo ""
echo "=== Container Ready ==="
echo ""
echo "  🌐 Claude Code UI: http://localhost:${PORT:-3001}"
echo "  🔌 Webhook API:    http://localhost:${WEBHOOK_PORT:-8080}"
echo ""
echo "Features:"
echo "  ✓ Interactive chat with Claude"
echo "  ✓ File explorer with syntax highlighting"
echo "  ✓ Git integration (view, stage, commit)"
echo "  ✓ Session management & history"
echo "  ✓ Mobile-friendly responsive design"
echo "  ✓ Built-in shell terminal"
echo ""

# Start Claude Code UI as the main process
exec claude-code-ui
