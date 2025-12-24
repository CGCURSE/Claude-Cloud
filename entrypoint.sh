#!/bin/bash
set -e

echo "=== Claude-Flow Container Starting ==="

# Validate required credentials
validate_required_env() {
    local missing=()

    # Check for Claude authentication
    if [ -z "$CLAUDE_OAUTH_TOKEN" ] && [ -z "$ANTHROPIC_API_KEY" ]; then
        missing+=("CLAUDE_OAUTH_TOKEN or ANTHROPIC_API_KEY")
    fi

    # Check for UI credentials (required for security)
    if [ -z "$CLAUDE_UI_USER" ] || [ -z "$CLAUDE_UI_PASSWORD" ]; then
        echo "ERROR: CLAUDE_UI_USER and CLAUDE_UI_PASSWORD are required!"
        echo "These credentials are used to secure the web UI."
        echo "Generate a secure password with: openssl rand -base64 32"
        exit 1
    fi

    # Warn about minimum password length
    if [ ${#CLAUDE_UI_PASSWORD} -lt 12 ]; then
        echo "WARNING: CLAUDE_UI_PASSWORD should be at least 12 characters for security"
    fi

    if [ ${#missing[@]} -gt 0 ]; then
        echo "WARNING: Missing recommended environment variables:"
        printf '  - %s\n' "${missing[@]}"
    fi
}

validate_required_env

# Configure Claude OAuth authentication
if [ -n "$CLAUDE_OAUTH_TOKEN" ]; then
    echo "Configuring Claude OAuth authentication..."
    mkdir -p /root/.claude

    # Set secure permissions on .claude directory
    chmod 700 /root/.claude

    # Build the credentials JSON with OAuth tokens
    cat > /root/.claude/credentials.json << EOF
{
  "claudeAiOauth": {
    "accessToken": "$CLAUDE_OAUTH_TOKEN",
    "refreshToken": "${CLAUDE_OAUTH_REFRESH_TOKEN:-}",
    "expiresAt": ${CLAUDE_OAUTH_EXPIRES_AT:-0}
  }
}
EOF

    # Secure credentials file - owner read/write only
    chmod 600 /root/.claude/credentials.json

    echo "Claude OAuth configured (credentials secured)"
elif [ -n "$ANTHROPIC_API_KEY" ]; then
    echo "Using API key authentication (legacy mode)"
else
    echo "ERROR: No Claude authentication configured!"
    echo "Set CLAUDE_OAUTH_TOKEN for OAuth or ANTHROPIC_API_KEY for legacy auth"
    exit 1
fi

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

# Initialize default user in background (waits for UI to create database)
export DATABASE_PATH="${DATABASE_PATH:-/root/.claude-code-ui/auth.db}"
node /app/init-user.js &

# Start Claude Code UI as the main process
exec claude-code-ui
