# Claude-Flow for Bunny.net Magic Containers
# Features:
#   - Claude Code UI (full web interface) on port 3001
#   - Claude Code in dangerously-skip-permissions mode
#   - GitHub CLI with token auth
#   - claude-flow for multi-agent orchestration
#   - Webhook endpoint for remote task submission
#   - Startup task support
#   - Python 3 included

FROM node:20-slim

# Install system dependencies + GitHub CLI
RUN apt-get update && apt-get install -y \
    git \
    curl \
    ca-certificates \
    gnupg \
    jq \
    tmux \
    python3 \
    python3-pip \
    python3-venv \
    procps \
    && mkdir -p /etc/apt/keyrings \
    # GitHub CLI
    && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | gpg --dearmor -o /etc/apt/keyrings/githubcli-archive-keyring.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" > /etc/apt/sources.list.d/github-cli.list \
    && apt-get update \
    && apt-get install -y gh \
    && rm -rf /var/lib/apt/lists/*

# Install Claude Code CLI, claude-flow, and Claude Code UI
RUN npm install -g \
    @anthropic-ai/claude-code \
    claude-flow@alpha \
    @siteboon/claude-code-ui

# Create workspace and data directories
WORKDIR /workspace
RUN mkdir -p \
    /root/.claude-flow \
    /root/.claude/projects \
    /root/.config/gh \
    /workspace/.swarm \
    /app

# Configure Claude Code for dangerously-skip-permissions mode
RUN echo '{"permissions": {"allow_all": true}, "auto_approve": true}' > /root/.claude/settings.json

# Copy webhook server and entrypoint
COPY webhook-server.js /app/webhook-server.js
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Environment defaults
ENV CLAUDE_CODE_SKIP_PERMISSIONS=1
ENV CLAUDE_CODE_AUTO_APPROVE=1
ENV PORT=3001
ENV WEBHOOK_PORT=8080

# Expose ports
# 3001 = Claude Code UI (web interface)
# 8080 = Webhook API
EXPOSE 3001 8080

# Health check against Claude Code UI
HEALTHCHECK --interval=30s --timeout=10s --start-period=90s --retries=3 \
    CMD curl -f http://localhost:${PORT}/ || exit 1

ENTRYPOINT ["/app/entrypoint.sh"]
