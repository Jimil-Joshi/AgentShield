"""
AgentShield MCP Server (Part 3)
Secure MCP server exposing GitHub operations with guardrails.
Implements: input validation, rate limiting, scope limiting, audit logging.
Uses the official MCP Python SDK (FastMCP).
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Optional

from .models import (
    AgentRegistryEntry,
    AgentRole,
    MCPAuditLog,
    MCPToolCall,
)

logger = logging.getLogger("agentshield.mcp_server")


# ─────────────────────────────────────────────
# Security Guardrails
# ─────────────────────────────────────────────

class PathValidator:
    """
    Prevents path traversal attacks.
    Rejects: ../, ..\\, absolute paths, null bytes, /etc/passwd, etc.
    """

    BLOCKED_PATTERNS = [
        r"\.\./",          # Unix path traversal
        r"\.\.\\\:",       # Windows path traversal
        r"\.\.",           # Any ..
        r"^/",             # Absolute Unix path
        r"^[A-Za-z]:\\",   # Absolute Windows path
        r"\x00",           # Null byte injection
        r"%00",            # URL-encoded null byte
        r"%2e%2e",         # URL-encoded ..
        r"/etc/",          # Unix system paths
        r"\\windows\\",    # Windows system paths
        r"\.env",          # Environment files
        r"\.git/",         # Git internals
        r"\.ssh",          # SSH keys
        r"id_rsa",
        r"\.pem$",
        r"\.key$",
        r"credentials",
        r"secrets",
    ]

    @classmethod
    def validate(cls, file_path: str) -> tuple[bool, str]:
        """
        Validate a file path is safe.
        Returns (is_valid, error_message).
        """
        if not file_path or not file_path.strip():
            return False, "Empty file path"

        normalized = file_path.replace("\\", "/").lower()

        for pattern in cls.BLOCKED_PATTERNS:
            if re.search(pattern, normalized, re.IGNORECASE):
                return False, f"Path traversal/security violation detected: '{file_path}' matches blocked pattern"

        # Validate it looks like a reasonable relative file path
        if not re.match(r"^[a-zA-Z0-9_\-./]+$", file_path.replace("\\", "/")):
            return False, f"Invalid characters in file path: '{file_path}'"

        return True, ""


class RateLimiter:
    """
    Sliding window rate limiter.
    Max operations per minute per agent.
    """

    def __init__(self, max_per_minute: int = 10):
        self.max_per_minute = max_per_minute
        self._windows: dict[str, list[float]] = defaultdict(list)

    def check(self, agent_id: str) -> tuple[bool, str]:
        """
        Check if agent is within rate limit.
        Returns (allowed, error_message).
        """
        now = time.time()
        window = self._windows[agent_id]

        # Remove entries outside the 60s window
        self._windows[agent_id] = [t for t in window if now - t < 60]
        window = self._windows[agent_id]

        if len(window) >= self.max_per_minute:
            return False, (
                f"Rate limit exceeded for agent '{agent_id}': "
                f"{len(window)}/{self.max_per_minute} operations in the last minute"
            )

        self._windows[agent_id].append(now)
        return True, ""

    def get_usage(self, agent_id: str) -> dict:
        """Get current rate usage for an agent."""
        now = time.time()
        window = [t for t in self._windows.get(agent_id, []) if now - t < 60]
        return {
            "agent_id": agent_id,
            "current_count": len(window),
            "max_per_minute": self.max_per_minute,
            "remaining": max(0, self.max_per_minute - len(window)),
        }


class ScopeGuard:
    """
    Scope limiter — agents can only access specific repos/branches.
    """

    def __init__(self, registry: dict[str, AgentRegistryEntry] = None):
        self._registry = registry or {}

    def register_agent(self, entry: AgentRegistryEntry) -> None:
        self._registry[entry.agent_id] = entry

    def check(
        self, agent_id: str, repo: str, branch: str = "main"
    ) -> tuple[bool, str]:
        """Check if agent can access the given repo/branch."""
        entry = self._registry.get(agent_id)
        if entry is None:
            return False, f"Agent '{agent_id}' is not registered"

        if not entry.is_active:
            return False, f"Agent '{agent_id}' is deactivated"

        if entry.allowed_repos and repo not in entry.allowed_repos:
            return False, (
                f"Agent '{agent_id}' does not have access to repo '{repo}'. "
                f"Allowed repos: {entry.allowed_repos}"
            )

        if entry.allowed_branches and branch not in entry.allowed_branches:
            return False, (
                f"Agent '{agent_id}' cannot access branch '{branch}'. "
                f"Allowed branches: {entry.allowed_branches}"
            )

        return True, ""

    def check_permission(
        self, agent_id: str, tool_name: str
    ) -> tuple[bool, str]:
        """Check role-based permission for a tool."""
        entry = self._registry.get(agent_id)
        if entry is None:
            return False, f"Agent '{agent_id}' is not registered"

        # Role → allowed tools mapping
        role_permissions = {
            AgentRole.ADMIN: {"read_file", "list_commits", "create_comment", "get_pr_details"},
            AgentRole.WRITER: {"read_file", "list_commits", "create_comment", "get_pr_details"},
            AgentRole.READER: {"read_file", "list_commits", "get_pr_details"},
            AgentRole.SECURITY_SCANNER: {"read_file", "list_commits", "get_pr_details"},
        }

        allowed = role_permissions.get(entry.role, set())
        if tool_name not in allowed:
            return False, (
                f"Agent '{agent_id}' (role: {entry.role.value}) "
                f"lacks permission for tool '{tool_name}'"
            )

        return True, ""


class AuditLogger:
    """
    Logs every MCP tool call with full context.
    In-memory list with optional JSON export.
    """

    def __init__(self):
        self.logs: list[MCPAuditLog] = []

    def log(
        self,
        tool_call: MCPToolCall,
        result_summary: str = "",
        duration_ms: float = 0.0,
        security_violations: list[str] = None,
        allowed: bool = True,
    ) -> MCPAuditLog:
        entry = MCPAuditLog(
            tool_call=tool_call,
            result_summary=result_summary,
            duration_ms=duration_ms,
            security_violations=security_violations or [],
            allowed=allowed,
        )
        self.logs.append(entry)
        log_level = logging.WARNING if not allowed else logging.INFO
        logger.log(
            log_level,
            "MCP %s | agent=%s tool=%s allowed=%s violations=%s",
            "BLOCKED" if not allowed else "OK",
            tool_call.agent_id,
            tool_call.tool_name,
            allowed,
            security_violations or [],
        )
        return entry

    def get_logs(
        self, agent_id: Optional[str] = None, tool_name: Optional[str] = None
    ) -> list[MCPAuditLog]:
        results = self.logs
        if agent_id:
            results = [l for l in results if l.tool_call.agent_id == agent_id]
        if tool_name:
            results = [l for l in results if l.tool_call.tool_name == tool_name]
        return results

    def get_violations(self) -> list[MCPAuditLog]:
        return [l for l in self.logs if l.security_violations]

    def export_json(self) -> str:
        return json.dumps(
            [l.model_dump(mode="json") for l in self.logs], indent=2, default=str
        )


# ─────────────────────────────────────────────
# Simulated GitHub Data (Demo Mode)
# ─────────────────────────────────────────────

DEMO_FILES = {
    "api-backend": {
        "main": {
            "src/auth/login.py": (
                "from flask import request, session\n"
                "def login(username, password):\n"
                "    user = db.query(f'SELECT * FROM users WHERE username=\"{username}\"')\n"
                "    if verify_password(password, user.hash):\n"
                "        session['user'] = user.id\n"
                "        return redirect('/dashboard')\n"
            ),
            "src/payment/process.py": (
                "import stripe\n"
                "def process_payment(user_id, amount, card_token):\n"
                "    user = get_user(user_id)\n"
                "    charge = stripe.Charge.create(\n"
                "        amount=int(amount * 100),\n"
                "        currency='usd',\n"
                "        source=card_token,\n"
                "    )\n"
                "    log_payment(user_id, charge.id, amount)\n"
                "    return charge\n"
            ),
            "src/admin/dashboard.py": (
                "from flask import render_template_string\n"
                "def admin_dashboard(user):\n"
                "    return render_template_string(\n"
                "        f'<h1>Welcome {user.name}</h1><p>{user.email}</p>'\n"
                "    )\n"
            ),
            "tests/test_auth.py": (
                "import pytest\n"
                "def test_login_valid():\n"
                "    result = login('admin', 'password123')\n"
                "    assert result.status == 200\n"
            ),
            "scripts/dev_setup.py": (
                "# Dev-only setup script\n"
                "DB_PASSWORD = 'dev_password_123'\n"
                "API_KEY = 'sk-dev-test-key-not-real'\n"
                "def setup_dev_db():\n"
                "    connect(f'postgresql://dev:{DB_PASSWORD}@localhost/devdb')\n"
            ),
            "README.md": "# API Backend\nProduction API service.",
        }
    }
}

DEMO_COMMITS = {
    "api-backend": [
        {"sha": "abc1234", "message": "Fix auth validation", "author": "dev-agent", "date": "2026-02-25"},
        {"sha": "def5678", "message": "Add payment processing", "author": "code-agent", "date": "2026-02-24"},
        {"sha": "ghi9012", "message": "Update admin dashboard", "author": "ai-agent-1", "date": "2026-02-23"},
    ]
}

DEMO_PRS = {
    "api-backend": {
        1: {"title": "Fix SQL injection in login", "author": "security-bot", "state": "open", "base": "main"},
        2: {"title": "Add rate limiting", "author": "dev-agent", "state": "merged", "base": "main"},
    }
}


# ─────────────────────────────────────────────
# MCP Server Implementation
# ─────────────────────────────────────────────

class MCPSecurityServer:
    """
    Secure MCP server exposing GitHub operations with guardrails.
    Works in demo mode (simulated data) or real mode (GitHub API).
    """

    def __init__(
        self,
        demo_mode: bool = True,
        max_rate_per_minute: int = 10,
    ):
        self.demo_mode = demo_mode
        self.path_validator = PathValidator()
        self.rate_limiter = RateLimiter(max_per_minute=max_rate_per_minute)
        self.scope_guard = ScopeGuard()
        self.audit_logger = AuditLogger()
        self._github_token = os.getenv("GITHUB_TOKEN")

        if not demo_mode and not self._github_token:
            logger.warning("GITHUB_TOKEN not set — falling back to demo mode")
            self.demo_mode = True

    def register_agent(self, entry: AgentRegistryEntry) -> None:
        """Register an agent with the server."""
        self.scope_guard.register_agent(entry)

    def _pre_check(
        self, agent_id: str, tool_name: str, repo: str, branch: str = "main",
        file_path: Optional[str] = None,
    ) -> tuple[bool, list[str]]:
        """
        Run all security guardrails before tool execution.
        Returns (allowed, list_of_violations).
        """
        violations = []

        # 1. Rate limit
        allowed, msg = self.rate_limiter.check(agent_id)
        if not allowed:
            violations.append(msg)

        # 2. Scope check
        allowed, msg = self.scope_guard.check(agent_id, repo, branch)
        if not allowed:
            violations.append(msg)

        # 3. Permission check
        allowed, msg = self.scope_guard.check_permission(agent_id, tool_name)
        if not allowed:
            violations.append(msg)

        # 4. Path validation (if applicable)
        if file_path:
            allowed, msg = self.path_validator.validate(file_path)
            if not allowed:
                violations.append(msg)

        return len(violations) == 0, violations

    # ── Tool: read_file ──────────────────────────────────────────

    def read_file(
        self, agent_id: str, repo: str, file_path: str, branch: str = "main"
    ) -> dict:
        """Read a file from a repository."""
        start_time = time.time()
        tool_call = MCPToolCall(
            tool_name="read_file",
            agent_id=agent_id,
            parameters={"repo": repo, "file_path": file_path, "branch": branch},
        )

        allowed, violations = self._pre_check(
            agent_id, "read_file", repo, branch, file_path
        )

        if not allowed:
            self.audit_logger.log(
                tool_call,
                result_summary="BLOCKED",
                duration_ms=(time.time() - start_time) * 1000,
                security_violations=violations,
                allowed=False,
            )
            return {"error": "Access denied", "violations": violations, "allowed": False}

        # Execute
        if self.demo_mode:
            content = (
                DEMO_FILES.get(repo, {}).get(branch, {}).get(file_path)
            )
            if content is None:
                result = {"error": f"File not found: {repo}/{branch}/{file_path}"}
            else:
                result = {"content": content, "file_path": file_path, "repo": repo, "branch": branch}
        else:
            result = self._github_read_file(repo, file_path, branch)

        self.audit_logger.log(
            tool_call,
            result_summary="OK" if "error" not in result else result["error"],
            duration_ms=(time.time() - start_time) * 1000,
            allowed=True,
        )
        return result

    # ── Tool: list_commits ───────────────────────────────────────

    def list_commits(
        self, agent_id: str, repo: str, branch: str = "main", limit: int = 10
    ) -> dict:
        """List recent commits for a repository."""
        start_time = time.time()
        tool_call = MCPToolCall(
            tool_name="list_commits",
            agent_id=agent_id,
            parameters={"repo": repo, "branch": branch, "limit": limit},
        )

        allowed, violations = self._pre_check(agent_id, "list_commits", repo, branch)

        if not allowed:
            self.audit_logger.log(
                tool_call, result_summary="BLOCKED",
                duration_ms=(time.time() - start_time) * 1000,
                security_violations=violations, allowed=False,
            )
            return {"error": "Access denied", "violations": violations, "allowed": False}

        if self.demo_mode:
            commits = DEMO_COMMITS.get(repo, [])[:limit]
            result = {"commits": commits, "repo": repo, "branch": branch}
        else:
            result = self._github_list_commits(repo, branch, limit)

        self.audit_logger.log(
            tool_call, result_summary=f"{len(result.get('commits', []))} commits",
            duration_ms=(time.time() - start_time) * 1000, allowed=True,
        )
        return result

    # ── Tool: create_comment ─────────────────────────────────────

    def create_comment(
        self, agent_id: str, repo: str, pr_number: int, body: str
    ) -> dict:
        """Create a comment on a pull request."""
        start_time = time.time()
        tool_call = MCPToolCall(
            tool_name="create_comment",
            agent_id=agent_id,
            parameters={"repo": repo, "pr_number": pr_number, "body": body[:200]},
        )

        allowed, violations = self._pre_check(agent_id, "create_comment", repo)

        if not allowed:
            self.audit_logger.log(
                tool_call, result_summary="BLOCKED",
                duration_ms=(time.time() - start_time) * 1000,
                security_violations=violations, allowed=False,
            )
            return {"error": "Access denied", "violations": violations, "allowed": False}

        if self.demo_mode:
            result = {
                "comment_id": f"comment_{int(time.time())}",
                "pr_number": pr_number,
                "body": body,
                "created": True,
            }
        else:
            result = self._github_create_comment(repo, pr_number, body)

        self.audit_logger.log(
            tool_call, result_summary="Comment created",
            duration_ms=(time.time() - start_time) * 1000, allowed=True,
        )
        return result

    # ── Tool: get_pr_details ─────────────────────────────────────

    def get_pr_details(
        self, agent_id: str, repo: str, pr_number: int
    ) -> dict:
        """Get details of a pull request."""
        start_time = time.time()
        tool_call = MCPToolCall(
            tool_name="get_pr_details",
            agent_id=agent_id,
            parameters={"repo": repo, "pr_number": pr_number},
        )

        allowed, violations = self._pre_check(agent_id, "get_pr_details", repo)

        if not allowed:
            self.audit_logger.log(
                tool_call, result_summary="BLOCKED",
                duration_ms=(time.time() - start_time) * 1000,
                security_violations=violations, allowed=False,
            )
            return {"error": "Access denied", "violations": violations, "allowed": False}

        if self.demo_mode:
            pr = DEMO_PRS.get(repo, {}).get(pr_number)
            if pr:
                result = {"pr_number": pr_number, **pr}
            else:
                result = {"error": f"PR #{pr_number} not found in {repo}"}
        else:
            result = self._github_get_pr(repo, pr_number)

        self.audit_logger.log(
            tool_call,
            result_summary="OK" if "error" not in result else result["error"],
            duration_ms=(time.time() - start_time) * 1000, allowed=True,
        )
        return result

    # ── Real GitHub API calls (when GITHUB_TOKEN is set) ─────────

    def _github_read_file(self, repo: str, file_path: str, branch: str) -> dict:
        try:
            import httpx
            resp = httpx.get(
                f"https://api.github.com/repos/{repo}/contents/{file_path}",
                params={"ref": branch},
                headers={"Authorization": f"token {self._github_token}"},
            )
            if resp.status_code == 200:
                import base64
                data = resp.json()
                content = base64.b64decode(data["content"]).decode()
                return {"content": content, "file_path": file_path, "repo": repo}
            return {"error": f"GitHub API error: {resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def _github_list_commits(self, repo: str, branch: str, limit: int) -> dict:
        try:
            import httpx
            resp = httpx.get(
                f"https://api.github.com/repos/{repo}/commits",
                params={"sha": branch, "per_page": limit},
                headers={"Authorization": f"token {self._github_token}"},
            )
            if resp.status_code == 200:
                commits = [
                    {"sha": c["sha"][:7], "message": c["commit"]["message"], "author": c["commit"]["author"]["name"]}
                    for c in resp.json()
                ]
                return {"commits": commits, "repo": repo}
            return {"error": f"GitHub API error: {resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def _github_create_comment(self, repo: str, pr_number: int, body: str) -> dict:
        try:
            import httpx
            resp = httpx.post(
                f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments",
                json={"body": body},
                headers={"Authorization": f"token {self._github_token}"},
            )
            if resp.status_code == 201:
                return {"comment_id": resp.json()["id"], "created": True}
            return {"error": f"GitHub API error: {resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def _github_get_pr(self, repo: str, pr_number: int) -> dict:
        try:
            import httpx
            resp = httpx.get(
                f"https://api.github.com/repos/{repo}/pulls/{pr_number}",
                headers={"Authorization": f"token {self._github_token}"},
            )
            if resp.status_code == 200:
                pr = resp.json()
                return {"pr_number": pr_number, "title": pr["title"], "state": pr["state"], "author": pr["user"]["login"]}
            return {"error": f"GitHub API error: {resp.status_code}"}
        except Exception as e:
            return {"error": str(e)}


# ─────────────────────────────────────────────
# FastMCP Server (for real MCP protocol usage)
# ─────────────────────────────────────────────

def create_mcp_server(
    server: Optional[MCPSecurityServer] = None,
    default_agent_id: str = "mcp-client",
) -> Any:
    """
    Create a FastMCP server wrapping the MCPSecurityServer.
    This exposes the tools via the MCP protocol (stdio/SSE transport).
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError:
        logger.error("mcp package not installed. Install with: pip install mcp")
        return None

    if server is None:
        server = MCPSecurityServer(demo_mode=True)
        # Register a default agent
        server.register_agent(AgentRegistryEntry(
            agent_id=default_agent_id,
            agent_name="MCP Client",
            role=AgentRole.READER,
            allowed_repos=["api-backend"],
            allowed_branches=["main"],
        ))

    mcp = FastMCP("AgentShield Security Server")

    @mcp.tool()
    def read_file(repo: str, file_path: str, branch: str = "main") -> str:
        """Read a file from a repository. Subject to security guardrails."""
        result = server.read_file(default_agent_id, repo, file_path, branch)
        return json.dumps(result, indent=2, default=str)

    @mcp.tool()
    def list_commits(repo: str, branch: str = "main", limit: int = 10) -> str:
        """List recent commits for a repository."""
        result = server.list_commits(default_agent_id, repo, branch, limit)
        return json.dumps(result, indent=2, default=str)

    @mcp.tool()
    def create_comment(repo: str, pr_number: int, body: str) -> str:
        """Create a comment on a pull request."""
        result = server.create_comment(default_agent_id, repo, pr_number, body)
        return json.dumps(result, indent=2, default=str)

    @mcp.tool()
    def get_pr_details(repo: str, pr_number: int) -> str:
        """Get details of a pull request."""
        result = server.get_pr_details(default_agent_id, repo, pr_number)
        return json.dumps(result, indent=2, default=str)

    return mcp


if __name__ == "__main__":
    mcp_app = create_mcp_server()
    if mcp_app:
        mcp_app.run(transport="stdio")
