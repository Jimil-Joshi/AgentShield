"""Tests for MCP Security Infrastructure (Part 3).

Covers Test Case 3: Path traversal rejection + rate limiting, scope checks, auditing.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.models import AgentRegistryEntry, AgentRole, MCPToolCall
from src.mcp_server import (
    MCPSecurityServer,
    PathValidator,
    RateLimiter,
    ScopeGuard,
    AuditLogger,
)


@pytest.fixture
def path_validator():
    return PathValidator()


@pytest.fixture
def rate_limiter():
    return RateLimiter(max_per_minute=3)


@pytest.fixture
def scope_guard():
    return ScopeGuard()


@pytest.fixture
def audit_logger():
    return AuditLogger()


@pytest.fixture
def mcp_server():
    server = MCPSecurityServer(demo_mode=True, max_rate_per_minute=10)
    server.register_agent(AgentRegistryEntry(
        agent_id="agent_1",
        agent_name="Test Agent",
        role=AgentRole.READER,
        allowed_repos=["api-backend"],
        allowed_branches=["main"],
    ))
    return server


class TestPathValidator:
    """Test Case 3: Path traversal attacks must be rejected."""

    def test_block_path_traversal(self, path_validator):
        """Classic ../../../etc/passwd must be rejected."""
        is_valid, reason = path_validator.validate("../../../etc/passwd")
        assert is_valid is False
        assert reason != ""

    def test_block_encoded_traversal(self, path_validator):
        """URL-encoded path traversal."""
        is_valid, reason = path_validator.validate("..%2F..%2Fetc%2Fpasswd")
        assert is_valid is False

    def test_block_windows_traversal(self, path_validator):
        """Windows-style backslash traversal."""
        is_valid, reason = path_validator.validate("..\\..\\windows\\system32\\config")
        assert is_valid is False

    def test_block_null_byte(self, path_validator):
        is_valid, reason = path_validator.validate("file.txt\x00.jpg")
        assert is_valid is False

    def test_block_sensitive_patterns(self, path_validator):
        """Well-known sensitive files must be blocked."""
        for p in [".env", ".git/config", "id_rsa", ".ssh/authorized_keys"]:
            is_valid, reason = path_validator.validate(p)
            assert is_valid is False, f"Should block: {p}"

    def test_allow_normal_paths(self, path_validator):
        for p in ["src/main.py", "README.md", "docs/guide.md"]:
            is_valid, reason = path_validator.validate(p)
            assert is_valid is True, f"Should allow: {p} (got reason: {reason})"


class TestRateLimiter:
    def test_allows_within_limit(self, rate_limiter):
        for _ in range(3):
            allowed, msg = rate_limiter.check("agent_1")
            assert allowed is True

    def test_blocks_over_limit(self, rate_limiter):
        for _ in range(3):
            rate_limiter.check("agent_1")
        allowed, msg = rate_limiter.check("agent_1")
        assert allowed is False
        assert "rate" in msg.lower() or "limit" in msg.lower()

    def test_separate_agents(self, rate_limiter):
        for _ in range(3):
            rate_limiter.check("agent_1")
        # Different agent should still have quota
        allowed, _ = rate_limiter.check("agent_2")
        assert allowed is True


class TestScopeGuard:
    def test_check_scope_allowed(self, scope_guard):
        scope_guard.register_agent(AgentRegistryEntry(
            agent_id="agent_1",
            agent_name="Test",
            role=AgentRole.READER,
            allowed_repos=["myrepo"],
            allowed_branches=["main"],
        ))
        ok, msg = scope_guard.check("agent_1", repo="myrepo", branch="main")
        assert ok is True

    def test_check_scope_denied(self, scope_guard):
        scope_guard.register_agent(AgentRegistryEntry(
            agent_id="agent_1",
            agent_name="Test",
            role=AgentRole.READER,
            allowed_repos=["myrepo"],
            allowed_branches=["main"],
        ))
        ok, msg = scope_guard.check("agent_1", repo="other-repo")
        assert ok is False

    def test_unregistered_agent(self, scope_guard):
        ok, msg = scope_guard.check("unknown_agent", repo="myrepo")
        assert ok is False


class TestAuditLogger:
    def test_log_and_get(self, audit_logger):
        tc = MCPToolCall(
            tool_name="read_file",
            agent_id="agent_1",
            parameters={"path": "src/main.py"},
        )
        audit_logger.log(tc, result_summary="success")
        logs = audit_logger.get_logs(agent_id="agent_1")
        assert len(logs) == 1
        assert logs[0].tool_call.tool_name == "read_file"

    def test_log_filtering(self, audit_logger):
        tc1 = MCPToolCall(tool_name="read_file", agent_id="a1", parameters={})
        tc2 = MCPToolCall(tool_name="list_commits", agent_id="a2", parameters={})
        audit_logger.log(tc1, result_summary="ok")
        audit_logger.log(tc2, result_summary="ok")
        assert len(audit_logger.get_logs(agent_id="a1")) == 1
        assert len(audit_logger.get_logs()) == 2


class TestMCPSecurityServerIntegration:
    """Integration tests for the full MCP security server."""

    def test_read_file_path_traversal_blocked(self, mcp_server):
        """Test Case 3: ../../../etc/passwd → blocked + captured in audit."""
        result = mcp_server.read_file(
            agent_id="agent_1",
            repo="api-backend",
            file_path="../../../etc/passwd",
        )
        assert "error" in result or result.get("allowed") is False
        # Audit should capture the attempt
        logs = mcp_server.audit_logger.get_logs(agent_id="agent_1")
        assert len(logs) >= 1

    def test_read_file_success(self, mcp_server):
        """Normal file reads should succeed (demo data)."""
        result = mcp_server.read_file(
            agent_id="agent_1",
            repo="api-backend",
            file_path="src/auth/login.py",
        )
        assert "content" in result or "error" not in result

    def test_rate_limiting_enforced(self, mcp_server):
        """Rapid requests should eventually be rate-limited."""
        mcp_server.rate_limiter = RateLimiter(max_per_minute=2)
        mcp_server.read_file(agent_id="agent_1", repo="api-backend", file_path="src/auth/login.py")
        mcp_server.read_file(agent_id="agent_1", repo="api-backend", file_path="src/auth/login.py")
        result = mcp_server.read_file(agent_id="agent_1", repo="api-backend", file_path="src/auth/login.py")
        assert "error" in result or result.get("allowed") is False

    def test_list_commits(self, mcp_server):
        result = mcp_server.list_commits(
            agent_id="agent_1",
            repo="api-backend",
            limit=5,
        )
        assert "commits" in result
        assert len(result["commits"]) > 0

    def test_create_comment(self, mcp_server):
        # Need writer role for comments — register a writer
        mcp_server.register_agent(AgentRegistryEntry(
            agent_id="agent_writer",
            agent_name="Writer",
            role=AgentRole.WRITER,
            allowed_repos=["api-backend"],
            allowed_branches=["main"],
        ))
        result = mcp_server.create_comment(
            agent_id="agent_writer",
            repo="api-backend",
            pr_number=1,
            body="Security review passed.",
        )
        assert result.get("created") is True or "error" not in result

    def test_get_pr_details(self, mcp_server):
        result = mcp_server.get_pr_details(
            agent_id="agent_1",
            repo="api-backend",
            pr_number=1,
        )
        assert "pr_number" in result or "error" not in result
