"""Tests for Autonomous Verifier Agent (Part 2).

Covers Test Cases 1, 1b, 2, and 4 from the specification.
"""

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.models import (
    AgentEvent,
    AgentNode,
    CodeFileNode,
    DependencyNode,
    EventType,
    VerificationDecision,
    FunctionCategory,
)
from src.context_graph import ContextGraph
from src.verifier_agent import (
    VerifierAgent,
    check_rule_001,
    check_rule_002,
    check_rule_003,
    check_rule_004,
    check_rule_005,
)


@pytest.fixture
def security_graph():
    """Build a context graph matching the spec's test scenarios."""
    g = ContextGraph()

    # Agents
    g.add_node(AgentNode(id="agent_codegen", name="CodeGen Agent", trust_score=0.7))
    g.add_node(AgentNode(id="agent_low_trust", name="Low Trust Agent", trust_score=0.2))

    # Code files
    g.add_node(CodeFileNode(
        id="file_auth_controller",
        file_path="src/auth/controller.py",
        function_category=FunctionCategory.AUTH,
        contains_security_logic=True,
        is_deployed=True,
    ))
    g.add_node(CodeFileNode(
        id="file_test_auth",
        file_path="tests/test_auth.py",
        function_category=FunctionCategory.TEST,
        contains_security_logic=True,
    ))
    g.add_node(CodeFileNode(
        id="file_config",
        file_path="config/.env.production",
        is_credential_file=True,
        is_deployed=True,
    ))

    return g


@pytest.fixture
def verifier(security_graph):
    return VerifierAgent(context_graph=security_graph)


# Rules take (event, context_dict) — context is the enriched dict, not the graph
def _make_context(security_graph, target_file=None):
    """Build a context dict like VerifierAgent._enrich_context would."""
    ctx = {"file_data": {}, "agent_data": {}, "agent_trust_score": 0.5}
    if target_file:
        file_data = security_graph.get_code_file_by_path(target_file)
        ctx["file_data"] = file_data or {}
    return ctx


class TestRule001:
    """Rule: BLOCK if agent removes or weakens security logic in production code."""

    def test_block_security_removal_in_prod(self, security_graph):
        """Test Case 1: Agent deletes auth validation → BLOCK."""
        event = AgentEvent(
            agent_id="agent_codegen",
            agent_name="CodeGen Agent",
            event_type=EventType.CODE_MODIFICATION,
            target_file="src/auth/controller.py",
            details={
                "change_summary": "Removed authentication validation check for simplification",
                "lines_removed": 15,
                "lines_added": 2,
                "function_category": "auth",
            },
        )
        ctx = _make_context(security_graph, "src/auth/controller.py")
        result = check_rule_001(event, ctx)
        assert result is not None
        assert result["decision"] == VerificationDecision.BLOCK

    def test_allow_security_removal_in_test(self, security_graph):
        """Test Case 1b: Same change in test file → ALLOW (not BLOCK)."""
        event = AgentEvent(
            agent_id="agent_codegen",
            agent_name="CodeGen Agent",
            event_type=EventType.CODE_MODIFICATION,
            target_file="tests/test_auth.py",
            details={
                "change_summary": "Removed authentication check from test helper",
                "lines_removed": 10,
                "lines_added": 2,
                "function_category": "test",
            },
        )
        ctx = _make_context(security_graph, "tests/test_auth.py")
        result = check_rule_001(event, ctx)
        # For test files, rule returns ALLOW (not BLOCK)
        assert result is not None
        assert result["decision"] == VerificationDecision.ALLOW


class TestRule002:
    """Rule: REQUIRE_HUMAN_REVIEW for new dependencies from untrusted sources."""

    def test_untrusted_dependency(self, security_graph):
        """Test Case 2: New dependency from untrusted fork → REQUIRE_HUMAN_REVIEW."""
        event = AgentEvent(
            agent_id="agent_codegen",
            agent_name="CodeGen Agent",
            event_type=EventType.DEPENDENCY_ADDITION,
            details={
                "dependency_name": "json-parser-fork-v2",
                "version": "0.1.0-alpha",
                "source": "unknown-registry",
                "is_trusted": False,
            },
        )
        ctx = _make_context(security_graph)
        result = check_rule_002(event, ctx)
        assert result is not None
        assert result["decision"] == VerificationDecision.REQUIRE_HUMAN_REVIEW


class TestRule003:
    """Rule: Auth code changes require human review."""

    def test_auth_code_change(self, security_graph):
        event = AgentEvent(
            agent_id="agent_codegen",
            agent_name="CodeGen Agent",
            event_type=EventType.CODE_MODIFICATION,
            target_file="src/auth/controller.py",
            details={"change_summary": "Updated login logic"},
        )
        ctx = _make_context(security_graph, "src/auth/controller.py")
        result = check_rule_003(event, ctx)
        assert result is not None
        assert result["decision"] == VerificationDecision.REQUIRE_HUMAN_REVIEW


class TestRule004:
    """Rule: BLOCK if agent accesses credential files."""

    def test_block_credential_access(self, security_graph):
        """Test Case 4: Agent reads .env.production → BLOCK."""
        event = AgentEvent(
            agent_id="agent_low_trust",
            agent_name="Low Trust Agent",
            event_type=EventType.FILE_ACCESS,
            target_file="config/.env.production",
        )
        ctx = _make_context(security_graph, "config/.env.production")
        result = check_rule_004(event, ctx)
        assert result is not None
        assert result["decision"] == VerificationDecision.BLOCK


class TestRule005:
    """Rule: PII-handling code changes require review."""

    def test_review_pii_change(self, security_graph):
        # Add a PII-handling file to the graph
        security_graph.add_node(CodeFileNode(
            id="file_pii",
            file_path="src/pii/handler.py",
            handles_pii=True,
        ))
        event = AgentEvent(
            agent_id="agent_codegen",
            agent_name="CodeGen Agent",
            event_type=EventType.CODE_MODIFICATION,
            target_file="src/pii/handler.py",
            details={"change_summary": "Updated PII handling"},
        )
        ctx = _make_context(security_graph, "src/pii/handler.py")
        result = check_rule_005(event, ctx)
        assert result is not None
        assert result["decision"] == VerificationDecision.WARN


class TestVerifierAgentIntegration:
    """Integration tests for the complete VerifierAgent."""

    def test_verify_returns_result(self, verifier):
        """Verify the agent returns a properly structured result."""
        event = AgentEvent(
            agent_id="agent_codegen",
            agent_name="CodeGen Agent",
            event_type=EventType.CODE_MODIFICATION,
            target_file="src/auth/controller.py",
            details={
                "change_summary": "Removed authentication validation",
                "lines_removed": 15,
                "lines_added": 2,
                "function_category": "auth",
            },
        )
        result = verifier.verify(event)
        assert result is not None
        assert hasattr(result, "decision")
        assert hasattr(result, "rules_violated")
        assert result.decision == VerificationDecision.BLOCK

    def test_allow_benign_modification(self, verifier):
        """A normal code change should be ALLOWED."""
        event = AgentEvent(
            agent_id="agent_codegen",
            agent_name="CodeGen Agent",
            event_type=EventType.CODE_MODIFICATION,
            target_file="src/utils/helper.py",
            details={
                "change_summary": "Added logging statement",
                "lines_removed": 0,
                "lines_added": 2,
            },
        )
        result = verifier.verify(event)
        assert result.decision == VerificationDecision.ALLOW

    def test_multiple_rules_triggered(self, verifier):
        """When multiple rules trigger, the strictest decision wins."""
        event = AgentEvent(
            agent_id="agent_low_trust",
            agent_name="Low Trust Agent",
            event_type=EventType.FILE_ACCESS,
            target_file="config/.env.production",
        )
        result = verifier.verify(event)
        assert result.decision == VerificationDecision.BLOCK
        assert len(result.rules_violated) >= 1
