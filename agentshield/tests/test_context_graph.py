"""Tests for Context Graph (Part 1)."""

import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.models import (
    AgentEvent,
    AgentNode,
    CodeFileNode,
    DependencyNode,
    RuntimeContextNode,
    VulnerabilityNode,
    EventType,
    FunctionCategory,
    VulnType,
    SASTSeverity,
    AccessedEdge,
    ModifiedEdge,
    AffectsEdge,
)
from src.context_graph import ContextGraph


@pytest.fixture
def graph():
    return ContextGraph()


@pytest.fixture
def populated_graph():
    """A graph pre-populated with test data."""
    g = ContextGraph()

    # Add agents
    agent1 = AgentNode(id="agent_1", name="TestAgent1", trust_score=0.8)
    agent2 = AgentNode(id="agent_2", name="TestAgent2", trust_score=0.3)
    g.add_node(agent1)
    g.add_node(agent2)

    # Add code files
    auth_file = CodeFileNode(
        id="file_auth", file_path="src/auth/login.py",
        function_category=FunctionCategory.AUTH,
        is_deployed=True, is_internet_facing=True,
    )
    payment_file = CodeFileNode(
        id="file_payment", file_path="src/payment/process.py",
        function_category=FunctionCategory.PAYMENT,
        is_deployed=True, handles_pii=True,
    )
    test_file = CodeFileNode(
        id="file_test", file_path="tests/test_auth.py",
        function_category=FunctionCategory.TEST,
    )
    g.add_node(auth_file)
    g.add_node(payment_file)
    g.add_node(test_file)

    # Add edges
    now = datetime.now(timezone.utc)
    g.add_edge(AccessedEdge(source="agent_1", target="file_auth", timestamp=now))
    g.add_edge(ModifiedEdge(
        source="agent_1", target="file_auth",
        timestamp=now, change_summary="Updated login logic",
    ))
    g.add_edge(AccessedEdge(source="agent_2", target="file_payment", timestamp=now))

    # Add vulnerability
    vuln = VulnerabilityNode(
        id="vuln_1", vuln_type=VulnType.SQL_INJECTION,
        sast_severity=SASTSeverity.HIGH,
        file_path="src/auth/login.py", cwe_id="CWE-89",
    )
    g.add_vulnerability(vuln, "file_auth")

    # Add runtime context
    ctx = RuntimeContextNode(
        id="ctx_prod", environment="production",
        is_deployed=True, is_internet_facing=True,
    )
    g.add_runtime_context(ctx, ["file_auth", "file_payment"])

    return g


class TestNodeOperations:
    def test_add_agent_node(self, graph):
        agent = AgentNode(id="a1", name="Test")
        nid = graph.add_node(agent)
        assert nid == "a1"
        assert graph.has_node("a1")

    def test_add_code_file_node(self, graph):
        cf = CodeFileNode(id="f1", file_path="src/main.py")
        graph.add_node(cf)
        data = graph.get_node_data("f1")
        assert data["file_path"] == "src/main.py"
        assert data["node_type"] == "CodeFile"

    def test_get_nodes_by_type(self, populated_graph):
        agents = populated_graph.get_nodes_by_type("Agent")
        assert len(agents) == 2
        files = populated_graph.get_nodes_by_type("CodeFile")
        assert len(files) == 3


class TestEdgeOperations:
    def test_add_edge(self, graph):
        graph.add_node(AgentNode(id="a1", name="A1"))
        graph.add_node(CodeFileNode(id="f1", file_path="test.py"))
        graph.add_edge(AccessedEdge(source="a1", target="f1"))
        edges = graph.get_edges(source="a1")
        assert len(edges) == 1
        assert edges[0]["edge_type"] == "accessed"

    def test_get_edges_by_type(self, populated_graph):
        accessed = populated_graph.get_edges(edge_type="accessed")
        modified = populated_graph.get_edges(edge_type="modified")
        assert len(accessed) >= 2
        assert len(modified) >= 1


class TestEventIngestion:
    def test_ingest_file_access(self, graph):
        event = AgentEvent(
            agent_id="agent_x", agent_name="AgentX",
            event_type=EventType.FILE_ACCESS,
            target_file="src/main.py",
        )
        action_id = graph.ingest_event(event)
        assert graph.has_node("agent_x")
        assert graph.has_node(action_id)

    def test_ingest_code_modification(self, graph):
        event = AgentEvent(
            agent_id="agent_x", agent_name="AgentX",
            event_type=EventType.CODE_MODIFICATION,
            target_file="src/auth/login.py",
            details={"change_summary": "Updated auth", "function_category": "auth"},
        )
        graph.ingest_event(event)
        agents = graph.get_agents_modifying_auth_code()
        assert len(agents) >= 1

    def test_ingest_dependency(self, graph):
        event = AgentEvent(
            agent_id="agent_x", agent_name="AgentX",
            event_type=EventType.DEPENDENCY_ADDITION,
            target_file="requirements.txt",
            details={"dependency_name": "evil-pkg", "source": "unknown", "is_trusted": False},
        )
        graph.ingest_event(event)
        deps = graph.get_dependencies_from_ai_code()
        assert len(deps) >= 1
        assert deps[0]["is_trusted"] == False


class TestQueries:
    def test_files_accessed_by_agent(self, populated_graph):
        since = datetime.now(timezone.utc) - timedelta(hours=1)
        files = populated_graph.get_files_accessed_by_agent("agent_1", since)
        assert len(files) >= 1
        assert any(f["file_path"] == "src/auth/login.py" for f in files)

    def test_agents_modifying_auth_code(self, populated_graph):
        agents = populated_graph.get_agents_modifying_auth_code()
        assert len(agents) >= 1
        assert any(a["id"] == "agent_1" for a in agents)

    def test_blast_radius(self, populated_graph):
        blast = populated_graph.get_blast_radius("agent_1")
        assert blast["total_affected"] > 0
        assert blast["agent_id"] == "agent_1"

    def test_dependencies_from_ai_code(self, graph):
        event = AgentEvent(
            agent_id="ai_agent", agent_name="AI",
            event_type=EventType.DEPENDENCY_ADDITION,
            details={"dependency_name": "ai-package", "source": "pypi"},
        )
        graph.ingest_event(event)
        deps = graph.get_dependencies_from_ai_code()
        assert len(deps) >= 1

    def test_production_vulnerabilities(self, populated_graph):
        vulns = populated_graph.get_production_vulnerabilities()
        assert len(vulns) >= 1

    def test_runtime_context_for_vulnerability(self, populated_graph):
        ctx = populated_graph.get_runtime_context_for_vulnerability("vuln_1")
        assert ctx is not None
        assert ctx.get("environment") == "production"

    def test_provenance(self, populated_graph):
        prov = populated_graph.get_provenance("src/auth/login.py")
        assert len(prov) >= 1
        assert prov[0]["agent_id"] == "agent_1"


class TestSerialization:
    def test_round_trip(self, populated_graph):
        data = populated_graph.to_dict()
        restored = ContextGraph.from_dict(data)
        assert restored.graph.number_of_nodes() == populated_graph.graph.number_of_nodes()
        assert restored.graph.number_of_edges() == populated_graph.graph.number_of_edges()


class TestStatistics:
    def test_get_stats(self, populated_graph):
        stats = populated_graph.get_stats()
        assert stats["total_nodes"] > 0
        assert stats["total_edges"] > 0
        assert "Agent" in stats["node_counts"]
        assert "CodeFile" in stats["node_counts"]
