"""
AgentShield Context Graph (Part 1)
Graph-based knowledge schema capturing AI agent interactions with code.
Uses NetworkX MultiDiGraph for typed nodes, typed edges, and provenance tracking.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

import networkx as nx

from .models import (
    AgentEvent,
    AgentNode,
    CodeFileNode,
    DependencyNode,
    SecurityRuleNode,
    ActionNode,
    VulnerabilityNode,
    RuntimeContextNode,
    GraphNode,
    GraphEdge,
    AccessedEdge,
    ModifiedEdge,
    DependsOnEdge,
    TriggeredEdge,
    ViolatedEdge,
    AffectsEdge,
    ExploitsEdge,
    EventType,
    FunctionCategory,
)
from .utils import is_auth_file, is_credential_file, is_test_file, generate_id

logger = logging.getLogger("agentshield.context_graph")


class ContextGraph:
    """
    A knowledge graph tracking AI agent interactions with code, dependencies,
    vulnerabilities, and runtime context.

    Backed by NetworkX MultiDiGraph — supports multiple typed edges between
    the same node pair.
    """

    def __init__(self) -> None:
        self.graph = nx.MultiDiGraph()
        self._node_index: dict[str, GraphNode] = {}  # id → Pydantic model
        self._edge_list: list[GraphEdge] = []

    # ── Node operations ──────────────────────────────────────────

    def add_node(self, node: GraphNode) -> str:
        """Add a typed node. Returns the node ID."""
        node_id = node.id
        attrs = node.model_dump()
        self.graph.add_node(node_id, **attrs)
        self._node_index[node_id] = node
        return node_id

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        """Retrieve a node's Pydantic model by ID."""
        return self._node_index.get(node_id)

    def get_node_data(self, node_id: str) -> Optional[dict]:
        """Retrieve a node's raw attribute dict."""
        if node_id in self.graph:
            return dict(self.graph.nodes[node_id])
        return None

    def has_node(self, node_id: str) -> bool:
        return node_id in self.graph

    def get_nodes_by_type(self, node_type: str) -> list[dict]:
        """Return all nodes of a given type as dicts."""
        return [
            dict(self.graph.nodes[n])
            for n in self.graph.nodes
            if self.graph.nodes[n].get("node_type") == node_type
        ]

    # ── Edge operations ──────────────────────────────────────────

    def add_edge(self, edge: GraphEdge) -> None:
        """Add a typed edge between two nodes."""
        attrs = edge.model_dump()
        edge_type = attrs.pop("edge_type")
        source = attrs.pop("source")
        target = attrs.pop("target")
        self.graph.add_edge(source, target, key=edge_type, edge_type=edge_type, **attrs)
        self._edge_list.append(edge)

    def get_edges(
        self, source: Optional[str] = None, edge_type: Optional[str] = None
    ) -> list[dict]:
        """Get edges, optionally filtered by source and/or type."""
        results = []
        edges = self.graph.edges(data=True, keys=True)
        if source:
            edges = self.graph.edges(source, data=True, keys=True)
        for u, v, k, d in edges:
            if edge_type and d.get("edge_type") != edge_type:
                continue
            results.append({"source": u, "target": v, "key": k, **d})
        return results

    # ── Event ingestion ──────────────────────────────────────────

    def ingest_event(self, event: AgentEvent) -> str:
        """
        Ingest an agent event, auto-creating nodes and edges.
        Returns the created Action node ID.
        """
        # Ensure agent node exists
        if not self.has_node(event.agent_id):
            agent = AgentNode(
                id=event.agent_id,
                name=event.agent_name or event.agent_id,
            )
            self.add_node(agent)

        # Create action node
        action = ActionNode(
            action_type=event.event_type,
            timestamp=event.timestamp,
            agent_id=event.agent_id,
            target=event.target_file,
            details=event.details,
        )
        self.add_node(action)

        # Link agent → action (triggered)
        self.add_edge(TriggeredEdge(
            source=event.agent_id, target=action.id, timestamp=event.timestamp,
        ))

        # Handle different event types
        if event.event_type == EventType.FILE_ACCESS:
            self._handle_file_access(event, action)
        elif event.event_type == EventType.CODE_MODIFICATION:
            self._handle_code_modification(event, action)
        elif event.event_type == EventType.DEPENDENCY_ADDITION:
            self._handle_dependency_addition(event, action)
        elif event.event_type == EventType.CREDENTIAL_ACCESS:
            self._handle_credential_access(event, action)
        elif event.event_type == EventType.SECURITY_VIOLATION:
            self._handle_security_violation(event, action)
        elif event.event_type == EventType.TOOL_CALL:
            self._handle_tool_call(event, action)

        logger.info(
            "Ingested event %s: agent=%s type=%s target=%s",
            event.id, event.agent_id, event.event_type.value, event.target_file,
        )
        return action.id

    def _ensure_file_node(self, file_path: str, details: dict = None) -> str:
        """Ensure a CodeFile node exists for the path. Returns its ID."""
        # Check if we already have a node for this path
        for nid, data in self.graph.nodes(data=True):
            if data.get("node_type") == "CodeFile" and data.get("file_path") == file_path:
                return nid

        details = details or {}
        cat = FunctionCategory.GENERAL
        if is_test_file(file_path):
            cat = FunctionCategory.TEST
        elif is_auth_file(file_path):
            cat = FunctionCategory.AUTH

        node = CodeFileNode(
            file_path=file_path,
            function_category=details.get("function_category", cat.value),
            is_deployed=details.get("is_deployed", False),
            is_internet_facing=details.get("is_internet_facing", False),
            handles_pii=details.get("handles_pii", False),
            language=details.get("language", "python"),
        )
        # Override category if explicitly set in details
        if "function_category" in details:
            try:
                node.function_category = FunctionCategory(details["function_category"])
            except ValueError:
                pass
        self.add_node(node)
        return node.id

    def _handle_file_access(self, event: AgentEvent, action: ActionNode) -> None:
        file_id = self._ensure_file_node(event.target_file, event.details)
        self.add_edge(AccessedEdge(
            source=event.agent_id,
            target=file_id,
            timestamp=event.timestamp,
            access_type=event.details.get("access_type", "read"),
        ))

    def _handle_code_modification(self, event: AgentEvent, action: ActionNode) -> None:
        file_id = self._ensure_file_node(event.target_file, event.details)
        self.add_edge(ModifiedEdge(
            source=event.agent_id,
            target=file_id,
            timestamp=event.timestamp,
            change_summary=event.details.get("change_summary", ""),
        ))

    def _handle_dependency_addition(self, event: AgentEvent, action: ActionNode) -> None:
        dep_name = event.details.get("dependency_name", event.target_file)
        dep_source = event.details.get("source", "unknown")
        is_trusted = event.details.get("is_trusted", dep_source in ("pypi", "npm", "maven"))

        dep = DependencyNode(
            name=dep_name,
            version=event.details.get("version", "latest"),
            source=dep_source,
            is_trusted=is_trusted,
            introduced_by=event.agent_id,
        )
        self.add_node(dep)

        # If there's a target file, link file → depends_on → dep
        if event.target_file:
            file_id = self._ensure_file_node(event.target_file, event.details)
            self.add_edge(DependsOnEdge(
                source=file_id,
                target=dep.id,
                introduced_by=event.agent_id,
            ))

    def _handle_credential_access(self, event: AgentEvent, action: ActionNode) -> None:
        file_id = self._ensure_file_node(event.target_file, event.details)
        self.add_edge(AccessedEdge(
            source=event.agent_id,
            target=file_id,
            timestamp=event.timestamp,
            access_type="credential_read",
        ))

    def _handle_security_violation(self, event: AgentEvent, action: ActionNode) -> None:
        rule_id = event.details.get("rule_id", "unknown")
        # Ensure security rule node
        rule_node_id = f"rule_{rule_id}"
        if not self.has_node(rule_node_id):
            rule = SecurityRuleNode(
                id=rule_node_id,
                rule_id=rule_id,
                description=event.details.get("rule_description", ""),
                severity=event.details.get("severity", "HIGH"),
            )
            self.add_node(rule)

        self.add_edge(ViolatedEdge(
            source=event.agent_id,
            target=rule_node_id,
            rule_id=rule_id,
            severity=event.details.get("severity", "HIGH"),
        ))

    def _handle_tool_call(self, event: AgentEvent, action: ActionNode) -> None:
        if event.target_file:
            file_id = self._ensure_file_node(event.target_file, event.details)
            self.add_edge(AccessedEdge(
                source=event.agent_id,
                target=file_id,
                timestamp=event.timestamp,
                access_type="tool_call",
            ))

    # ── Vulnerability & runtime context linking ──────────────────

    def add_vulnerability(
        self, vuln: VulnerabilityNode, file_id: Optional[str] = None
    ) -> str:
        """Add a vulnerability node and optionally link it to a code file."""
        self.add_node(vuln)
        if file_id:
            self.add_edge(AffectsEdge(
                source=vuln.id, target=file_id, impact_scope="code",
            ))
        elif vuln.file_path:
            # Try to find the file node by path
            for nid, data in self.graph.nodes(data=True):
                if data.get("node_type") == "CodeFile" and data.get("file_path") == vuln.file_path:
                    self.add_edge(AffectsEdge(
                        source=vuln.id, target=nid, impact_scope="code",
                    ))
                    break
        return vuln.id

    def add_runtime_context(
        self, ctx: RuntimeContextNode, file_ids: Optional[list[str]] = None
    ) -> str:
        """Add runtime context and link to code files."""
        self.add_node(ctx)
        for fid in (file_ids or []):
            self.add_edge(AffectsEdge(
                source=ctx.id, target=fid, impact_scope="runtime",
            ))
        return ctx.id

    def link_vulnerability_to_context(
        self, vuln_id: str, ctx_id: str, exploitability: float = 0.0
    ) -> None:
        """Link a vulnerability to runtime context."""
        self.add_edge(ExploitsEdge(
            source=vuln_id, target=ctx_id, exploitability_score=exploitability,
        ))

    # ── Query methods ────────────────────────────────────────────

    def get_files_accessed_by_agent(
        self, agent_id: str, since: Optional[datetime] = None
    ) -> list[dict]:
        """
        Query: "Show me all files accessed by Agent X in the last hour"
        """
        if since is None:
            since = datetime.now(timezone.utc) - timedelta(hours=1)
        results = []
        for edge in self.get_edges(source=agent_id, edge_type="accessed"):
            ts = edge.get("timestamp")
            if ts and isinstance(ts, datetime) and ts >= since:
                target_data = self.get_node_data(edge["target"])
                if target_data and target_data.get("node_type") == "CodeFile":
                    results.append(target_data)
        # Also check 'modified' edges
        for edge in self.get_edges(source=agent_id, edge_type="modified"):
            ts = edge.get("timestamp")
            if ts and isinstance(ts, datetime) and ts >= since:
                target_data = self.get_node_data(edge["target"])
                if target_data and target_data.get("node_type") == "CodeFile":
                    if target_data not in results:
                        results.append(target_data)
        return results

    def get_agents_modifying_auth_code(self) -> list[dict]:
        """
        Query: "Which agents have modified authentication code?"
        """
        agents = set()
        for u, v, k, d in self.graph.edges(data=True, keys=True):
            if d.get("edge_type") != "modified":
                continue
            target = self.get_node_data(v)
            if target and target.get("function_category") in (
                "auth", FunctionCategory.AUTH, FunctionCategory.AUTH.value
            ):
                agent_data = self.get_node_data(u)
                if agent_data and agent_data.get("node_type") == "Agent":
                    agents.add(u)
        return [self.get_node_data(a) for a in agents if self.get_node_data(a)]

    def get_blast_radius(self, agent_id: str, max_depth: int = 3) -> dict:
        """
        Query: "What's the blast radius if Agent Y is compromised?"
        Returns all transitively reachable nodes from the agent.
        """
        if not self.has_node(agent_id):
            return {"agent_id": agent_id, "affected_nodes": [], "depth": 0}

        visited: set[str] = set()
        affected: list[dict] = []
        queue = [(agent_id, 0)]

        while queue:
            current, depth = queue.pop(0)
            if current in visited or depth > max_depth:
                continue
            visited.add(current)
            for successor in self.graph.successors(current):
                if successor not in visited:
                    data = self.get_node_data(successor)
                    if data:
                        affected.append({**data, "_depth": depth + 1})
                    queue.append((successor, depth + 1))

        return {
            "agent_id": agent_id,
            "affected_nodes": affected,
            "total_affected": len(affected),
            "depth": max_depth,
        }

    def get_dependencies_from_ai_code(self) -> list[dict]:
        """
        Query: "Find all dependencies introduced by AI-generated code"
        """
        deps = []
        for nid, data in self.graph.nodes(data=True):
            if data.get("node_type") == "Dependency" and data.get("introduced_by"):
                deps.append(data)
        return deps

    def get_production_vulnerabilities(self) -> list[dict]:
        """
        Query: "Which vulnerabilities are in production-deployed code paths?"
        """
        results = []
        for nid, data in self.graph.nodes(data=True):
            if data.get("node_type") != "Vulnerability":
                continue
            # Follow 'affects' edges to code files
            for _, target, _, edata in self.graph.edges(nid, data=True, keys=True):
                target_data = self.get_node_data(target)
                if target_data and target_data.get("is_deployed"):
                    results.append({**data, "deployed_file": target_data.get("file_path")})
                    break
            # Also check via runtime context
            for _, target, _, edata in self.graph.edges(nid, data=True, keys=True):
                target_data = self.get_node_data(target)
                if (
                    target_data
                    and target_data.get("node_type") == "RuntimeContext"
                    and target_data.get("is_deployed")
                ):
                    if data not in results:
                        results.append({**data, "runtime_context": target_data})
                    break
        return results

    def get_runtime_context_for_vulnerability(self, vuln_id: str) -> Optional[dict]:
        """
        Query: "What runtime context exists for this SQL injection finding?"
        """
        for _, target, _, edata in self.graph.edges(vuln_id, data=True, keys=True):
            target_data = self.get_node_data(target)
            if target_data and target_data.get("node_type") == "RuntimeContext":
                return target_data
        # If no direct link, try to find via affected code file
        for _, target, _, edata in self.graph.edges(vuln_id, data=True, keys=True):
            target_data = self.get_node_data(target)
            if target_data and target_data.get("node_type") == "CodeFile":
                # Find runtime context linked to this file
                for pre in self.graph.predecessors(target):
                    pre_data = self.get_node_data(pre)
                    if pre_data and pre_data.get("node_type") == "RuntimeContext":
                        return pre_data
        return None

    def get_runtime_context_for_file(self, file_path: str) -> Optional[dict]:
        """Get runtime context for a file by its path."""
        file_id = None
        for nid, data in self.graph.nodes(data=True):
            if data.get("node_type") == "CodeFile" and data.get("file_path") == file_path:
                file_id = nid
                break
        if not file_id:
            return None
        # Check predecessors (runtime context → affects → file)
        for pre in self.graph.predecessors(file_id):
            pre_data = self.get_node_data(pre)
            if pre_data and pre_data.get("node_type") == "RuntimeContext":
                return pre_data
        return None

    def get_code_file_by_path(self, file_path: str) -> Optional[dict]:
        """Get a code file node by its file path."""
        for nid, data in self.graph.nodes(data=True):
            if data.get("node_type") == "CodeFile" and data.get("file_path") == file_path:
                return data
        return None

    def get_agent_history(self, agent_id: str) -> list[dict]:
        """
        Get full action history of an agent. Used for behavioral baseline.
        """
        actions = []
        for _, target, _, edata in self.graph.edges(agent_id, data=True, keys=True):
            target_data = self.get_node_data(target)
            if target_data and target_data.get("node_type") == "Action":
                actions.append(target_data)
        actions.sort(key=lambda a: a.get("timestamp", ""))
        return actions

    def get_provenance(self, file_path: str) -> list[dict]:
        """
        Provenance: "Which agent modified this file? Why? When?"
        Returns list of modification events for the file.
        """
        file_id = None
        for nid, data in self.graph.nodes(data=True):
            if data.get("node_type") == "CodeFile" and data.get("file_path") == file_path:
                file_id = nid
                break
        if not file_id:
            return []

        provenance = []
        for pre in self.graph.predecessors(file_id):
            pre_data = self.get_node_data(pre)
            if pre_data and pre_data.get("node_type") == "Agent":
                # Get edges from agent to this file
                for u, v, k, edata in self.graph.edges(pre, data=True, keys=True):
                    if v == file_id and edata.get("edge_type") in ("modified", "accessed"):
                        provenance.append({
                            "agent_id": pre,
                            "agent_name": pre_data.get("name", pre),
                            "action": edata.get("edge_type"),
                            "timestamp": edata.get("timestamp"),
                            "change_summary": edata.get("change_summary", ""),
                        })
        provenance.sort(key=lambda p: str(p.get("timestamp", "")))
        return provenance

    # ── Statistics ───────────────────────────────────────────────

    def get_stats(self) -> dict:
        """Get graph statistics."""
        node_counts: dict[str, int] = {}
        for _, data in self.graph.nodes(data=True):
            nt = data.get("node_type", "unknown")
            node_counts[nt] = node_counts.get(nt, 0) + 1

        edge_counts: dict[str, int] = {}
        for _, _, _, data in self.graph.edges(data=True, keys=True):
            et = data.get("edge_type", "unknown")
            edge_counts[et] = edge_counts.get(et, 0) + 1

        return {
            "total_nodes": self.graph.number_of_nodes(),
            "total_edges": self.graph.number_of_edges(),
            "node_counts": node_counts,
            "edge_counts": edge_counts,
        }

    # ── Serialization ────────────────────────────────────────────

    def to_dict(self) -> dict:
        """Serialize graph to a JSON-compatible dict."""
        return nx.node_link_data(self.graph)

    @classmethod
    def from_dict(cls, data: dict) -> "ContextGraph":
        """Restore graph from serialized dict."""
        cg = cls()
        cg.graph = nx.node_link_graph(data, directed=True, multigraph=True)
        # Rebuild node index
        for nid, ndata in cg.graph.nodes(data=True):
            cg._node_index[nid] = ndata  # store raw dicts as fallback
        return cg
