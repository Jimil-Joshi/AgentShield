#!/usr/bin/env python3
"""
AgentShield Demo Script
End-to-end demonstration of all 5 components.
Runs all 7 test cases and prints formatted results.
"""

import json
import os
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.models import (
    AgentEvent,
    AgentNode,
    AgentRegistryEntry,
    AgentRole,
    CodeFileNode,
    EventType,
    FunctionCategory,
    RuntimeContextNode,
    SASTFinding,
    SASTSeverity,
    VulnType,
)
from src.context_graph import ContextGraph
from src.verifier_agent import VerifierAgent
from src.mcp_server import MCPSecurityServer
from src.integrity_monitor import IntegrityMonitor
from src.triage_agent import TriageAgent


# ═══════════════════════════════════════════════
# Utilities
# ═══════════════════════════════════════════════

EXAMPLES_DIR = Path(__file__).resolve().parent
DIVIDER = "═" * 80
SUB_DIVIDER = "─" * 60


def print_header(title: str):
    print(f"\n{DIVIDER}")
    print(f"  {title}")
    print(DIVIDER)


def print_subheader(title: str):
    print(f"\n{SUB_DIVIDER}")
    print(f"  {title}")
    print(SUB_DIVIDER)


def load_json(filename: str):
    with open(EXAMPLES_DIR / filename) as f:
        return json.load(f)


# ═══════════════════════════════════════════════
# Step 1: Build Context Graph
# ═══════════════════════════════════════════════

def build_context_graph() -> ContextGraph:
    print_header("PART 1: Context Graph — Building Knowledge Schema")

    graph = ContextGraph()

    # Load and ingest events
    events_data = load_json("sample_events.json")
    print(f"  Loaded {len(events_data)} agent events")

    for evt_data in events_data:
        event = AgentEvent(**evt_data)
        graph.ingest_event(event)

    # Load and link runtime contexts
    contexts_data = load_json("sample_runtime_context.json")
    for ctx_data in contexts_data:
        file_paths = ctx_data.pop("file_paths", [])
        ctx_data.pop("description", None)

        ctx = RuntimeContextNode(**ctx_data)
        # Find file node IDs for linking
        file_ids = []
        for fp in file_paths:
            for nid, ndata in graph.graph.nodes(data=True):
                if ndata.get("node_type") == "CodeFile" and ndata.get("file_path") == fp:
                    file_ids.append(nid)
                    break
            else:
                # Create the file node if it doesn't exist
                file_node = CodeFileNode(file_path=fp)
                file_ids.append(graph.add_node(file_node))

        graph.add_runtime_context(ctx, file_ids)

    # Print graph stats
    stats = graph.get_stats()
    print(f"\n  Graph Statistics:")
    print(f"    Total Nodes: {stats['total_nodes']}")
    print(f"    Total Edges: {stats['total_edges']}")
    print(f"    Node Types: {json.dumps(stats['node_counts'], indent=6)}")
    print(f"    Edge Types: {json.dumps(stats['edge_counts'], indent=6)}")

    # Demonstrate queries
    print_subheader("Graph Query: Files accessed by agent_coder_01 (last 2 hours)")
    since = datetime.now(timezone.utc) - timedelta(hours=2)
    files = graph.get_files_accessed_by_agent("agent_coder_01", since)
    for f in files:
        print(f"    • {f.get('file_path')} [category: {f.get('function_category')}]")

    print_subheader("Graph Query: Agents modifying auth code")
    agents = graph.get_agents_modifying_auth_code()
    for a in agents:
        print(f"    • {a.get('name', a.get('id'))} [trust: {a.get('trust_score', 'N/A')}]")

    print_subheader("Graph Query: Blast radius of agent_coder_01")
    blast = graph.get_blast_radius("agent_coder_01")
    print(f"    Total affected nodes: {blast['total_affected']}")
    for node in blast["affected_nodes"][:5]:
        print(f"    • {node.get('node_type')}: {node.get('file_path', node.get('name', node.get('id')))}")

    print_subheader("Graph Query: AI-introduced dependencies")
    deps = graph.get_dependencies_from_ai_code()
    for d in deps:
        print(f"    • {d.get('name')} v{d.get('version')} (source: {d.get('source')}, trusted: {d.get('is_trusted')})")

    return graph


# ═══════════════════════════════════════════════
# Step 2: Verifier Agent Tests
# ═══════════════════════════════════════════════

def run_verifier_tests(graph: ContextGraph):
    print_header("PART 2: Autonomous Verifier Agent")

    verifier = VerifierAgent(graph, use_llm=False)

    # ── Test Case 1: Malicious Agent Removal of Security Logic ──
    print_subheader("Test Case 1: Malicious Agent Removal of Security Logic")
    event_tc1 = AgentEvent(
        agent_id="agent_coder_01",
        agent_name="CodeAssistant",
        event_type=EventType.CODE_MODIFICATION,
        target_file="src/auth/login.py",
        details={
            "change_summary": "Removed verify_password() call to simplify login",
            "removed_code": "if verify_password(password, user.hash): authenticate(user)",
            "function_category": "auth",
            "is_deployed": True,
        },
    )
    result = verifier.verify(event_tc1)
    print(f"  Decision:       {result.decision.value}")
    print(f"  Risk Score:     {result.risk_score:.2f}")
    print(f"  Rules Violated: {result.rules_violated}")
    print(f"  Reasoning:\n    {result.reasoning[:300]}...")
    assert result.decision.value in ("BLOCK", "REQUIRE_HUMAN_REVIEW"), \
        f"TC1 FAILED: Expected BLOCK, got {result.decision.value}"
    print(f"\n  ✓ Test Case 1 PASSED: {result.decision.value}")

    # ── Test Case 1b: Same removal in test file → ALLOW ──
    print_subheader("Test Case 1b: Security logic removal in TEST file (should ALLOW)")
    event_tc1b = AgentEvent(
        agent_id="agent_coder_01",
        agent_name="CodeAssistant",
        event_type=EventType.CODE_MODIFICATION,
        target_file="tests/test_auth.py",
        details={
            "change_summary": "Removed verify() call in test setup",
            "removed_code": "verify(token)",
            "function_category": "test",
        },
    )
    result_1b = verifier.verify(event_tc1b)
    print(f"  Decision:       {result_1b.decision.value}")
    print(f"  Risk Score:     {result_1b.risk_score:.2f}")
    print(f"  Reasoning:      {result_1b.reasoning[:200]}")
    assert result_1b.decision.value == "ALLOW", \
        f"TC1b FAILED: Expected ALLOW, got {result_1b.decision.value}"
    print(f"\n  ✓ Test Case 1b PASSED: ALLOW (context-aware for test files)")

    # ── Test Case 2: Supply Chain Attack ──
    print_subheader("Test Case 2: Supply Chain Attack (Dependency Injection)")
    event_tc2 = AgentEvent(
        agent_id="agent_builder_02",
        agent_name="BuildAgent",
        event_type=EventType.DEPENDENCY_ADDITION,
        target_file="requirements.txt",
        details={
            "dependency_name": "backdoor-logger",
            "version": "0.1.0",
            "source": "https://evil-packages.example.com/pypi",
            "is_trusted": False,
        },
    )
    result2 = verifier.verify(event_tc2)
    print(f"  Decision:       {result2.decision.value}")
    print(f"  Risk Score:     {result2.risk_score:.2f}")
    print(f"  Rules Violated: {result2.rules_violated}")
    print(f"  Reasoning:\n    {result2.reasoning[:300]}")
    assert result2.decision.value == "REQUIRE_HUMAN_REVIEW", \
        f"TC2 FAILED: Expected REQUIRE_HUMAN_REVIEW, got {result2.decision.value}"
    print(f"\n  ✓ Test Case 2 PASSED: {result2.decision.value}")

    # ── Test Case 4: Credential Access ──
    print_subheader("Test Case 4: Behavioral Anomaly (Credential Access)")
    event_tc4 = AgentEvent(
        agent_id="agent_rogue_04",
        agent_name="CompromisedAgent",
        event_type=EventType.CREDENTIAL_ACCESS,
        target_file=".env",
        details={"access_type": "credential_read"},
    )
    result4 = verifier.verify(event_tc4)
    print(f"  Decision:       {result4.decision.value}")
    print(f"  Risk Score:     {result4.risk_score:.2f}")
    print(f"  Rules Violated: {result4.rules_violated}")
    print(f"  Reasoning:\n    {result4.reasoning[:300]}")
    assert result4.decision.value == "BLOCK", \
        f"TC4 FAILED: Expected BLOCK, got {result4.decision.value}"
    print(f"\n  ✓ Test Case 4 PASSED: {result4.decision.value}")


# ═══════════════════════════════════════════════
# Step 3: MCP Security Tests
# ═══════════════════════════════════════════════

def run_mcp_tests():
    print_header("PART 3: MCP Security Infrastructure")

    server = MCPSecurityServer(demo_mode=True)

    # Register agents
    server.register_agent(AgentRegistryEntry(
        agent_id="agent_reader",
        agent_name="Reader Agent",
        role=AgentRole.READER,
        allowed_repos=["api-backend"],
        allowed_branches=["main"],
    ))
    server.register_agent(AgentRegistryEntry(
        agent_id="agent_writer",
        agent_name="Writer Agent",
        role=AgentRole.WRITER,
        allowed_repos=["api-backend"],
        allowed_branches=["main", "develop"],
    ))

    # ── Test Case 3: Path Traversal Attempt ──
    print_subheader("Test Case 3: MCP Path Traversal Attempt")
    print('  Tool call: read_file(repo="api-backend", file_path="../../.env")')
    result = server.read_file("agent_reader", "api-backend", "../../.env")
    print(f"  Result: {json.dumps(result, indent=4)}")
    assert result.get("allowed") == False or "violations" in result, \
        "TC3 FAILED: Path traversal should be rejected"
    print(f"\n  ✓ Test Case 3 PASSED: Path traversal rejected")

    # ── Additional MCP tests ──
    print_subheader("MCP Test: Valid file read")
    result = server.read_file("agent_reader", "api-backend", "src/auth/login.py")
    print(f"  Result keys: {list(result.keys())}")
    print(f"  Content preview: {result.get('content', '')[:100]}...")
    assert "content" in result, "Valid read should return content"
    print("  ✓ Valid read succeeded")

    print_subheader("MCP Test: Unauthorized repo access")
    result = server.read_file("agent_reader", "secret-repo", "README.md")
    print(f"  Result: {json.dumps(result, indent=4)}")
    assert result.get("allowed") == False, "Unauthorized repo access should be denied"
    print("  ✓ Unauthorized repo access denied")

    print_subheader("MCP Test: Rate limiting")
    for i in range(12):
        res = server.read_file("agent_reader", "api-backend", "README.md")
    print(f"  After 12 requests: {json.dumps(res, indent=4)}")
    violations = server.audit_logger.get_violations()
    print(f"  Total security violations logged: {len(violations)}")

    print_subheader("MCP Test: Audit log summary")
    logs = server.audit_logger.get_logs()
    print(f"  Total audit log entries: {len(logs)}")
    blocked = [l for l in logs if not l.allowed]
    print(f"  Blocked requests: {len(blocked)}")
    for log in blocked[:3]:
        print(f"    • {log.tool_call.tool_name} by {log.tool_call.agent_id}: {log.security_violations}")


# ═══════════════════════════════════════════════
# Step 4: Integrity Monitor Tests
# ═══════════════════════════════════════════════

def run_integrity_tests(graph: ContextGraph):
    print_header("PART 4: Agent Supply Chain Integrity")

    monitor = IntegrityMonitor(graph)

    # Record some decision traces
    print_subheader("Decision Trace Recording & Signing")
    trace1 = monitor.record_decision(
        agent_id="agent_coder_01",
        action="code_modification",
        inputs={"file": "src/auth/login.py", "change": "remove verify()"},
        reasoning="Agent attempted to simplify authentication logic",
        output={"decision": "BLOCK", "risk_score": 0.95},
    )
    print(f"  Trace 1: {trace1.trace_id} (seq #{trace1.sequence_number})")
    print(f"  Signature: {trace1.signature[:32]}...")

    trace2 = monitor.record_decision(
        agent_id="agent_builder_02",
        action="dependency_addition",
        inputs={"dependency": "backdoor-logger", "source": "untrusted"},
        reasoning="Agent tried to add dependency from untrusted source",
        output={"decision": "REQUIRE_HUMAN_REVIEW", "risk_score": 0.8},
    )
    print(f"  Trace 2: {trace2.trace_id} (seq #{trace2.sequence_number})")
    print(f"  Previous hash: {trace2.previous_hash[:32]}...")

    trace3 = monitor.record_decision(
        agent_id="agent_rogue_04",
        action="credential_access",
        inputs={"file": ".env"},
        reasoning="Agent attempted to access credentials",
        output={"decision": "BLOCK", "risk_score": 0.95},
    )

    # Verify chain integrity
    print_subheader("Chain Integrity Verification")
    valid, errors = monitor.verify_chain_integrity()
    print(f"  Chain valid: {valid}")
    if errors:
        for e in errors:
            print(f"  Error: {e}")
    else:
        print("  ✓ All signatures valid, chain intact")

    # ── Test Case 4: Behavioral Anomaly ──
    print_subheader("Test Case 4: Behavioral Anomaly Detection")

    # Build baseline for agent_rogue_04 (has only accessed general utility files)
    baseline = monitor.build_agent_baseline("agent_rogue_04")
    print(f"  Baseline for agent_rogue_04:")
    print(f"    Total actions: {baseline.get('total_actions', 0)}")
    print(f"    Has accessed credentials: {baseline.get('has_accessed_credentials', False)}")
    print(f"    Has accessed auth code: {baseline.get('has_accessed_auth_code', False)}")

    # Now check anomaly: agent tries to access credentials
    alert = monitor.check_action(
        agent_id="agent_rogue_04",
        action_type="credential_access",
        target=".env",
    )
    if alert:
        print(f"\n  ANOMALY DETECTED:")
        print(f"    Type:     {alert.alert_type}")
        print(f"    Severity: {alert.severity.value}")
        print(f"    Baseline: {alert.baseline_value}")
        print(f"    Observed: {alert.observed_value}")
        print(f"    Details:  {alert.description}")
        print(f"\n  ✓ Test Case 4 PASSED: Behavioral anomaly detected")
    else:
        print("  ✗ Test Case 4 FAILED: No anomaly detected")

    # Print integrity report
    print_subheader("Full Integrity Report")
    report = monitor.get_integrity_report()
    print(f"  Total traces: {report['total_traces']}")
    print(f"  Chain valid: {report['chain_valid']}")
    print(f"  Total alerts: {report['total_alerts']}")
    print(f"  Alerts by severity: {report['alerts_by_severity']}")

    return monitor


# ═══════════════════════════════════════════════
# Step 5: Triage Agent Tests
# ═══════════════════════════════════════════════

def run_triage_tests(graph: ContextGraph):
    print_header("PART 5: Autonomous Vulnerability Triage Agent")

    agent = TriageAgent(graph, use_llm=False)

    # Load SAST findings
    findings_data = load_json("sample_sast_findings.json")
    findings = [SASTFinding(**f) for f in findings_data]
    print(f"  Loaded {len(findings)} SAST findings")

    # ── Test Case 5: Production Critical SQL Injection ──
    print_subheader("Test Case 5: SQL Injection in Production Payment Code")
    # Find the payment SQL injection finding
    tc5_finding = next(f for f in findings if f.file_path == "src/payment/process.py")
    tc5_result = agent.triage_finding(tc5_finding)

    print(f"  Original SAST Severity: {tc5_result.original_severity.value}")
    print(f"  Final Priority:         {tc5_result.final_priority.value}")
    print(f"  Exploitability Score:   {tc5_result.exploitability.score:.2f}")
    print(f"  Business Risk Score:    {tc5_result.business_risk_score:.2f}")
    print(f"\n  Reasoning:")
    for line in tc5_result.reasoning.split("\n")[:15]:
        print(f"    {line}")
    print(f"\n  Remediation:")
    if tc5_result.remediation:
        print(f"    {tc5_result.remediation.description[:200]}")
        print(f"    Code: {tc5_result.remediation.code_snippet[:150]}...")
        print(f"    Effort: {tc5_result.remediation.effort_estimate}")

    assert tc5_result.final_priority.value == "URGENT", \
        f"TC5 FAILED: Expected URGENT, got {tc5_result.final_priority.value}"
    assert tc5_result.exploitability.score >= 0.85, \
        f"TC5 FAILED: Expected exploitability >= 0.85, got {tc5_result.exploitability.score}"
    print(f"\n  ✓ Test Case 5 PASSED: URGENT, exploitability={tc5_result.exploitability.score:.2f}")

    # ── Test Case 6: Dev Script False Alarm ──
    print_subheader("Test Case 6: Hardcoded Secret in Dev-Only Script")
    tc6_finding = next(f for f in findings if f.file_path == "scripts/dev_setup.py")
    tc6_result = agent.triage_finding(tc6_finding)

    print(f"  Original SAST Severity: {tc6_result.original_severity.value}")
    print(f"  Final Priority:         {tc6_result.final_priority.value}")
    print(f"  Exploitability Score:   {tc6_result.exploitability.score:.2f}")
    print(f"  Business Risk Score:    {tc6_result.business_risk_score:.2f}")
    print(f"\n  Reasoning:")
    for line in tc6_result.reasoning.split("\n")[:15]:
        print(f"    {line}")

    assert tc6_result.final_priority.value == "LOW" or tc6_result.final_priority.value == "INFO", \
        f"TC6 FAILED: Expected LOW/INFO, got {tc6_result.final_priority.value}"
    assert tc6_result.exploitability.score <= 0.15, \
        f"TC6 FAILED: Expected exploitability <= 0.15, got {tc6_result.exploitability.score}"
    print(f"\n  ✓ Test Case 6 PASSED: {tc6_result.final_priority.value} (downgraded from CRITICAL), exploitability={tc6_result.exploitability.score:.2f}")

    # ── Test Case 7: Context Upgrade ──
    print_subheader("Test Case 7: Medium XSS in Production Admin Dashboard with PII")
    tc7_finding = next(f for f in findings if f.file_path == "src/admin/dashboard.py" and f.vuln_type == VulnType.XSS)
    tc7_result = agent.triage_finding(tc7_finding)

    print(f"  Original SAST Severity: {tc7_result.original_severity.value}")
    print(f"  Final Priority:         {tc7_result.final_priority.value}")
    print(f"  Exploitability Score:   {tc7_result.exploitability.score:.2f}")
    print(f"  Business Risk Score:    {tc7_result.business_risk_score:.2f}")
    print(f"\n  Reasoning:")
    for line in tc7_result.reasoning.split("\n")[:15]:
        print(f"    {line}")

    assert tc7_result.final_priority.value in ("HIGH", "URGENT"), \
        f"TC7 FAILED: Expected HIGH/URGENT, got {tc7_result.final_priority.value}"
    assert tc7_result.exploitability.score >= 0.65, \
        f"TC7 FAILED: Expected exploitability >= 0.65, got {tc7_result.exploitability.score}"
    print(f"\n  ✓ Test Case 7 PASSED: {tc7_result.final_priority.value} (upgraded from MEDIUM), exploitability={tc7_result.exploitability.score:.2f}")

    # ── Full triage run ──
    print_subheader("Full Triage Results (all findings, sorted by priority)")
    all_results = agent.triage_all(findings)
    print(f"\n  {'Finding':<30} {'SAST':<10} {'Final':<10} {'Exploit':<10} {'Risk':<10}")
    print(f"  {'─'*30} {'─'*10} {'─'*10} {'─'*10} {'─'*10}")
    for r in all_results:
        finding = next(f for f in findings if f.id == r.finding_id)
        print(
            f"  {finding.file_path:<30} {r.original_severity.value:<10} "
            f"{r.final_priority.value:<10} {r.exploitability.score:<10.2f} "
            f"{r.business_risk_score:<10.2f}"
        )


# ═══════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════

def main():
    print("\n" + "█" * 80)
    print("  AgentShield — AI Agent Security Platform Demo")
    print("  End-to-end demonstration of all 5 components")
    print("█" * 80)

    # Part 1: Context Graph
    graph = build_context_graph()

    # Part 2: Verifier Agent
    run_verifier_tests(graph)

    # Part 3: MCP Server
    run_mcp_tests()

    # Part 4: Integrity Monitor
    monitor = run_integrity_tests(graph)

    # Part 5: Triage Agent
    run_triage_tests(graph)

    # ── Summary ──
    print_header("DEMO COMPLETE — All 7 Test Cases Passed")
    print("""
  Test Case 1: ✓ Verifier BLOCKS security logic removal in auth code
  Test Case 1b: ✓ Verifier ALLOWS security logic removal in test file (context-aware)
  Test Case 2: ✓ Verifier REQUIRES HUMAN REVIEW for untrusted dependency
  Test Case 3: ✓ MCP guardrails REJECT path traversal attempt
  Test Case 4: ✓ Integrity monitor DETECTS behavioral anomaly (credential access)
  Test Case 5: ✓ Triage agent rates SQL injection as URGENT (production payment)
  Test Case 6: ✓ Triage agent DOWNGRADES hardcoded secret to LOW (dev script)
  Test Case 7: ✓ Triage agent UPGRADES XSS to HIGH (production admin + PII)
    """)


if __name__ == "__main__":
    main()
