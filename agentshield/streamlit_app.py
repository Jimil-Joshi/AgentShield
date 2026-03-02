"""
AgentShield Security Dashboard — Streamlit App
An interactive demo dashboard showcasing all 5 parts of the AgentShield platform.
Run with: streamlit run streamlit_app.py
"""

import sys
import json
import time
from pathlib import Path
from datetime import datetime, timezone, timedelta

import streamlit as st

# Ensure src is importable
sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.models import (
    AgentEvent,
    AgentNode,
    AgentRegistryEntry,
    AgentRole,
    CodeFileNode,
    DependencyNode,
    EventType,
    FunctionCategory,
    RuntimeContextNode,
    SASTFinding,
    SASTSeverity,
    VulnType,
    VerificationDecision,
    TriagePriority,
    AnomalySeverity,
)
from src.context_graph import ContextGraph
from src.verifier_agent import VerifierAgent
from src.mcp_server import MCPSecurityServer, PathValidator, RateLimiter
from src.integrity_monitor import IntegrityMonitor
from src.triage_agent import TriageAgent


# ─── Page Config ─────────────────────────────────────────────────────

st.set_page_config(
    page_title="AgentShield — AI Agent Security Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Custom CSS ──────────────────────────────────────────────────────

st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: 700;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-align: center;
        padding: 1rem 0;
    }
    .sub-header {
        text-align: center;
        color: #6c757d;
        font-size: 1.1rem;
        margin-bottom: 2rem;
    }
    .metric-card {
        background: linear-gradient(135deg, #f5f7fa 0%, #c3cfe2 100%);
        border-radius: 12px;
        padding: 1.2rem;
        text-align: center;
        box-shadow: 0 2px 8px rgba(0,0,0,0.06);
    }
    .status-badge-pass { color: #28a745; font-weight: bold; }
    .status-badge-fail { color: #dc3545; font-weight: bold; }
    .status-badge-warn { color: #ffc107; font-weight: bold; }
    .stTabs [data-baseweb="tab-list"] {
        gap: 8px;
    }
    .stTabs [data-baseweb="tab"] {
        border-radius: 8px;
        padding: 8px 20px;
    }
</style>
""", unsafe_allow_html=True)


# ─── Session State Setup ────────────────────────────────────────────

def init_session_state():
    """Initialize all demo components in session state."""
    if "initialized" in st.session_state:
        return

    # Build the Context Graph
    graph = ContextGraph()

    # Add agents
    graph.add_node(AgentNode(id="agent_codegen", name="CodeGen Agent", trust_score=0.7))
    graph.add_node(AgentNode(id="agent_reviewer", name="Security Reviewer", trust_score=0.9))
    graph.add_node(AgentNode(id="agent_low_trust", name="Low-Trust Bot", trust_score=0.2))

    # Add code files
    graph.add_node(CodeFileNode(
        id="file_auth", file_path="src/auth/controller.py",
        function_category=FunctionCategory.AUTH,
        contains_security_logic=True, is_deployed=True, is_internet_facing=True,
    ))
    graph.add_node(CodeFileNode(
        id="file_payment", file_path="src/payment/process.py",
        function_category=FunctionCategory.PAYMENT,
        is_deployed=True, is_internet_facing=True, handles_pii=True,
    ))
    graph.add_node(CodeFileNode(
        id="file_admin", file_path="src/admin/panel.py",
        function_category=FunctionCategory.ADMIN,
        is_deployed=True, is_internet_facing=True,
    ))
    graph.add_node(CodeFileNode(
        id="file_test", file_path="tests/test_auth.py",
        function_category=FunctionCategory.TEST,
        contains_security_logic=True,
    ))
    graph.add_node(CodeFileNode(
        id="file_dev", file_path="scripts/dev_setup.py",
        function_category=FunctionCategory.DEV_SCRIPT,
    ))
    graph.add_node(CodeFileNode(
        id="file_config", file_path="config/.env.production",
        is_credential_file=True, is_deployed=True,
    ))

    # Add runtime contexts
    graph.add_runtime_context(RuntimeContextNode(
        id="ctx_prod", environment="production",
        is_deployed=True, is_internet_facing=True, handles_pii=True,
    ), ["file_auth", "file_payment"])
    graph.add_runtime_context(RuntimeContextNode(
        id="ctx_admin", environment="production",
        is_deployed=True, is_internet_facing=True,
        recently_modified_by_ai=True,
    ), ["file_admin"])
    graph.add_runtime_context(RuntimeContextNode(
        id="ctx_dev", environment="development",
        is_deployed=False, is_internet_facing=False,
    ), ["file_dev", "file_test"])

    # Add some agent history events
    events = [
        AgentEvent(agent_id="agent_codegen", agent_name="CodeGen Agent",
                   event_type=EventType.FILE_ACCESS, target_file="src/auth/controller.py"),
        AgentEvent(agent_id="agent_codegen", agent_name="CodeGen Agent",
                   event_type=EventType.CODE_MODIFICATION, target_file="src/payment/process.py",
                   details={"change_summary": "Updated payment flow", "function_category": "payment"}),
        AgentEvent(agent_id="agent_reviewer", agent_name="Security Reviewer",
                   event_type=EventType.FILE_ACCESS, target_file="src/auth/controller.py"),
        AgentEvent(agent_id="agent_low_trust", agent_name="Low-Trust Bot",
                   event_type=EventType.FILE_ACCESS, target_file="src/admin/panel.py"),
    ]
    for e in events:
        graph.ingest_event(e)

    st.session_state.graph = graph
    st.session_state.verifier = VerifierAgent(context_graph=graph)
    st.session_state.mcp_server = MCPSecurityServer(demo_mode=True)
    st.session_state.mcp_server.register_agent(AgentRegistryEntry(
        agent_id="demo_agent", agent_name="Demo Agent",
        role=AgentRole.READER, allowed_repos=["api-backend"], allowed_branches=["main"],
    ))
    st.session_state.integrity = IntegrityMonitor(context_graph=graph)
    st.session_state.triage = TriageAgent(context_graph=graph)
    st.session_state.test_results = []
    st.session_state.initialized = True


init_session_state()


# ─── Header ─────────────────────────────────────────────────────────

st.markdown('<div class="main-header">🛡️ AgentShield</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">AI Agent Security Platform — Interactive Demo Dashboard</div>', unsafe_allow_html=True)

# ─── Sidebar ────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("## 🧭 Navigation")
    st.markdown("Use the tabs below to explore each component of the AgentShield platform.")
    st.divider()
    st.markdown("### Architecture")
    st.markdown("""
    **5 Core Components:**
    1. 📊 Context Graph
    2. 🔍 Verifier Agent
    3. 🔒 MCP Security
    4. 🔗 Integrity Monitor
    5. 🎯 Triage Agent
    """)
    st.divider()
    st.markdown("### Tech Stack")
    st.markdown("""
    - **Graph**: NetworkX MultiDiGraph
    - **Agents**: LangGraph StateGraph
    - **LLM**: Claude 3.5 Sonnet (Bedrock)
    - **MCP**: Official mcp SDK
    - **Signing**: HMAC-SHA256
    - **Models**: Pydantic v2
    """)
    st.divider()
    if st.button("🔄 Reset Demo State", use_container_width=True):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()


# ─── Tabs ────────────────────────────────────────────────────────────

tab_overview, tab_graph, tab_verifier, tab_mcp, tab_integrity, tab_triage, tab_tests = st.tabs([
    "📋 Overview",
    "📊 Context Graph",
    "🔍 Verifier Agent",
    "🔒 MCP Security",
    "🔗 Integrity Monitor",
    "🎯 Triage Agent",
    "✅ Test Cases",
])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TAB: Overview
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

with tab_overview:
    st.markdown("## Platform Overview")

    col1, col2, col3, col4, col5 = st.columns(5)
    graph_stats = st.session_state.graph.get_stats()

    with col1:
        st.metric("Graph Nodes", graph_stats["total_nodes"])
    with col2:
        st.metric("Graph Edges", graph_stats["total_edges"])
    with col3:
        n_agents = graph_stats["node_counts"].get("Agent", 0)
        st.metric("Agents Tracked", n_agents)
    with col4:
        n_files = graph_stats["node_counts"].get("CodeFile", 0)
        st.metric("Code Files", n_files)
    with col5:
        st.metric("Verification Rules", 5)

    st.divider()

    st.markdown("""
    ### How AgentShield Works

    ```
    ┌─────────────┐    ┌───────────────┐    ┌─────────────────┐
    │ AI Agent     │───>│ Context Graph │───>│ Verifier Agent  │
    │ (any action) │    │ (knowledge)   │    │ (5 rules)       │
    └─────────────┘    └───────────────┘    └────────┬────────┘
                                                      │
         ┌────────────────────────────────────────────┘
         │
    ┌────▼──────────┐    ┌─────────────────┐    ┌───────────────┐
    │ MCP Security  │    │ Integrity       │    │ Triage Agent  │
    │ (guardrails)  │    │ (HMAC chains)   │    │ (SAST → Prio) │
    └───────────────┘    └─────────────────┘    └───────────────┘
    ```
    """)

    st.markdown("""
    ### 7 Test Cases Covered

    | # | Scenario | Expected Result |
    |---|----------|-----------------|
    | 1 | Agent deletes auth validation | **BLOCK** |
    | 1b | Same change in test file | **ALLOW** |
    | 2 | Untrusted dependency addition | **REQUIRE_HUMAN_REVIEW** |
    | 3 | Path traversal attack | **BLOCKED** |
    | 4 | Behavioral anomaly detection | **ALERT** |
    | 5 | SQL injection in prod payment | **URGENT** (exploit ≥ 0.90) |
    | 6 | Hardcoded secret in dev script | **LOW** (exploit ≤ 0.10) |
    | 7 | Medium XSS upgraded via context | **HIGH** (upgraded from MEDIUM) |
    """)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TAB: Context Graph
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

with tab_graph:
    st.markdown("## 📊 Part 1: Context Graph")
    st.markdown("Knowledge graph tracking all AI agent interactions with code, dependencies, and runtime context.")

    stats = st.session_state.graph.get_stats()

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("### Node Types")
        for ntype, count in stats["node_counts"].items():
            st.markdown(f"- **{ntype}**: {count}")
    with col2:
        st.markdown("### Edge Types")
        for etype, count in stats["edge_counts"].items():
            st.markdown(f"- **{etype}**: {count}")
    with col3:
        st.markdown("### Summary")
        st.metric("Total Nodes", stats["total_nodes"])
        st.metric("Total Edges", stats["total_edges"])

    st.divider()

    # Interactive queries
    st.markdown("### 🔎 Query the Graph")
    query_type = st.selectbox("Select Query", [
        "Files accessed by an agent",
        "Agents modifying auth code",
        "Blast radius of an agent",
        "Dependencies from AI code",
        "Production vulnerabilities",
    ])

    if query_type == "Files accessed by an agent":
        agent_id = st.text_input("Agent ID", "agent_codegen")
        if st.button("Run Query", key="q1"):
            since = datetime.now(timezone.utc) - timedelta(hours=24)
            files = st.session_state.graph.get_files_accessed_by_agent(agent_id, since)
            if files:
                st.json(files)
            else:
                st.info("No files found for this agent.")

    elif query_type == "Agents modifying auth code":
        if st.button("Run Query", key="q2"):
            agents = st.session_state.graph.get_agents_modifying_auth_code()
            if agents:
                st.json(agents)
            else:
                st.info("No agents modifying auth code.")

    elif query_type == "Blast radius of an agent":
        agent_id = st.text_input("Agent ID", "agent_codegen", key="blast_agent")
        if st.button("Run Query", key="q3"):
            blast = st.session_state.graph.get_blast_radius(agent_id)
            st.json(blast)

    elif query_type == "Dependencies from AI code":
        if st.button("Run Query", key="q4"):
            deps = st.session_state.graph.get_dependencies_from_ai_code()
            if deps:
                st.json(deps)
            else:
                st.info("No AI-introduced dependencies found. Try ingesting a DEPENDENCY_ADDITION event.")

    elif query_type == "Production vulnerabilities":
        if st.button("Run Query", key="q5"):
            vulns = st.session_state.graph.get_production_vulnerabilities()
            if vulns:
                st.json(vulns)
            else:
                st.info("No production vulnerabilities found.")

    st.divider()

    # Event ingestion
    st.markdown("### ➕ Ingest a New Event")
    with st.form("event_form"):
        ecol1, ecol2 = st.columns(2)
        with ecol1:
            ev_agent = st.text_input("Agent ID", "agent_codegen")
            ev_type = st.selectbox("Event Type", [e.value for e in EventType])
        with ecol2:
            ev_target = st.text_input("Target File", "src/main.py")
            ev_summary = st.text_input("Change Summary (optional)", "")

        if st.form_submit_button("Ingest Event"):
            details = {}
            if ev_summary:
                details["change_summary"] = ev_summary
            event = AgentEvent(
                agent_id=ev_agent, agent_name=ev_agent,
                event_type=EventType(ev_type),
                target_file=ev_target, details=details,
            )
            action_id = st.session_state.graph.ingest_event(event)
            st.success(f"Event ingested! Action node: `{action_id}`")
            st.rerun()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TAB: Verifier Agent
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

with tab_verifier:
    st.markdown("## 🔍 Part 2: Autonomous Verifier Agent")
    st.markdown("Real-time verification of agent actions against 5 security rules.")

    st.markdown("""
    | Rule | Description | Decision |
    |------|-------------|----------|
    | RULE-001 | No security logic removal in production | BLOCK |
    | RULE-002 | Untrusted dependencies need approval | REQUIRE_HUMAN_REVIEW |
    | RULE-003 | Auth code changes need human review | REQUIRE_HUMAN_REVIEW |
    | RULE-004 | No credential file access | BLOCK |
    | RULE-005 | PII-handling code needs data flow review | WARN |
    """)

    st.divider()

    st.markdown("### 🧪 Test Verification Scenarios")

    scenario = st.selectbox("Choose a scenario:", [
        "TC1: Agent deletes auth validation → BLOCK",
        "TC1b: Same change in test file → ALLOW",
        "TC2: Untrusted dependency → REQUIRE_HUMAN_REVIEW",
        "TC4: Low-trust agent reads credentials → BLOCK",
        "Custom event",
    ])

    def run_verification(event):
        verifier = st.session_state.verifier
        start = time.time()
        result = verifier.verify(event)
        elapsed = (time.time() - start) * 1000

        # Display decision
        decision_colors = {
            VerificationDecision.BLOCK: "🔴",
            VerificationDecision.REQUIRE_HUMAN_REVIEW: "🟡",
            VerificationDecision.WARN: "🟠",
            VerificationDecision.ALLOW: "🟢",
        }
        icon = decision_colors.get(result.decision, "⚪")

        st.markdown(f"### {icon} Decision: **{result.decision.value}**")
        st.markdown(f"**Risk Score:** {result.risk_score:.2f}")
        st.markdown(f"**Confidence:** {result.confidence:.0%}")
        st.markdown(f"**Time:** {elapsed:.1f}ms")

        if result.rules_violated:
            st.error(f"Rules violated: {', '.join(result.rules_violated)}")
        else:
            st.success("No rules violated")

        with st.expander("Full Reasoning"):
            st.text(result.reasoning)

        with st.expander("Context Used"):
            st.json(result.context_used)

        return result

    if scenario.startswith("TC1:"):
        event = AgentEvent(
            agent_id="agent_codegen", agent_name="CodeGen Agent",
            event_type=EventType.CODE_MODIFICATION,
            target_file="src/auth/controller.py",
            details={
                "change_summary": "Removed authentication validation check for simplification",
                "lines_removed": 15, "lines_added": 2,
            },
        )
        st.code(f"Agent: {event.agent_id}\nAction: {event.event_type.value}\nTarget: {event.target_file}\nChange: {event.details.get('change_summary')}", language="text")
        if st.button("▶ Run Verification", key="v1"):
            run_verification(event)

    elif scenario.startswith("TC1b"):
        event = AgentEvent(
            agent_id="agent_codegen", agent_name="CodeGen Agent",
            event_type=EventType.CODE_MODIFICATION,
            target_file="tests/test_auth.py",
            details={
                "change_summary": "Removed authentication check from test helper",
                "lines_removed": 10, "lines_added": 2,
            },
        )
        st.code(f"Agent: {event.agent_id}\nAction: {event.event_type.value}\nTarget: {event.target_file}\nChange: {event.details.get('change_summary')}", language="text")
        if st.button("▶ Run Verification", key="v1b"):
            run_verification(event)

    elif scenario.startswith("TC2"):
        event = AgentEvent(
            agent_id="agent_codegen", agent_name="CodeGen Agent",
            event_type=EventType.DEPENDENCY_ADDITION,
            details={
                "dependency_name": "json-parser-fork-v2",
                "source": "unknown-registry", "is_trusted": False,
            },
        )
        st.code(f"Agent: {event.agent_id}\nAction: {event.event_type.value}\nDependency: {event.details.get('dependency_name')}\nSource: {event.details.get('source')}", language="text")
        if st.button("▶ Run Verification", key="v2"):
            run_verification(event)

    elif scenario.startswith("TC4"):
        event = AgentEvent(
            agent_id="agent_low_trust", agent_name="Low-Trust Bot",
            event_type=EventType.FILE_ACCESS,
            target_file="config/.env.production",
        )
        st.code(f"Agent: {event.agent_id}\nAction: {event.event_type.value}\nTarget: {event.target_file}", language="text")
        if st.button("▶ Run Verification", key="v4"):
            run_verification(event)

    elif scenario == "Custom event":
        with st.form("custom_verify"):
            cv1, cv2 = st.columns(2)
            with cv1:
                c_agent = st.text_input("Agent ID", "agent_codegen")
                c_type = st.selectbox("Event Type", [e.value for e in EventType])
            with cv2:
                c_target = st.text_input("Target File", "src/main.py")
                c_summary = st.text_input("Change Summary", "")

            if st.form_submit_button("▶ Verify"):
                details = {}
                if c_summary:
                    details["change_summary"] = c_summary
                event = AgentEvent(
                    agent_id=c_agent, agent_name=c_agent,
                    event_type=EventType(c_type),
                    target_file=c_target, details=details,
                )
                run_verification(event)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TAB: MCP Security
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

with tab_mcp:
    st.markdown("## 🔒 Part 3: MCP Security Infrastructure")
    st.markdown("Secure tool server with path validation, rate limiting, scope guards, and audit logging.")

    mcol1, mcol2, mcol3 = st.columns(3)
    with mcol1:
        st.markdown("### 🛡 Path Validator")
        st.markdown("Blocks traversal attacks, sensitive files, null bytes")
    with mcol2:
        st.markdown("### ⏱ Rate Limiter")
        st.markdown("Sliding window, 10 req/min per agent")
    with mcol3:
        st.markdown("### 🔐 Scope Guard")
        st.markdown("Repo/branch/role-based access control")

    st.divider()

    st.markdown("### 🧪 Test Path Validation (Test Case 3)")

    test_paths = {
        "../../../etc/passwd": "Path traversal 🔴",
        "..%2F..%2Fetc%2Fpasswd": "URL-encoded traversal 🔴",
        ".env.production": "Sensitive file 🔴",
        ".git/config": "Git internals 🔴",
        "src/main.py": "Normal path 🟢",
        "docs/README.md": "Normal path 🟢",
    }

    path_input = st.text_input("Enter a file path to validate:", "../../../etc/passwd")

    if st.button("🔍 Validate Path", key="validate_path"):
        is_valid, reason = PathValidator.validate(path_input)
        if is_valid:
            st.success(f"✅ **ALLOWED**: `{path_input}` is a valid path.")
        else:
            st.error(f"🚫 **BLOCKED**: {reason}")

    st.divider()

    # Show pre-built test cases
    st.markdown("### Batch Path Validation Results")
    path_results = []
    for p, label in test_paths.items():
        is_valid, reason = PathValidator.validate(p)
        path_results.append({
            "Path": p,
            "Expected": label,
            "Result": "✅ ALLOWED" if is_valid else "🚫 BLOCKED",
            "Valid": is_valid,
        })
    st.dataframe(path_results, use_container_width=True, hide_index=True)

    st.divider()

    # MCP Tool Calls
    st.markdown("### 🔧 MCP Tool Calls (Demo Mode)")
    mcp_tool = st.selectbox("Tool", ["read_file", "list_commits", "get_pr_details"])

    if mcp_tool == "read_file":
        mcp_path = st.text_input("File Path", "src/auth/login.py", key="mcp_filepath")
        if st.button("Execute Tool", key="mcp_exec"):
            result = st.session_state.mcp_server.read_file("demo_agent", "api-backend", mcp_path)
            if "error" in result:
                st.error(f"Error: {result}")
            else:
                st.success("File read successfully!")
                st.json(result)

    elif mcp_tool == "list_commits":
        if st.button("Execute Tool", key="mcp_exec_commits"):
            result = st.session_state.mcp_server.list_commits("demo_agent", "api-backend", limit=5)
            st.json(result)

    elif mcp_tool == "get_pr_details":
        pr_num = st.number_input("PR Number", min_value=1, value=1)
        if st.button("Execute Tool", key="mcp_exec_pr"):
            result = st.session_state.mcp_server.get_pr_details("demo_agent", "api-backend", pr_num)
            st.json(result)

    # Audit log
    st.divider()
    st.markdown("### 📝 Audit Log")
    logs = st.session_state.mcp_server.audit_logger.get_logs()
    if logs:
        log_data = []
        for log in logs[-10:]:  # Last 10
            log_data.append({
                "Time": log.timestamp.strftime("%H:%M:%S"),
                "Agent": log.tool_call.agent_id,
                "Tool": log.tool_call.tool_name,
                "Allowed": "✅" if log.allowed else "🚫",
                "Violations": ", ".join(log.security_violations) if log.security_violations else "None",
            })
        st.dataframe(log_data, use_container_width=True, hide_index=True)
    else:
        st.info("No audit logs yet. Execute a tool call above to generate logs.")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TAB: Integrity Monitor
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

with tab_integrity:
    st.markdown("## 🔗 Part 4: Agent Supply Chain Integrity")
    st.markdown("HMAC-SHA256 signed decision traces with blockchain-like chain verification and behavioral anomaly detection.")

    icol1, icol2 = st.columns(2)

    with icol1:
        st.markdown("### 📜 Decision Trace Chain")

        if st.button("Record Sample Decisions", key="record_decisions"):
            monitor = st.session_state.integrity
            monitor.record_decision(
                "agent_codegen", "verify_code", {"file": "auth.py"},
                "Verifying auth code changes", {"decision": "ALLOW"},
            )
            monitor.record_decision(
                "agent_codegen", "modify_file", {"file": "payment.py"},
                "Updating payment logic", {"decision": "BLOCK"},
            )
            monitor.record_decision(
                "agent_reviewer", "review_pr", {"pr": 42},
                "Reviewing PR #42", {"decision": "APPROVE"},
            )
            st.success("3 decision traces recorded!")

        # Show chain status
        chain_valid, errors = st.session_state.integrity.verify_chain_integrity()
        traces = st.session_state.integrity.trace_store.traces

        if traces:
            st.markdown(f"**Chain Length:** {len(traces)} traces")
            if chain_valid:
                st.success("✅ Chain integrity VERIFIED — no tampering detected")
            else:
                st.error(f"🚫 Chain BROKEN — {len(errors)} error(s)")
                for err in errors:
                    st.markdown(f"- {err}")

            # Show traces
            trace_data = []
            for t in traces[-5:]:
                trace_data.append({
                    "Seq": t.sequence_number,
                    "Agent": t.agent_id,
                    "Action": t.action,
                    "Signature": t.signature[:16] + "…",
                    "Chain Hash": t.previous_hash[:16] + "…" if t.previous_hash else "—(genesis)",
                })
            st.dataframe(trace_data, use_container_width=True, hide_index=True)
        else:
            st.info("No traces recorded yet. Click 'Record Sample Decisions' above.")

    with icol2:
        st.markdown("### 🚨 Anomaly Detection (Test Case 4)")
        st.markdown("Detects behavioral deviations from established baselines.")

        st.markdown("**Scenario**: Agent that normally reads utility files suddenly tries to access credentials.")

        if st.button("🔍 Run Anomaly Check", key="anomaly_check"):
            monitor = st.session_state.integrity

            # Build baseline for codegen agent
            monitor.build_agent_baseline("agent_codegen")

            # Check for anomaly — credential access
            alert = monitor.check_action(
                "agent_codegen", "file_access", "config/.env.production"
            )

            if alert:
                st.error(f"🚨 **ANOMALY DETECTED!**")
                st.markdown(f"**Type:** {alert.alert_type}")
                st.markdown(f"**Severity:** {alert.severity.value}")
                st.markdown(f"**Baseline:** {alert.baseline_value}")
                st.markdown(f"**Observed:** {alert.observed_value}")
                with st.expander("Full Description"):
                    st.markdown(alert.description)
            else:
                st.info("No anomaly detected for this action.")

        # Show all alerts
        all_alerts = st.session_state.integrity.get_all_alerts()
        if all_alerts:
            st.markdown(f"### Alert History ({len(all_alerts)} total)")
            for a in all_alerts[-5:]:
                severity_icons = {
                    AnomalySeverity.CRITICAL: "🔴",
                    AnomalySeverity.HIGH: "🟠",
                    AnomalySeverity.MEDIUM: "🟡",
                    AnomalySeverity.LOW: "🟢",
                }
                icon = severity_icons.get(a.severity, "⚪")
                st.markdown(f"{icon} **{a.severity.value}** — {a.alert_type}: {a.description[:100]}…")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TAB: Triage Agent
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

with tab_triage:
    st.markdown("## 🎯 Part 5: Autonomous Vulnerability Triage Agent")
    st.markdown("Combines SAST findings + runtime context + code awareness → intelligent prioritization with remediation guidance.")

    st.divider()

    st.markdown("### 🧪 Triage Scenarios")

    triage_scenario = st.selectbox("Select finding to triage:", [
        "TC5: SQL Injection in Payment (prod, internet-facing, PII) → URGENT",
        "TC6: Hardcoded Secret in Dev Script (not deployed) → LOW",
        "TC7: Medium XSS in Admin Panel (AI-modified, internet-facing) → HIGH (upgraded)",
    ])

    findings_map = {
        "TC5": SASTFinding(id="tc5_sqli", vuln_type=VulnType.SQL_INJECTION,
                           severity=SASTSeverity.HIGH, file_path="src/payment/process.py",
                           line_number=42, description="SQL injection via string concatenation in payment endpoint",
                           cwe_id="CWE-89"),
        "TC6": SASTFinding(id="tc6_secret", vuln_type=VulnType.HARDCODED_SECRET,
                           severity=SASTSeverity.MEDIUM, file_path="scripts/dev_setup.py",
                           line_number=5, description="Hardcoded API key in development setup script",
                           cwe_id="CWE-798"),
        "TC7": SASTFinding(id="tc7_xss", vuln_type=VulnType.XSS,
                           severity=SASTSeverity.MEDIUM, file_path="src/admin/panel.py",
                           line_number=100, description="Reflected XSS in admin search parameter",
                           cwe_id="CWE-79"),
    }

    tc_key = triage_scenario.split(":")[0]
    finding = findings_map[tc_key]

    # Show finding details
    st.markdown(f"""
    **Finding:** {finding.description}
    - **File:** `{finding.file_path}:{finding.line_number}`
    - **Type:** {finding.vuln_type.value}
    - **SAST Severity:** {finding.severity.value}
    - **CWE:** {finding.cwe_id}
    """)

    if st.button("▶ Run Triage", key="run_triage"):
        triage = st.session_state.triage
        result = triage.triage_finding(finding)

        # Priority display
        priority_colors = {
            TriagePriority.URGENT: ("🔴", "#dc3545"),
            TriagePriority.HIGH: ("🟠", "#fd7e14"),
            TriagePriority.MEDIUM: ("🟡", "#ffc107"),
            TriagePriority.LOW: ("🟢", "#28a745"),
            TriagePriority.INFO: ("⚪", "#6c757d"),
        }
        icon, color = priority_colors.get(result.final_priority, ("⚪", "#6c757d"))

        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown(f"### {icon} Priority: **{result.final_priority.value}**")
        with col2:
            st.metric("Exploitability", f"{result.exploitability.score:.2f}")
        with col3:
            st.metric("Business Risk", f"{result.business_risk_score:.2f}")

        # Severity change indicator
        if result.final_priority.value != result.original_severity.value:
            if TriagePriority[result.final_priority.value].value != result.original_severity.value:
                st.warning(f"⚡ **Priority adjusted**: {result.original_severity.value} → {result.final_priority.value}")

        # Exploitability factors
        with st.expander("📊 Exploitability Factors"):
            for factor in result.exploitability.factors:
                st.markdown(f"- {factor}")

        # Full reasoning
        with st.expander("🧠 Full Reasoning"):
            st.text(result.reasoning)

        # Remediation
        if result.remediation:
            with st.expander("🔧 Remediation Guidance"):
                st.markdown(f"**{result.remediation.description}**")
                if result.remediation.code_snippet:
                    st.code(result.remediation.code_snippet, language="python")
                st.markdown(f"**Effort:** {result.remediation.effort_estimate}")
                if result.remediation.references:
                    st.markdown("**References:**")
                    for ref in result.remediation.references:
                        st.markdown(f"- [{ref}]({ref})")

    st.divider()

    # Batch triage
    st.markdown("### 📋 Batch Triage All Findings")
    if st.button("Run All 3 Test Case Findings", key="batch_triage"):
        triage = st.session_state.triage
        all_findings = list(findings_map.values())
        results = triage.triage_all(all_findings)

        rows = []
        for r in results:
            picon = {"URGENT": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "⚪"}.get(r.final_priority.value, "⚪")
            rows.append({
                "Finding": r.finding_id,
                "Original": r.original_severity.value,
                "Final": f"{picon} {r.final_priority.value}",
                "Exploitability": f"{r.exploitability.score:.2f}",
                "Risk Score": f"{r.business_risk_score:.2f}",
                "Changed": "⚡" if r.final_priority.value != r.original_severity.value else "—",
            })
        st.dataframe(rows, use_container_width=True, hide_index=True)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# TAB: Test Cases
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

with tab_tests:
    st.markdown("## ✅ Test Case Validation")
    st.markdown("Run all 7 test cases to validate the AgentShield platform.")

    if st.button("▶ Run All 7 Test Cases", key="run_all_tests", type="primary"):
        results = []

        with st.spinner("Running test cases..."):
            graph = st.session_state.graph
            verifier = st.session_state.verifier
            integrity = st.session_state.integrity
            triage = st.session_state.triage

            # ── TC1: Agent deletes auth validation → BLOCK ──
            tc1_event = AgentEvent(
                agent_id="agent_codegen", agent_name="CodeGen Agent",
                event_type=EventType.CODE_MODIFICATION,
                target_file="src/auth/controller.py",
                details={"change_summary": "Removed authentication validation check", "lines_removed": 15, "lines_added": 2},
            )
            tc1_result = verifier.verify(tc1_event)
            tc1_pass = tc1_result.decision == VerificationDecision.BLOCK
            results.append(("TC1", "Agent deletes auth validation", "BLOCK", tc1_result.decision.value, tc1_pass))

            # ── TC1b: Same change in test file → ALLOW ──
            tc1b_event = AgentEvent(
                agent_id="agent_codegen", agent_name="CodeGen Agent",
                event_type=EventType.CODE_MODIFICATION,
                target_file="tests/test_auth.py",
                details={"change_summary": "Removed authentication check from test helper", "lines_removed": 10, "lines_added": 2},
            )
            tc1b_result = verifier.verify(tc1b_event)
            tc1b_pass = tc1b_result.decision == VerificationDecision.ALLOW
            results.append(("TC1b", "Same change in test file", "ALLOW", tc1b_result.decision.value, tc1b_pass))

            # ── TC2: Untrusted dependency → REQUIRE_HUMAN_REVIEW ──
            tc2_event = AgentEvent(
                agent_id="agent_codegen", agent_name="CodeGen Agent",
                event_type=EventType.DEPENDENCY_ADDITION,
                details={"dependency_name": "json-parser-fork-v2", "source": "unknown-registry", "is_trusted": False},
            )
            tc2_result = verifier.verify(tc2_event)
            tc2_pass = tc2_result.decision == VerificationDecision.REQUIRE_HUMAN_REVIEW
            results.append(("TC2", "Untrusted dependency addition", "REQUIRE_HUMAN_REVIEW", tc2_result.decision.value, tc2_pass))

            # ── TC3: Path traversal → BLOCKED ──
            tc3_valid, tc3_msg = PathValidator.validate("../../../etc/passwd")
            tc3_pass = not tc3_valid
            results.append(("TC3", "Path traversal attack", "BLOCKED", "BLOCKED" if not tc3_valid else "ALLOWED", tc3_pass))

            # ── TC4: Behavioral anomaly ──
            integrity.build_agent_baseline("agent_codegen")
            tc4_alert = integrity.check_action("agent_codegen", "file_access", "config/.env.production")
            tc4_pass = tc4_alert is not None
            results.append(("TC4", "Behavioral anomaly detection", "ALERT", "ALERT" if tc4_alert else "NO ALERT", tc4_pass))

            # ── TC5: SQL injection in payment → URGENT ──
            tc5_finding = SASTFinding(
                id="tc5", vuln_type=VulnType.SQL_INJECTION, severity=SASTSeverity.HIGH,
                file_path="src/payment/process.py", line_number=42,
                description="SQL injection in payment endpoint", cwe_id="CWE-89",
            )
            tc5_result = triage.triage_finding(tc5_finding)
            tc5_pass = tc5_result.final_priority == TriagePriority.URGENT and tc5_result.exploitability.score >= 0.90
            results.append(("TC5", f"SQL injection in prod payment (exploit={tc5_result.exploitability.score:.2f})", "URGENT", tc5_result.final_priority.value, tc5_pass))

            # ── TC6: Hardcoded secret in dev → LOW ──
            tc6_finding = SASTFinding(
                id="tc6", vuln_type=VulnType.HARDCODED_SECRET, severity=SASTSeverity.MEDIUM,
                file_path="scripts/dev_setup.py", line_number=5,
                description="Hardcoded API key in dev script", cwe_id="CWE-798",
            )
            tc6_result = triage.triage_finding(tc6_finding)
            tc6_pass = tc6_result.final_priority == TriagePriority.LOW and tc6_result.exploitability.score <= 0.10
            results.append(("TC6", f"Hardcoded secret in dev (exploit={tc6_result.exploitability.score:.2f})", "LOW", tc6_result.final_priority.value, tc6_pass))

            # ── TC7: Medium XSS upgraded → HIGH ──
            tc7_finding = SASTFinding(
                id="tc7", vuln_type=VulnType.XSS, severity=SASTSeverity.MEDIUM,
                file_path="src/admin/panel.py", line_number=100,
                description="Reflected XSS in admin panel", cwe_id="CWE-79",
            )
            tc7_result = triage.triage_finding(tc7_finding)
            tc7_pass = tc7_result.final_priority in (TriagePriority.HIGH, TriagePriority.URGENT)
            results.append(("TC7", f"Medium XSS upgraded (exploit={tc7_result.exploitability.score:.2f})", "HIGH+", tc7_result.final_priority.value, tc7_pass))

        # Display results
        st.divider()

        total = len(results)
        passed = sum(1 for r in results if r[4])

        if passed == total:
            st.success(f"🎉 **All {total}/{total} test cases PASSED!**")
            st.balloons()
        else:
            st.warning(f"⚠ {passed}/{total} test cases passed")

        # Results table
        rows = []
        for tc_id, desc, expected, actual, passed_flag in results:
            status = "✅ PASS" if passed_flag else "❌ FAIL"
            rows.append({
                "Test": tc_id,
                "Description": desc,
                "Expected": expected,
                "Actual": actual,
                "Status": status,
            })
        st.dataframe(rows, use_container_width=True, hide_index=True)

        st.session_state.test_results = results


# ─── Footer ──────────────────────────────────────────────────────────

st.divider()
st.markdown(
    '<div style="text-align: center; color: #6c757d; padding: 1rem;">'
    'AgentShield — AI Agent Security Platform | Built with LangGraph, NetworkX, MCP SDK, Pydantic v2'
    '</div>',
    unsafe_allow_html=True,
)
