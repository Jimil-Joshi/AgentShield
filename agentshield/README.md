# 🛡️ AgentShield — AI Agent Security Platform

> A comprehensive security platform for monitoring, verifying, and securing AI agent operations in software development environments.

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![LangGraph](https://img.shields.io/badge/LangGraph-0.2+-green.svg)](https://github.com/langchain-ai/langgraph)
[![MCP](https://img.shields.io/badge/MCP-Official_SDK-purple.svg)](https://github.com/modelcontextprotocol/python-sdk)

---

## 📋 Overview

AgentShield is a 5-part AI agent security platform that provides:

1. **Context Graph** — Knowledge graph tracking all agent interactions with code, dependencies, and runtime
2. **Autonomous Verifier Agent** — Real-time verification of agent actions via LangGraph + 5 security rules
3. **MCP Security Infrastructure** — Secure tool server with path validation, rate limiting, and scope guards
4. **Supply Chain Integrity Monitor** — HMAC-SHA256 signed decision traces with anomaly detection
5. **Autonomous Vulnerability Triage Agent** — SAST findings + runtime context → intelligent prioritization

## 🏗 Architecture

```
┌─────────────┐    ┌───────────────┐    ┌─────────────────┐
│ AI Agent     │───>│ Context Graph │───>│ Verifier Agent  │
│ (any action) │    │ (NetworkX)    │    │ (LangGraph)     │
└─────────────┘    └───────────────┘    └────────┬────────┘
                                                  │
     ┌────────────────────────────────────────────┘
     │
┌────▼──────────┐    ┌─────────────────┐    ┌───────────────┐
│ MCP Security  │    │ Integrity       │    │ Triage Agent  │
│ (FastMCP)     │    │ (HMAC chains)   │    │ (LangGraph)   │
└───────────────┘    └─────────────────┘    └───────────────┘
```

## ⚡ Quick Start

### 1. Prerequisites

- Python 3.11+
- pip

### 2. Install Dependencies

```bash
cd agentshield
pip install -r requirements.txt
```

### 3. Environment Variables (Optional)

Copy the `.env` file to the agentshield directory and set:

```bash
# Primary LLM (AWS Bedrock — Claude 3.5 Sonnet)
AWS_ACCESS_KEY_ID=your_key
AWS_SECRET_ACCESS_KEY=your_secret
AWS_DEFAULT_REGION=us-west-2

# Fallback LLM (Azure OpenAI)
AZURE_OPENAI_API_KEY=your_key
AZURE_OPENAI_ENDPOINT=https://your-endpoint.openai.azure.com/

# Integrity signing key (optional — has a default)
AGENTSHIELD_SIGNING_KEY=your-secret-key
```

> **Note**: The platform works fully in demo mode without any API keys. LLM integration enhances verifier reasoning but is optional.

### 4. Run the Demo

```bash
# Command-line demo (all 7 test cases)
python examples/demo_script.py

# Streamlit dashboard (interactive UI)
streamlit run streamlit_app.py
```

### 5. Run Tests

```bash
cd agentshield
pytest tests/ -v
```

## 📁 Project Structure

```
agentshield/
├── src/
│   ├── __init__.py
│   ├── models.py                 # All Pydantic v2 data models
│   ├── utils.py                  # LLM providers, security helpers
│   ├── context_graph.py          # Part 1: NetworkX MultiDiGraph
│   ├── verifier_agent.py         # Part 2: LangGraph verifier + 5 rules
│   ├── mcp_server.py             # Part 3: MCP security server (FastMCP)
│   ├── integrity_monitor.py      # Part 4: HMAC signing + anomaly detection
│   ├── exploitability_analyzer.py # Part 5: Exploitability scoring
│   ├── risk_calculator.py        # Part 5: Risk + priority calculation
│   ├── remediation_generator.py  # Part 5: Fix guidance with code snippets
│   └── triage_agent.py           # Part 5: LangGraph triage orchestrator
├── tests/
│   ├── __init__.py
│   ├── test_context_graph.py     # Graph CRUD, queries, serialization
│   ├── test_verifier.py          # TC1, TC1b, TC2, TC4 — rule validation
│   ├── test_mcp_security.py      # TC3 — path traversal, rate limiting
│   ├── test_integrity.py         # TC4 — HMAC signing, chain, anomalies
│   └── test_triage_agent.py      # TC5, TC6, TC7 — triage + prioritization
├── examples/
│   ├── demo_script.py            # End-to-end demo with all 7 test cases
│   ├── sample_events.json        # Sample agent events
│   ├── sample_sast_findings.json # Sample SAST scan results
│   └── sample_runtime_context.json # Sample runtime contexts
├── streamlit_app.py              # Interactive Streamlit dashboard
├── requirements.txt              # Python dependencies
├── DESIGN.md                     # Architecture design document
└── .gitignore
```

## ✅ Test Cases

All 7 test cases from the specification are implemented and validated:

| # | Scenario | Expected | Component |
|---|----------|----------|-----------|
| **TC1** | Agent deletes auth validation in production code | **BLOCK** | Verifier (Rule 001) |
| **TC1b** | Same change in test file | **ALLOW** | Verifier (Rule 001, context-aware) |
| **TC2** | Untrusted dependency from unknown registry | **REQUIRE_HUMAN_REVIEW** | Verifier (Rule 002) |
| **TC3** | Path traversal attack (`../../../etc/passwd`) | **BLOCKED** | MCP PathValidator |
| **TC4** | Agent suddenly accesses credentials (no prior history) | **ANOMALY ALERT** | Integrity Monitor |
| **TC5** | SQL injection in prod payment (deployed, internet, PII) | **URGENT** (exploit ≥ 0.90) | Triage Agent |
| **TC6** | Hardcoded secret in dev script (not deployed) | **LOW** (exploit ≤ 0.10) | Triage Agent |
| **TC7** | Medium XSS, but AI-modified + internet-facing | **HIGH** (upgraded from MEDIUM) | Triage Agent |

## 🔧 Technology Stack

| Component | Technology |
|-----------|------------|
| **Graph Store** | NetworkX MultiDiGraph (in-memory) |
| **Agent Framework** | LangGraph StateGraph |
| **Primary LLM** | AWS Bedrock — Claude 3.5 Sonnet v2 |
| **Fallback LLM** | Azure OpenAI — GPT-4.1-mini |
| **MCP Protocol** | Official `mcp` Python SDK (FastMCP) |
| **Data Models** | Pydantic v2 |
| **Signing** | HMAC-SHA256 (hashlib + hmac) |
| **Dashboard** | Streamlit + Plotly |
| **Testing** | pytest + pytest-asyncio |

## 🔍 Key Design Decisions

1. **NetworkX over Neo4j** — In-memory graph avoids external dependencies; sufficient for demo scope with serialization support
2. **TypedDict for LangGraph state** — Avoids Pydantic/LangGraph reducer conflicts; Pydantic models embedded as sub-objects
3. **HMAC-SHA256 over RSA** — Symmetric signing is simpler, faster, and appropriate for single-service deployment
4. **Template + LLM hybrid** — Remediation uses deterministic templates for common vulns (9 types), with optional LLM enhancement
5. **Context-aware rules** — Rule 001 distinguishes test vs. production files, avoiding false positives

## 📊 Streamlit Dashboard

The interactive dashboard provides:

- **Overview** — Platform metrics and architecture diagram
- **Context Graph** — Interactive queries, event ingestion, node/edge statistics
- **Verifier Agent** — Run all 4 verification scenarios with full reasoning output
- **MCP Security** — Path validation testing, MCP tool calls, audit log viewer
- **Integrity Monitor** — Decision trace chain visualization, anomaly detection demo
- **Triage Agent** — Run individual or batch triage with exploitability/risk/remediation details
- **Test Cases** — One-click execution of all 7 test cases with pass/fail reporting

```bash
streamlit run streamlit_app.py
```

## 📝 License

This project is provided as-is for assessment purposes.
