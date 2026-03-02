# AgentShield — Complete Guide: Real Data, Demo Flow & How It All Works

---

## Table of Contents

1. [How AgentShield Works (End-to-End)](#1-how-agentshield-works-end-to-end)
2. [Demo Mode vs Real Mode](#2-demo-mode-vs-real-mode)
3. [Using Real Data](#3-using-real-data)
4. [Connecting to Your Real GitHub](#4-connecting-to-your-real-github)
5. [Enabling LLM-Enhanced Mode](#5-enabling-llm-enhanced-mode)
6. [Full Demo Walkthrough (Step-by-Step)](#6-full-demo-walkthrough-step-by-step)
7. [Quick Reference: Commands](#7-quick-reference-commands)

---

## 1. How AgentShield Works (End-to-End)

AgentShield is a security platform that monitors, controls, and audits AI coding agents. Here's exactly what each part does and how they connect:

### The Problem It Solves

When AI agents (like GitHub Copilot, Cursor, Devin, etc.) modify your codebase, they can:
- Remove security checks (authentication, authorization)
- Introduce malicious dependencies (supply chain attacks)
- Access sensitive files (.env, credentials)
- Expose PII through internet-facing code
- Make changes that look innocent but create vulnerabilities

AgentShield catches ALL of these.

### Data Flow — What Happens When an Agent Acts

```
Step 1: An AI agent performs an action
        (modifies a file, reads a file, adds a dependency)
                    │
                    ▼
Step 2: The ACTION is recorded as an AgentEvent
        {
          agent_id: "copilot_agent",
          event_type: "code_modification",
          target_file: "src/auth/login.py",
          details: { change_summary: "Removed password check" }
        }
                    │
                    ▼
Step 3: CONTEXT GRAPH ingests the event
        - Creates/updates nodes (agent, file, dependency)
        - Creates edges (agent --MODIFIED--> file)
        - Now we can query: "Which agents touched auth code?"
                    │
                    ▼
Step 4: VERIFIER AGENT evaluates the action
        - Rule 001: Is security logic being removed? → BLOCK
        - Rule 002: Is an untrusted dependency added? → BLOCK
        - Rule 003: Is auth code being changed? → ESCALATE
        - Rule 004: Are credentials being accessed? → BLOCK
        - Rule 005: Is PII exposed internet-facing? → ESCALATE
        - Result: ALLOW / BLOCK / ESCALATE + confidence score
                    │
                    ▼
Step 5: MCP SERVER enforces tool access
        - Is the file path safe? (no ../../etc/passwd)
        - Is the agent within rate limits? (max N/minute)
        - Is the agent allowed in this repo/branch?
        - Everything is audit-logged
                    │
                    ▼
Step 6: INTEGRITY MONITOR records the decision
        - Signs it with HMAC-SHA256
        - Chains it to the previous decision (hash chain)
        - Checks for behavioral anomalies
        - If tampered later → chain verification catches it
                    │
                    ▼
Step 7: TRIAGE AGENT processes SAST findings
        - Takes raw scanner output (SQL injection, XSS, etc.)
        - Calculates exploitability (is it deployed? internet-facing? PII?)
        - Assigns priority: URGENT / HIGH / MEDIUM / LOW / INFO
        - Generates remediation steps with code examples
```

### What Each Component Stores

| Component | What it Knows | Example Query |
|---|---|---|
| **Context Graph** | All agents, files, vulnerabilities, dependencies, and relationships | "Show me every file agent_copilot modified in the auth module" |
| **Verifier Agent** | 5 security rules + context-aware logic | "Should this agent be allowed to remove verify_password()?" |
| **MCP Server** | Allowed paths, rate limits, agent scopes, audit trail | "Has agent_X exceeded 10 requests/minute?" |
| **Integrity Monitor** | Signed decision chain, behavioral baselines, agent identities | "Has anyone tampered with decision #47?" |
| **Triage Agent** | Vulnerability scores, priorities, remediation guidance | "Which of these 200 SAST findings should I fix first?" |

---

## 2. Demo Mode vs Real Mode

| Aspect | Demo Mode (default) | Real Mode |
|---|---|---|
| **Data source** | Built-in synthetic events, files, vulnerabilities | Your actual GitHub repos, real SAST output |
| **GitHub access** | Fake file contents, fake commits, fake PRs | Real GitHub API via GITHUB_TOKEN |
| **LLM** | Off (`use_llm=False`) — pure deterministic rules | On (`use_llm=True`) — Claude/GPT enhances reasoning |
| **When to use** | Presentations, testing, development | Production monitoring, real security analysis |
| **Setup needed** | None (just `pip install` and run) | API keys in .env |

### What Demo Mode Gives You

The demo data simulates a realistic scenario:

**Agents:**
- `agent_coder_01` (CodeAssistant) — an AI coding agent
- `agent_builder_02` (BuildAgent) — an AI build/CI agent
- `agent_scanner_03` (SecurityScanner) — an AI security scanner

**Files being worked on:**
- `src/auth/login.py` — authentication code (high sensitivity)
- `src/payment/process.py` — payment processing (high sensitivity)
- `src/admin/dashboard.py` — admin panel (medium sensitivity)
- `scripts/dev_setup.py` — development helper (low sensitivity)

**Scenarios that play out:**
1. CodeAssistant removes `verify_password()` from auth code → **BLOCKED**
2. BuildAgent adds an untrusted dependency `backdoor-logger` → **BLOCKED**
3. Agent tries to read `../../etc/passwd` → **PATH BLOCKED**
4. Agent makes >10 requests/minute → **RATE LIMITED**
5. SQL injection found in production payment code → **URGENT priority**
6. Hardcoded secret in dev script → **INFO priority** (correctly deprioritized)

---

## 3. Using Real Data

### 3a. Real Agent Events

Instead of demo events, feed in real actions from your CI/CD pipeline or IDE telemetry.

**Create a Python script** (`real_data_demo.py`):

```python
"""
AgentShield with your own real data.
Replace the placeholder values with actual data from your project.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from src.models import (
    AgentEvent, AgentNode, CodeFileNode, RuntimeContextNode,
    EventType, FunctionCategory, AgentRole,
    SASTFinding, SASTSeverity, VulnType,
)
from src.context_graph import ContextGraph
from src.verifier_agent import VerifierAgent
from src.mcp_server import MCPSecurityServer
from src.integrity_monitor import IntegrityMonitor
from src.triage_agent import TriageAgent


# ── Step 1: Build the Context Graph with YOUR project data ──

graph = ContextGraph()

# Register your actual AI agents
graph.add_node("github_copilot", {
    "node_type": "Agent",
    "name": "GitHub Copilot",
    "role": "code_assistant",
    "trust_level": 0.8,           # How much you trust this agent (0-1)
})

graph.add_node("cursor_agent", {
    "node_type": "Agent",
    "name": "Cursor AI",
    "role": "code_assistant",
    "trust_level": 0.7,
})

# Register your actual code files
graph.add_node("file_auth", {
    "node_type": "CodeFile",
    "file_path": "src/auth/login.py",        # ← YOUR actual file path
    "language": "python",
    "function_category": "auth",              # auth | payment | admin | general | test
    "ai_generated": False,                    # Was this file AI-generated?
})

graph.add_node("file_api", {
    "node_type": "CodeFile",
    "file_path": "src/api/endpoints.py",      # ← YOUR actual file path
    "language": "python",
    "function_category": "general",
    "ai_generated": True,                     # Copilot wrote this
})

# Add runtime context (from your deployment)
graph.add_node("runtime_auth", {
    "node_type": "RuntimeContext",
    "file_path": "src/auth/login.py",
    "deployed_to_production": True,           # ← Is this file in prod?
    "is_internet_facing": True,               # ← Exposed to the internet?
    "handles_pii": True,                      # ← Processes personal data?
    "recently_modified_by_ai": False,
})

# Connect them
graph.add_edge("github_copilot", "file_api", "GENERATED", {"timestamp": "2026-02-27T10:00:00Z"})
graph.add_edge("file_auth", "runtime_auth", "HAS_RUNTIME_CONTEXT", {})


# ── Step 2: Verify an agent action ──

verifier = VerifierAgent(graph, use_llm=False)

# Simulate: Copilot tries to modify your auth code
event = AgentEvent(
    agent_id="github_copilot",
    agent_name="GitHub Copilot",
    event_type=EventType.CODE_MODIFICATION,
    target_file="src/auth/login.py",          # ← YOUR actual file
    details={
        "change_summary": "Removed authenticate() call to simplify login",
        "removed_code": "if not authenticate(user): raise Forbidden()",
        "function_category": "auth",
    },
)

result = verifier.verify(event)
print(f"Decision: {result.decision.value}")   # BLOCK
print(f"Rules violated: {result.rules_violated}")
print(f"Confidence: {result.confidence}")
print(f"Reasoning: {result.reasoning}")


# ── Step 3: Triage YOUR actual SAST findings ──

triage = TriageAgent(graph, use_llm=False)

# Add runtime context for the vulnerable file
graph.add_node("runtime_payment", {
    "node_type": "RuntimeContext",
    "file_path": "src/payment/checkout.py",
    "deployed_to_production": True,
    "is_internet_facing": True,
    "handles_pii": True,
    "recently_modified_by_ai": True,
})

# Paste in findings from your actual SAST scanner (Semgrep, SonarQube, etc.)
your_findings = [
    SASTFinding(
        id="finding_001",
        severity=SASTSeverity.HIGH,
        vuln_type=VulnType.SQL_INJECTION,
        file_path="src/payment/checkout.py",  # ← YOUR actual file
        line_number=42,
        description="User input directly in SQL query",
        cwe_id="CWE-89",
    ),
    SASTFinding(
        id="finding_002",
        severity=SASTSeverity.MEDIUM,
        vuln_type=VulnType.XSS,
        file_path="src/frontend/search.py",   # ← YOUR actual file
        line_number=15,
        description="Unescaped user input in HTML template",
        cwe_id="CWE-79",
    ),
]

# Triage them all
results = triage.triage_all(your_findings)
for r in results:
    print(f"[{r.final_priority.value}] {r.finding_id} — Score: {r.business_risk_score:.2f}")
    print(f"  Remediation: {r.remediation.description}")
    print(f"  Fix steps: {r.remediation.fix_steps}")
    print()


# ── Step 4: Record everything in the integrity chain ──

monitor = IntegrityMonitor(graph)

monitor.record_decision(
    agent_id="github_copilot",
    action="code_modification",
    inputs={"file": "src/auth/login.py", "change": "removed authenticate()"},
    reasoning="Rule 001 triggered: security logic removal in auth code",
    output={"decision": "BLOCK", "confidence": 0.95},
)

# Verify the chain hasn't been tampered with
valid, issues = monitor.verify_chain()
print(f"Chain integrity: {'VALID' if valid else 'COMPROMISED'}")
if issues:
    print(f"Issues: {issues}")
```

Run it:
```bash
cd agentshield
python real_data_demo.py
```

### 3b. Import SAST Output from Real Scanners

**From Semgrep:**
```bash
# Run Semgrep on your project
semgrep --config auto --json -o semgrep_output.json /path/to/your/project
```

Then convert:
```python
import json
from src.models import SASTFinding, SASTSeverity, VulnType

# Map Semgrep severity to AgentShield severity
SEVERITY_MAP = {
    "ERROR": SASTSeverity.HIGH,
    "WARNING": SASTSeverity.MEDIUM,
    "INFO": SASTSeverity.LOW,
}

# Map common CWE to VulnType
CWE_MAP = {
    "CWE-89": VulnType.SQL_INJECTION,
    "CWE-79": VulnType.XSS,
    "CWE-78": VulnType.COMMAND_INJECTION,
    "CWE-22": VulnType.PATH_TRAVERSAL,
    "CWE-918": VulnType.SSRF,
    "CWE-798": VulnType.HARDCODED_SECRET,
}

with open("semgrep_output.json") as f:
    semgrep = json.load(f)

findings = []
for i, result in enumerate(semgrep.get("results", [])):
    findings.append(SASTFinding(
        id=f"semgrep_{i}",
        severity=SEVERITY_MAP.get(result.get("extra", {}).get("severity", "INFO"), SASTSeverity.MEDIUM),
        vuln_type=CWE_MAP.get(result.get("extra", {}).get("metadata", {}).get("cwe", ""), VulnType.MISSING_AUTH),
        file_path=result.get("path", "unknown"),
        line_number=result.get("start", {}).get("line", 0),
        description=result.get("extra", {}).get("message", ""),
        cwe_id=result.get("extra", {}).get("metadata", {}).get("cwe", ""),
    ))

# Now triage them
triage = TriageAgent(graph, use_llm=False)
results = triage.triage_all(findings)
```

**From SonarQube** (export issues as JSON and convert similarly).

---

## 4. Connecting to Your Real GitHub

The MCP server can call the real GitHub API instead of returning fake data.

### Step 1: Create a GitHub Personal Access Token

1. Go to https://github.com/settings/tokens?type=beta
2. Click **Generate new token (Fine-grained)**
3. Give it a name like "AgentShield"
4. Select repositories: choose your target repo(s)
5. Permissions needed:
   - Contents: Read
   - Pull requests: Read/Write (if you want to create comments)
   - Commits: Read
6. Generate token and copy it

### Step 2: Set the Token

Add to your `.env` file (project root):
```
GITHUB_TOKEN=github_pat_xxxxxxxxxxxxxxxxxxxxxxxxx
```

Or set inline:
```bash
$env:GITHUB_TOKEN = "github_pat_xxxxxxxxxxxxxxxxxxxxxxxxx"   # PowerShell
```

### Step 3: Use Real Mode

```python
from src.models import AgentRegistryEntry, AgentRole
from src.mcp_server import MCPSecurityServer

# demo_mode=False → uses real GitHub API
server = MCPSecurityServer(demo_mode=False, max_rate_per_minute=30)

# Register an agent with access to YOUR repo
server.register_agent(AgentRegistryEntry(
    agent_id="my_agent",
    agent_name="My Coding Agent",
    role=AgentRole.READER,
    allowed_repos=["YourUsername/YourRepo"],   # ← YOUR actual repo
    allowed_branches=["main", "develop"],
))

# Read a real file from your repo
result = server.read_file("my_agent", "YourUsername/YourRepo", "src/main.py")
print(result)  # Real file content from GitHub!

# List real commits
commits = server.list_commits("my_agent", "YourUsername/YourRepo", "main", limit=5)
print(commits)

# Get real PR details
pr = server.get_pr_details("my_agent", "YourUsername/YourRepo", pr_number=1)
print(pr)

# Security still enforced!
# This will be BLOCKED (path traversal):
bad = server.read_file("my_agent", "YourUsername/YourRepo", "../../etc/passwd")
print(bad)  # {"error": "Access denied", "violations": [...]}
```

### Step 4: Install httpx (needed for real GitHub calls)

```bash
pip install httpx
```

---

## 5. Enabling LLM-Enhanced Mode

By default, everything runs **deterministic** (no AI). To add LLM reasoning:

### What LLM Mode Adds

| Component | Without LLM | With LLM |
|---|---|---|
| **Verifier Agent** | 5 rule-based checks (fast, deterministic) | Rules + LLM reviews ambiguous ESCALATE cases for nuanced reasoning |
| **Triage Agent** | Template-based remediation | LLM generates context-specific fix suggestions |
| **All others** | Fully deterministic (graph, MCP, integrity) | Same — these don't use LLM |

### Enable It

Make sure your `.env` has the API keys:

```env
# Option A: AWS Bedrock (primary)
AWS_ACCESS_KEY_ID=your_key
AWS_SECRET_ACCESS_KEY=your_secret
AWS_REGION_NAME=us-west-2

# Option B: Azure OpenAI (fallback)
AZURE_OPENAI_API_KEY=your_key
AZURE_OPENAI_ENDPOINT=https://your-instance.openai.azure.com/
AZURE_OPENAI_DEPLOYMENT_NAME=gpt-4.1-mini
```

Then pass `use_llm=True`:

```python
verifier = VerifierAgent(graph, use_llm=True)   # LLM-enhanced verification
triage = TriageAgent(graph, use_llm=True)        # LLM-enhanced remediation
```

The system tries Bedrock first, falls back to Azure if Bedrock fails. If BOTH fail, it gracefully degrades to deterministic mode.

---

## 6. Full Demo Walkthrough (Step-by-Step)

### Before You Start

```bash
cd agentshield
python -m pytest tests/ -v      # Confirm 75 passed
streamlit run streamlit_app.py   # Launch dashboard
```

### Flow 1: "An AI agent just deleted authentication checks" (2 min)

**Context**: You're showing how AgentShield catches dangerous agent behavior.

1. **Tab 2 — Context Graph** → Click **Load Sample Data**
   > "This graph represents a real codebase — agents, files, dependencies, vulnerabilities, all connected."

2. Run query: **"Agents modifying auth code"**
   > "We can instantly see which AI agents have touched authentication code — this is the first red flag."

3. **Tab 3 — Verifier Agent**
   - Event type: `CODE_MODIFICATION`
   - Target file: `src/auth/controller.py`
   - Change summary: `Removed authentication validation check`
   - Click **Verify**
   
   > "The agent tried to remove `authenticate()` from production auth code. Rule 001 fires → BLOCKED with 95% confidence. The agent's change is rejected."

4. Now change target to `tests/test_auth.py`, same summary, click **Verify**
   > "Same change in a test file → ALLOWED. The verifier is context-aware — it knows the difference between prod and test code."

### Flow 2: "Securing agent tool access" (2 min)

**Context**: You're showing how MCP prevents agents from accessing things they shouldn't.

5. **Tab 4 — MCP Security**
   - Type `../../etc/passwd` → **BLOCKED** (path traversal attack)
   - Type `.env.production` → **BLOCKED** (sensitive file)
   - Type `src/api/handler.py` → **ALLOWED** (normal file)
   
   > "Every file access goes through path validation. Even if an agent is compromised, it can't read secrets or escape the repo."

6. Click **Read File** with repo `api-backend`, file `src/main.py`
   > "In demo mode we return synthetic data. In production, this calls the real GitHub API — same security guardrails apply."

7. Rapidly click read file 12 times
   > "Rate limiter kicks in after the configured limit. No single agent can flood the system."

### Flow 3: "You can't tamper with decisions" (1 min)

**Context**: You're showing the integrity guarantee.

8. **Tab 5 — Integrity Monitor**
   - Record 3 decisions
   - Click **Verify Chain** → **VALID**
   
   > "Every decision is signed with HMAC-SHA256 and hash-chained. If someone modifies decision #2, the chain breaks at #3. This is your audit proof."

### Flow 4: "200 findings? Here are the 3 that matter" (2 min)

**Context**: You're showing how triage eliminates alert fatigue.

9. **Tab 6 — Triage Agent**
   - Click **Load Sample Findings**
   - Click **Triage All**
   
   > "We had 6 raw SAST findings. AgentShield looked at each one in context:"
   > - "SQL injection in production payment code, internet-facing, handles PII → **URGENT**"
   > - "Same SQL injection but in auth code, also production → **HIGH** (slightly less exposed)"
   > - "XSS in admin panel → **MEDIUM**"
   > - "Hardcoded secret in dev script, not deployed → **INFO** (correctly deprioritized)"
   
   > "A developer now knows exactly what to fix first. No more drowning in 200 identical 'HIGH' alerts."

10. Click on an URGENT finding to see remediation
    > "Each finding comes with step-by-step fix instructions and code examples."

### Flow 5: "One-click validation" (30 sec)

11. **Tab 7 — Test Cases** → Click **Run All 7 Tests**
    > "All 7 specification test cases pass. Context graph queries, verifier blocking, MCP security, rate limiting, chain integrity, SAST triage, and anomaly detection — all verified."

### Key Talking Points

| When Someone Asks | Your Answer |
|---|---|
| "Does this work with real GitHub?" | "Yes — set `GITHUB_TOKEN` and `demo_mode=False`. Same security guardrails, real GitHub API" |
| "Do you need an LLM?" | "No. All rules are deterministic. LLM is optional for enhancing ambiguous cases" |
| "What SAST scanners does it support?" | "Any scanner that outputs findings. JSON mapping for Semgrep/SonarQube included" |
| "Can this scale?" | "Graph swaps to Neo4j, signing moves to AWS KMS, MCP serves over HTTP. See DESIGN.md" |
| "How do you prevent false positives?" | "Context-aware rules: same change in test vs prod gets different treatment" |
| "What if a decision is tampered with?" | "HMAC-signed + hash-chained. Any tampering breaks the chain" |

---

## 7. Quick Reference: Commands

```bash
# ── Tests ──
python -m pytest tests/ -v                    # All 75 tests
python -m pytest tests/test_verifier.py -v    # Just verifier tests

# ── Streamlit Dashboard ──
streamlit run streamlit_app.py                # Default port 8501
streamlit run streamlit_app.py --server.port 8080  # Custom port

# ── CLI Demo ──
python examples/demo_script.py                # Terminal-based full demo

# ── Real Data Script ──
python real_data_demo.py                      # After you create it (see Section 3a)

# ── MCP Server (for real MCP protocol clients) ──
python -m src.mcp_server                      # Runs FastMCP on stdio

# ── Environment Variables ──
# .env file (project root):
GITHUB_TOKEN=github_pat_xxx                   # For real GitHub access
AWS_ACCESS_KEY_ID=xxx                         # For Bedrock LLM
AWS_SECRET_ACCESS_KEY=xxx
AZURE_OPENAI_API_KEY=xxx                      # For Azure LLM fallback
AGENTSHIELD_SIGNING_KEY=xxx                   # For HMAC signing (default provided)
```

---

## Summary: The Two Modes

### Demo Mode (what you have now)
```python
server = MCPSecurityServer(demo_mode=True)     # Fake GitHub data
verifier = VerifierAgent(graph, use_llm=False)  # Deterministic rules only
triage = TriageAgent(graph, use_llm=False)      # Template remediation
# → Works offline, no API keys, all 75 tests pass
```

### Real Mode (production-ready)
```python
server = MCPSecurityServer(demo_mode=False)     # Real GitHub API
verifier = VerifierAgent(graph, use_llm=True)   # LLM-enhanced reasoning
triage = TriageAgent(graph, use_llm=True)       # LLM-enhanced remediation
# → Needs GITHUB_TOKEN + (Bedrock or Azure keys) in .env
```

Everything else (context graph, integrity monitor, rules, path validation, rate limiting, scope guards, anomaly detection) works identically in both modes.
