# AgentShield — How to Test, Run Streamlit & Demo

Everything you need in one place.

---

## 1. Prerequisites

```
Python 3.10+
Git installed
Virtual environment already set up at ../.venv/
```

If you haven't installed dependencies yet:

```bash
cd agentshield
pip install -r requirements.txt
```

---

## 2. Run All Tests (pytest)

From within the `agentshield/` folder:

```bash
# Run all 75 tests with verbose output
python -m pytest tests/ -v

# Run a single test suite
python -m pytest tests/test_context_graph.py -v      # Part 1 — Context Graph (17 tests)
python -m pytest tests/test_verifier.py -v            # Part 2 — Verifier Agent (9 tests)
python -m pytest tests/test_mcp_security.py -v        # Part 3 — MCP Security (14 tests)
python -m pytest tests/test_integrity.py -v           # Part 4 — Integrity Monitor (16 tests)
python -m pytest tests/test_triage_agent.py -v        # Part 5 — Triage Agent (12 tests)

# Run a specific test function
python -m pytest tests/test_verifier.py::TestRule001::test_block_security_removal_in_prod -v
```

Expected output: **75 passed in ~1 second**. No cloud credentials or API keys needed — all tests run fully offline.

---

## 3. Push to Your Personal GitHub

### 3a. Create a new repo on GitHub

1. Go to https://github.com/new
2. Name it something like `AgentShield` or `CognitivTrust-Assignment`
3. Keep it **Public** or **Private** — your choice
4. Do NOT initialize with README (we already have one)
5. Click **Create repository**

### 3b. Initialize and push

Open a terminal in the **project root** (parent of `agentshield/`):

```bash
# Navigate to project root
cd C:\Users\JoshiJimil\Langgraph\CongnitivTrust-Assignment

# Initialize git (if not already done)
git init

# Create a root .gitignore so .env and .venv are excluded
echo .env > .gitignore
echo .venv/ >> .gitignore
echo __pycache__/ >> .gitignore

# Stage everything
git add agentshield/

# Commit
git commit -m "AgentShield: AI Agent Security Platform — all 5 parts"

# Add your GitHub remote (replace with YOUR repo URL)
git remote add origin https://github.com/YOUR_USERNAME/AgentShield.git

# Push
git branch -M main
git push -u origin main
```

### 3c. Verify on GitHub

After pushing, your repo should show:

```
agentshield/
├── src/                    # 11 source modules
│   ├── models.py
│   ├── utils.py
│   ├── context_graph.py
│   ├── verifier_agent.py
│   ├── mcp_server.py
│   ├── integrity_monitor.py
│   ├── exploitability_analyzer.py
│   ├── risk_calculator.py
│   ├── remediation_generator.py
│   ├── triage_agent.py
│   └── __init__.py
├── tests/                  # 5 test suites (75 tests)
├── examples/               # Demo data + demo script
├── streamlit_app.py        # Interactive dashboard
├── requirements.txt
├── README.md
├── DESIGN.md
└── HOW_TO_RUN.md
```

### 3d. Clone and test on a fresh machine

```bash
git clone https://github.com/YOUR_USERNAME/AgentShield.git
cd AgentShield/agentshield
python -m venv .venv
.venv\Scripts\activate          # Windows
pip install -r requirements.txt
python -m pytest tests/ -v      # Should see 75 passed
```

---

## 4. Run the Streamlit Dashboard

```bash
cd agentshield
streamlit run streamlit_app.py
```

This opens a browser at **http://localhost:8501** with 7 interactive tabs:

### Tab 1 — Overview
- System architecture diagram
- Component status cards
- Quick stats (nodes, edges, events in the graph)

### Tab 2 — Context Graph Explorer
- **Load sample data** button populates the graph with agents, files, vulnerabilities, and runtime contexts
- Run any of the 7 graph queries interactively:
  - Files accessed by a specific agent
  - Agents modifying authentication code
  - Blast radius of a vulnerability
  - Dependencies introduced by AI-generated code
  - Production vulnerabilities above a severity threshold
  - Runtime context for a vulnerability
  - File provenance (who changed it and when)
- View raw graph statistics (node/edge counts by type)

### Tab 3 — Verifier Agent
- Create custom agent events (pick event type, target file, details)
- Click **Verify** to see the ALLOW / BLOCK / ESCALATE decision
- Shows which rules fired, confidence score, and full reasoning
- Try these scenarios:
  - Target: `src/auth/controller.py` with change_summary "removed authentication" → **BLOCK**
  - Target: `tests/test_auth.py` with same summary → **ALLOW**
  - Target: `.env.production` with event type FILE_ACCESS → **BLOCK**

### Tab 4 — MCP Security
- **Path Validator**: Type a file path to test (try `../../etc/passwd` → blocked, `src/main.py` → allowed)
- **Rate Limiter**: Simulate rapid requests and see when the limit kicks in
- **Scope Guard**: Register agents with repos/branches, then test access
- **Read File / List Commits / PRs**: Demo-mode tools with synthetic data

### Tab 5 — Integrity Monitor
- Record agent decisions and see them signed + chained
- Verify the full decision chain (detects tampering)
- Check for behavioral anomalies
- Register and verify agent identities

### Tab 6 — Triage Agent
- Load sample SAST findings or create custom ones
- Run single-finding or batch triage
- See exploitability score, risk priority, and remediation guidance
- Results sorted by priority (URGENT first)

### Tab 7 — Run All 7 Test Cases
- One-click button runs all 7 specification test cases
- Shows pass/fail with detailed output for each:
  1. Context Graph queries
  2. Agent modifies auth code → BLOCK
  3. Path traversal attack → denied
  4. Rate limiting enforcement
  5. Decision chain integrity
  6. SAST triage with prioritization
  7. Anomaly detection

### Streamlit Tips
- Use `Ctrl+C` in terminal to stop the server
- The dashboard works **fully offline** — no API keys needed
- If you get an import error, make sure you're running from the `agentshield/` folder
- To change the port: `streamlit run streamlit_app.py --server.port 8080`

---

## 5. Run the CLI Demo Script

For a non-interactive, terminal-based demo:

```bash
cd agentshield
python examples/demo_script.py
```

This runs all 7 test cases end-to-end and prints formatted results with pass/fail status. Great for quick validation or recording a demo session.

---

## 6. Demo Walkthrough (Suggested Script)

If you're presenting this to someone, here's a recommended flow:

### Step 1: Show the Tests Pass (30 seconds)

```bash
python -m pytest tests/ -v
```

> "All 75 tests pass across 5 suites — context graph, verifier agent, MCP security, integrity monitoring, and vulnerability triage."

### Step 2: Launch Streamlit (1 minute)

```bash
streamlit run streamlit_app.py
```

> "Here's the interactive dashboard. Let me walk through each component."

### Step 3: Context Graph (2 minutes)

- Click **Tab 2 — Context Graph**
- Click **Load Sample Data**
- Run "Files accessed by agent" → shows agent_copilot's file history
- Run "Blast radius" → shows how one vulnerability cascades through dependencies
- Run "Agents modifying auth code" → identifies risky agent behavior

> "The context graph tracks every agent, file, vulnerability, and their relationships. We can query it to answer security questions like 'which agents touched authentication code?'"

### Step 4: Verifier Agent (2 minutes)

- Click **Tab 3 — Verifier Agent**
- Create event: agent modifies `src/auth/controller.py`, summary = "removed authentication check"
- Click Verify → **BLOCK**
- Change target to `tests/test_auth.py` → **ALLOW**

> "The verifier uses 5 deterministic rules with context-aware logic. Same change is blocked in production auth code but allowed in test files — no false positives."

### Step 5: MCP Security (1 minute)

- Click **Tab 4 — MCP Security**
- Type `../../etc/passwd` in Path Validator → **BLOCKED**
- Type `src/main.py` → **ALLOWED**
- Show rate limiter hitting the limit after rapid clicks

> "Every tool call goes through path validation, rate limiting, and scope guards. All logged for audit."

### Step 6: Integrity Monitor (1 minute)

- Click **Tab 5 — Integrity**
- Record a few decisions
- Verify chain → **Valid**

> "Every agent decision is cryptographically signed with HMAC-SHA256 and hash-chained. If anyone tampers with a decision, the chain verification catches it."

### Step 7: Triage Agent (2 minutes)

- Click **Tab 6 — Triage**
- Load sample findings
- Run batch triage
- Show SQL injection in production → **URGENT** vs hardcoded secret in dev → **INFO**

> "Raw SAST findings get transformed into prioritized, actionable remediations. A critical SQL injection in production + internet-facing code gets URGENT priority, while a secret in a dev script is properly deprioritized."

### Step 8: All-in-One Test Cases (30 seconds)

- Click **Tab 7 — Test Cases**
- Click **Run All 7 Tests** → all green

> "And here are all 7 specification test cases passing in one click."

---

## 7. Troubleshooting

| Issue | Fix |
|---|---|
| `ModuleNotFoundError: No module named 'src'` | Make sure you're in the `agentshield/` directory |
| `streamlit: command not found` | Run `pip install streamlit` or use `python -m streamlit run streamlit_app.py` |
| Tests fail with import errors | Run `pip install -r requirements.txt` |
| Port 8501 already in use | Use `streamlit run streamlit_app.py --server.port 8080` |
| Git push rejected | Make sure the remote repo is empty (no README/LICENSE initialized) |

---

## 8. Project Tech Stack Summary

| Component | Technology |
|---|---|
| Context Graph | NetworkX MultiDiGraph |
| Verifier Agent | LangGraph StateGraph + 5 deterministic rules |
| MCP Server | Official `mcp` SDK (FastMCP pattern) |
| Integrity | HMAC-SHA256 signing + hash chain |
| Triage | Exploitability scoring + template remediation |
| LLM (optional) | AWS Bedrock Claude 3.5 Sonnet v2 / Azure OpenAI GPT-4.1-mini |
| Dashboard | Streamlit (7 tabs) |
| Testing | pytest (75 tests) |
| Models | Pydantic v2 |
