# AgentShield — Architecture & Design Document

## Table of Contents

1. [Design Philosophy](#design-philosophy)
2. [System Architecture](#system-architecture)
3. [Part 1 — Context Graph](#part-1--context-graph)
4. [Part 2 — Autonomous Verifier Agent](#part-2--autonomous-verifier-agent)
5. [Part 3 — MCP Security Infrastructure](#part-3--mcp-security-infrastructure)
6. [Part 4 — Agent Supply Chain Integrity](#part-4--agent-supply-chain-integrity)
7. [Part 5 — Autonomous Vulnerability Triage](#part-5--autonomous-vulnerability-triage)
8. [LLM Integration Strategy](#llm-integration-strategy)
9. [Data Flow & Interactions](#data-flow--interactions)
10. [Security Model](#security-model)
11. [Production Deployment Considerations](#production-deployment-considerations)

---

## Design Philosophy

AgentShield is built around four core principles:

| Principle | Implementation |
|---|---|
| **Defense in Depth** | Every layer (graph, verifier, MCP, integrity, triage) independently validates security constraints |
| **Deterministic First** | All rule-based checks run without LLM; AI is an *optional enhancer*, not a requirement |
| **Auditability** | Every decision is signed, chained, and traceable via cryptographic integrity proofs |
| **Minimal Trust** | Agents are treated as untrusted by default; scope, rate, and path are all constrained |

---

## System Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        Streamlit Dashboard                       │
│  (Overview · Graph · Verifier · MCP · Integrity · Triage · Tests)│
└────────────────────────────┬─────────────────────────────────────┘
                             │ calls
┌────────────────────────────▼─────────────────────────────────────┐
│                      AgentShield Core (Python)                   │
│                                                                  │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────────┐ │
│  │ Context   │  │ Verifier │  │   MCP    │  │    Integrity     │ │
│  │  Graph    │◄─┤  Agent   │  │ Security │  │    Monitor       │ │
│  │ (Part 1)  │  │ (Part 2) │  │ (Part 3) │  │    (Part 4)      │ │
│  └──────┬───┘  └────┬─────┘  └────┬─────┘  └───────┬──────────┘ │
│         │           │              │                │            │
│         └───────────┴──────┬───────┴────────────────┘            │
│                            │                                     │
│                   ┌────────▼────────┐                            │
│                   │  Triage Agent   │                            │
│                   │    (Part 5)     │                            │
│                   └─────────────────┘                            │
└──────────────────────────────────────────────────────────────────┘
         │                                          │
   ┌─────▼──────┐                          ┌────────▼────────┐
   │ AWS Bedrock │  (fallback)             │  Azure OpenAI   │
   │ Claude 3.5  │◄────────────────────────│  GPT-4.1-mini   │
   │  Sonnet v2  │                         │                 │
   └─────────────┘                         └─────────────────┘
```

---

## Part 1 — Context Graph

### Goal

Maintain a living, queryable knowledge graph of every entity in the AI-assisted development pipeline — agents, files, vulnerabilities, runtime contexts, and the relationships between them.

### Data Model

```
Node Types:
  agent          │ identity, role, trust_level
  code_file      │ path, language, function_category, AI-generated flag
  vulnerability  │ SAST finding details, severity, vuln_type
  runtime_context│ deployment status, internet-facing, PII flags
  event          │ agent actions recorded as timestamped nodes
  dependency     │ third-party packages agents introduce

Edge Types:
  ACCESSED / MODIFIED / GENERATED / DEPENDS_ON / AFFECTS /
  HAS_VULNERABILITY / HAS_RUNTIME_CONTEXT / TRIGGERED / REVIEWED
```

### Technology Choice — NetworkX `MultiDiGraph`

| Consideration | Decision |
|---|---|
| Persistence | In-memory (demo scope); serializable via `to_dict()` / `from_dict()` |
| Multi-edges | MultiDiGraph supports multiple typed edges between the same pair |
| Query complexity | BFS/DFS built-in; blast-radius = `nx.descendants()` |
| Production path | Swap to Neo4j by implementing same interface over Bolt driver |

### Key Queries (7 implemented)

| # | Query | Algorithm |
|---|---|---|
| 1 | Files accessed by agent | Single-hop neighbor filter on edge type |
| 2 | Agents modifying auth code | Filter `code_file` nodes by `function_category`, traverse `MODIFIED` edges |
| 3 | Blast radius of vulnerability | `nx.descendants()` over dependency/affects edges |
| 4 | Dependencies from AI-generated code | Two-hop: AI code_file → DEPENDS_ON → dependency |
| 5 | Production vulnerabilities | Filter vulnerability nodes by severity + runtime context `deployed_to_production` |
| 6 | Runtime context for vulnerability | Traverse `HAS_RUNTIME_CONTEXT` from SAST → file → runtime |
| 7 | Runtime context for file | Direct edge traversal |

### Serialization

`to_dict()` exports nodes (with attributes) and edges as plain dicts; `from_dict()` rebuilds. This enables JSON persistence, snapshot comparison, and Streamlit display.

---

## Part 2 — Autonomous Verifier Agent

### Goal

Intercept every agent action (file modification, dependency addition, credential access) and autonomously decide **ALLOW / BLOCK / ESCALATE** using a layered rule engine, optionally enhanced by LLM reasoning.

### Architecture — LangGraph StateGraph

```
START ──► enrich_context ──► evaluate_rules ──► [llm_review?] ──► make_decision ──► END
                                                     │
                                          (only if use_llm=True
                                           AND rules are ambiguous)
```

**Why LangGraph?** The verifier is naturally a stateful, multi-step workflow:
1. Context enrichment reads the graph and builds a contextual dict.
2. Rule evaluation runs 5 deterministic rules in sequence.
3. LLM review (optional) provides nuanced reasoning for edge cases.
4. Final decision aggregates all signals.

The `TypedDict`-based state avoids Pydantic reducer conflicts with LangGraph's internal channeling.

### Rule Engine

| Rule | Trigger | Decision |
|---|---|---|
| **001** — AI code in production | `code_file` with `ai_generated=True` targets production & not test file | BLOCK |
| **002** — Untrusted dependency | Agent adds dep with `trusted=False` | BLOCK |
| **003** — Auth code modification | Agent modifies file with `function_category ∈ {AUTHENTICATION, AUTHORIZATION}` | ESCALATE |
| **004** — Credential access | Event targets credential/secret file patterns | BLOCK |
| **005** — PII exposure | Runtime context shows PII and internet-facing | ESCALATE |

Each rule function returns a `dict` with `rule`, `decision`, `reasoning` — or `None` if the rule does not apply. Test files are explicitly allowed by Rule 001 to avoid false positives.

### Confidence Score

```
confidence = base_confidence × (0.9 ^ ambiguous_count)
```

Multiple ESCALATE signals reduce confidence, signaling that human review is warranted.

---

## Part 3 — MCP Security Infrastructure

### Goal

Wrap all tool access through a **Model Context Protocol** server that enforces path validation, rate limiting, scope guards, and full audit logging — so agents can only perform sanctioned operations.

### Component Stack

```
┌─────────────────┐
│   FastMCP Server │  ← @mcp.tool() decorators
├─────────────────┤
│   AuditLogger   │  ← logs every MCPToolCall
├─────────────────┤
│   ScopeGuard    │  ← repo/branch whitelist per agent
├─────────────────┤
│   RateLimiter   │  ← sliding-window per agent_id
├─────────────────┤
│  PathValidator  │  ← regex blocklist for traversal attacks
└─────────────────┘
```

### PathValidator

Blocks 6 attack patterns via compiled regex:
- `..` directory traversal
- Absolute paths (`/etc/`, `C:\`)
- Hidden files (`.env`, `.git/`)
- `/proc`, `/sys` filesystem access
- Null bytes
- Home directory references (`~/`)

Returns `tuple[bool, str]` — boolean validity + human-readable reason.

### RateLimiter

Sliding-window algorithm: maintains a deque of timestamps per agent. On each `check()`, prunes entries older than 60 seconds, then compares count against `max_per_minute`.

### ScopeGuard

Agents must be **pre-registered** with an `AgentRegistryEntry` specifying `allowed_repos` and `allowed_branches`. Any unregistered agent or out-of-scope access is denied.

### Audit Trail

Every tool invocation is captured as an `MCPToolCall` (Pydantic model) with:
- `tool_name`, `agent_id`, `arguments`
- `timestamp`, `allowed` (bool), `denial_reason` (if blocked)

The audit log is append-only and queryable for compliance.

### Demo Mode

When `demo_mode=True`, the server returns synthetic data (files, commits, PRs) for the `"api-backend"` repository. This enables full end-to-end demonstration without any real GitHub/VCS connectivity.

---

## Part 4 — Agent Supply Chain Integrity

### Goal

Ensure that every decision an agent makes is **cryptographically signed**, **tamper-detectable** via hash chains, and **anomaly-monitored** against behavioral baselines — establishing a verifiable provenance trail.

### Cryptographic Signing

```
HMAC-SHA256(
    key = AGENTSHIELD_SIGNING_KEY (env var),
    message = canonical_json(payload)
)
```

**Design decision**: The signing key is loaded from the environment at module level, not passed as a constructor argument. This:
1. Prevents accidental key leakage through object serialization.
2. Follows 12-factor app principles (config via environment).
3. Keeps function signatures clean: `sign_payload(payload)`, `verify_signature(payload, signature)`.

### Decision Trace Chain

```
Entry_0: hash(payload_0)
Entry_1: hash(payload_1 + prev_hash_0)
Entry_2: hash(payload_2 + prev_hash_1)
   ...
```

`DecisionTraceStore.verify_chain()` walks the chain and checks that each `previous_hash` matches the actual hash of the preceding entry. Returns `tuple[bool, list[str]]` — validity flag and list of integrity issues found.

### Anomaly Detection

`AnomalyDetector` builds per-agent behavioral baselines from the Context Graph:
- **Action frequency** — how many events per hour is typical for this agent?
- **Target diversity** — how many unique files does the agent normally touch?
- **Scope patterns** — does the agent usually work in specific directories?

An anomaly is flagged when:
- Burst: current window has >2× the baseline event rate
- Scope deviation: agent accesses previously-unseen directories
- Privilege escalation patterns detected

Returns `Optional[AnomalyAlert]` with severity and explanation.

### Identity Verification

`IdentityVerifier` maintains agent fingerprints (could be API key hashes, certificate fingerprints, etc.). Agents must be registered before their identity can be verified. Unregistered agents are always rejected.

### IntegrityMonitor — Unified Facade

`IntegrityMonitor(context_graph)` composes all four subsystems:

```python
monitor.record_decision(agent_id, action, inputs, reasoning, output)
  → signs + chains + logs

monitor.check_action(agent_id, action_type, target, details)
  → anomaly detection against baseline

monitor.verify_identity(agent_id, fingerprint)
  → identity check

monitor.verify_chain()
  → full chain integrity audit
```

---

## Part 5 — Autonomous Vulnerability Triage

### Goal

Transform raw SAST findings into **prioritized, actionable remediation plans** by combining exploitability analysis, business-risk scoring, and contextual remediation generation — reducing alert fatigue and focusing developer effort.

### Pipeline Architecture (LangGraph)

```
START ──► analyze_exploitability ──► calculate_risk ──► generate_remediation ──► END
```

Each stage enriches the state dict, which flows through the graph. The TriageAgent internally fetches runtime and code context from the Context Graph, so callers only need to pass the SAST finding.

### Exploitability Scoring

Weighted multi-factor analysis:

| Factor | Weight | Source |
|---|---|---|
| Deployed to production | 0.30 | Runtime context |
| Internet-facing | 0.20 | Runtime context |
| Handles PII | 0.10 | Runtime context |
| Auth-related | 0.10 | Runtime context |
| SAST severity | 0.15 | Finding |
| Vulnerability type | 0.15 | Finding |

**Multipliers:**
- Test/development file → 0.1× (dramatic reduction)
- Auth/payment code → 1.3× (boost)
- AI-modified code → 1.15× (slight boost for AI trust gap)

Score is clamped to `[0.0, 1.0]`.

### Risk Calculation

```
risk_score = exploitability_score    (from analyzer)
```

Priority thresholds:
| Score Range | Priority |
|---|---|
| ≥ 0.85 | URGENT |
| ≥ 0.65 | HIGH |
| ≥ 0.40 | MEDIUM |
| ≥ 0.20 | LOW |
| < 0.20 | INFO |

Returns `tuple[TriagePriority, float, str]` — priority enum, numeric score, human reasoning.

### Remediation Generation

Template-based engine covering 9 vulnerability types:
- SQL Injection, XSS, Command Injection
- Path Traversal, SSRF, Insecure Deserialization
- Hardcoded Secrets, Broken Authentication
- Default fallback template

Each template provides:
- `description` — what the vulnerability is
- `fix_steps` — ordered list of concrete remediation actions
- `code_example` — before/after code snippets
- `references` — links to OWASP, CWE, etc.
- `estimated_effort` — LOW / MEDIUM / HIGH

When `use_llm=True`, an LLM call enhances the remediation with context-specific advice.

### Batch Triage

`triage_all(findings)` processes a list of findings and returns results sorted by priority (URGENT first), enabling security teams to focus on what matters most.

---

## LLM Integration Strategy

### Dual-Provider Architecture

```
Primary:   AWS Bedrock — Claude 3.5 Sonnet v2
           (anthropic.claude-3-5-sonnet-20241022-v2:0, us-west-2)

Fallback:  Azure OpenAI — GPT-4.1-mini
           (deployment: gpt-4.1-mini, endpoint: SanerAI.openai.azure.com)
```

### Graceful Degradation

```python
def get_llm():
    try:
        return ChatBedrock(...)       # Primary
    except Exception:
        try:
            return AzureChatOpenAI(...)  # Fallback
        except Exception:
            return None               # LLM unavailable — deterministic mode
```

**Every component works WITHOUT an LLM.** The `use_llm=False` default ensures:
- Tests pass without cloud credentials
- Demo mode works offline
- Deterministic behavior for reproducibility
- LLM enhances but never gates functionality

---

## Data Flow & Interactions

### Typical End-to-End Flow

```
1. Agent event arrives (e.g., "agent-copilot modifies auth.py")
        │
2. Context Graph ingests event → creates/updates nodes & edges
        │
3. Verifier Agent queries graph for context → runs 5 rules
        │
      ┌─┤ ALLOW → action proceeds
      │ │ ESCALATE → logged + human notified
      │ └ BLOCK → action rejected
      │
4. If action involves MCP tools:
      │  └→ MCP Server validates path, rate, scope → audit logs
      │
5. Integrity Monitor records decision → signs + chains
      │  └→ Anomaly detector checks behavioral baseline
      │
6. Periodically, SAST findings arrive
      └→ Triage Agent scores, prioritizes, generates remediation
```

### Cross-Component Dependencies

| Component | Depends On |
|---|---|
| Verifier Agent | Context Graph (for context enrichment) |
| MCP Security Server | Standalone (no graph dependency) |
| Integrity Monitor | Context Graph (for anomaly baselines) |
| Triage Agent | Context Graph (for runtime/code context) |
| Streamlit Dashboard | All components |

---

## Security Model

### Threat Model

| Threat | Mitigation |
|---|---|
| Agent reads sensitive files | PathValidator blocks traversal; ScopeGuard limits repos |
| Agent floods API | RateLimiter enforces per-agent sliding window |
| Agent escalates privileges | ScopeGuard + VerifierAgent Rule 004 |
| Agent introduces backdoor via dependency | VerifierAgent Rule 002 blocks untrusted deps |
| Decision tampering | HMAC-SHA256 signing + hash chain verification |
| Agent impersonation | IdentityVerifier fingerprint matching |
| Behavioral drift | AnomalyDetector flags deviations from baseline |
| AI code in production without review | VerifierAgent Rule 001 blocks unreviewed AI code |

### Trust Boundaries

```
UNTRUSTED          │  ENFORCED          │  TRUSTED
                   │                    │
Agent actions ────►│ Verifier + MCP ───►│ Approved operations
SAST findings ────►│ Triage ───────────►│ Prioritized alerts
                   │ Integrity signing  │ Verified decisions
```

---

## Production Deployment Considerations

### Database Migration Path

The current NetworkX in-memory graph is suitable for prototyping. For production:

```
NetworkX (current)  →  Neo4j / Amazon Neptune
Dict audit logs     →  PostgreSQL / DynamoDB
In-memory baselines →  Redis / ElastiCache
Decision traces     →  Immutable append-only store (S3 + DynamoDB)
```

### Scalability

| Component | Current | Production |
|---|---|---|
| Context Graph | In-memory NetworkX | Neo4j cluster with read replicas |
| MCP Server | Single-process FastMCP | MCP over SSE/HTTP with load balancer |
| Integrity signing | Module-level key | AWS KMS / HashiCorp Vault |
| Anomaly detection | Threshold-based | ML model (Isolation Forest / Autoencoder) |
| Triage | Template-based | Fine-tuned LLM with RAG over vulnerability DB |

### Observability

- **Structured logging**: Every component logs JSON-structured events
- **Audit trail**: MCP AuditLogger captures all tool invocations
- **Decision traces**: Cryptographically chained for forensic analysis
- **Anomaly alerts**: Real-time alerting on behavioral deviations

### Configuration Management

All secrets are managed via environment variables (12-factor):
- `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` — Bedrock
- `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT` — Azure fallback
- `AGENTSHIELD_SIGNING_KEY` — HMAC signing (default provided for demo)

---

## Design Tradeoffs

| Decision | Rationale | Alternative Considered |
|---|---|---|
| NetworkX over Neo4j | Zero infrastructure for demo; same interface upgradeable | Neo4j requires server setup |
| TypedDict for LangGraph state | Avoids Pydantic reducer conflicts | Pydantic models (caused state channel errors) |
| HMAC-SHA256 over RSA | Symmetric signing is simpler for single-system demo | Asymmetric signing for multi-party verification |
| Template remediation over pure LLM | Deterministic, fast, works offline | Pure LLM (slower, requires credentials, non-deterministic) |
| Tuple returns over result objects | Lighter-weight for validation functions | Custom result classes (more code, same info) |
| Demo mode built-in | Enables full showcase without real VCS/GitHub | Separate mock server (more complexity) |
| `use_llm=False` default | Tests and demos work without cloud credentials | Always-on LLM (fragile, slow, costly) |

---

*Document version: 1.0 — Generated as part of AgentShield implementation*
