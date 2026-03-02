"""
AgentShield Verifier Agent (Part 2)
Autonomous agent that validates other agents' security decisions.
Uses LangGraph StateGraph with Claude 3.5 Sonnet for nuanced reasoning.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Annotated, Any, Optional

from .context_graph import ContextGraph
from .models import (
    AgentEvent,
    EventType,
    FunctionCategory,
    VerificationDecision,
    VerificationResult,
    VerificationRule,
)
from .utils import (
    contains_security_logic,
    is_auth_file,
    is_credential_file,
    is_test_file,
)

logger = logging.getLogger("agentshield.verifier")

# ─────────────────────────────────────────────
# Verification Rules
# ─────────────────────────────────────────────

RULES = [
    VerificationRule(
        rule_id="RULE-001",
        name="No Security Logic Removal",
        description="No agent can remove security validation logic (verify, authenticate, validate, sanitize)",
        severity="CRITICAL",
    ),
    VerificationRule(
        rule_id="RULE-002",
        name="Untrusted Dependency Approval",
        description="Dependencies from untrusted sources require human approval",
        severity="HIGH",
    ),
    VerificationRule(
        rule_id="RULE-003",
        name="Auth Code Human Review",
        description="Authentication code changes require human review",
        severity="HIGH",
    ),
    VerificationRule(
        rule_id="RULE-004",
        name="No Credential Access",
        description="Agents cannot access credentials or API keys",
        severity="CRITICAL",
    ),
    VerificationRule(
        rule_id="RULE-005",
        name="PII Data Flow Analysis",
        description="Code that handles PII must pass data flow analysis",
        severity="HIGH",
    ),
]


# ─────────────────────────────────────────────
# Rule Check Functions
# ─────────────────────────────────────────────

def check_rule_001(event: AgentEvent, context: dict) -> Optional[dict]:
    """
    Rule 1: No agent can remove security validation logic.
    Context-aware: Removing verify() in test file = OK, in auth code = BLOCK.
    """
    if event.event_type != EventType.CODE_MODIFICATION:
        return None

    change_summary = event.details.get("change_summary", "")
    removed_code = event.details.get("removed_code", "")
    combined = f"{change_summary} {removed_code}".lower()

    # Check if security logic is being removed
    security_keywords = [
        "verify(", "authenticate(", "validate(", "sanitize(",
        "check_auth(", "require_auth(", "is_authenticated(",
        "check_permission(", "authorize(", "csrf_protect(",
        "remove security", "removed validation", "disabled auth",
        "bypass", "skip verification",
        "removed auth", "removed authentication", "disable security",
        "removed authorization", "removed csrf", "removed sanitiz",
    ]
    is_removing_security = any(kw in combined for kw in security_keywords)

    if not is_removing_security:
        return None

    # Context-aware: test file → OK
    if is_test_file(event.target_file):
        return {
            "rule_id": "RULE-001",
            "decision": VerificationDecision.ALLOW,
            "reasoning": (
                f"Security logic change detected in TEST file '{event.target_file}'. "
                "Test files may legitimately modify security stubs. ALLOWED."
            ),
            "risk_score": 0.1,
        }

    # Auth / production code → BLOCK
    file_context = context.get("file_data", {})
    function_cat = file_context.get(
        "function_category",
        FunctionCategory.GENERAL.value if not is_auth_file(event.target_file) else FunctionCategory.AUTH.value,
    )

    if function_cat in (FunctionCategory.AUTH.value, "auth", FunctionCategory.PAYMENT.value, "payment"):
        return {
            "rule_id": "RULE-001",
            "decision": VerificationDecision.BLOCK,
            "reasoning": (
                f"CRITICAL: Agent '{event.agent_id}' is removing security validation logic "
                f"from {function_cat} code '{event.target_file}'. "
                f"Detected removal: '{combined[:200]}'. "
                "This is a critical security violation — BLOCKED."
            ),
            "risk_score": 0.95,
        }

    # General code → WARN + human review
    return {
        "rule_id": "RULE-001",
        "decision": VerificationDecision.REQUIRE_HUMAN_REVIEW,
        "reasoning": (
            f"Agent '{event.agent_id}' is modifying security logic in '{event.target_file}'. "
            f"Change: '{combined[:200]}'. Requires human review."
        ),
        "risk_score": 0.7,
    }


def check_rule_002(event: AgentEvent, context: dict) -> Optional[dict]:
    """Rule 2: Dependencies from untrusted sources require approval."""
    if event.event_type != EventType.DEPENDENCY_ADDITION:
        return None

    source = event.details.get("source", "unknown")
    dep_name = event.details.get("dependency_name", event.target_file)
    is_trusted = event.details.get("is_trusted", source in ("pypi", "npm", "maven", "crates.io"))

    if is_trusted:
        return {
            "rule_id": "RULE-002",
            "decision": VerificationDecision.ALLOW,
            "reasoning": (
                f"Dependency '{dep_name}' from trusted source '{source}'. ALLOWED."
            ),
            "risk_score": 0.1,
        }

    return {
        "rule_id": "RULE-002",
        "decision": VerificationDecision.REQUIRE_HUMAN_REVIEW,
        "reasoning": (
            f"Dependency '{dep_name}' from UNTRUSTED source '{source}' "
            f"introduced by agent '{event.agent_id}'. "
            "Supply chain risk — requires human approval before installation."
        ),
        "risk_score": 0.8,
    }


def check_rule_003(event: AgentEvent, context: dict) -> Optional[dict]:
    """Rule 3: Authentication code changes require human review."""
    if event.event_type != EventType.CODE_MODIFICATION:
        return None

    if not is_auth_file(event.target_file):
        file_data = context.get("file_data", {})
        func_cat = file_data.get("function_category", "")
        if func_cat not in (FunctionCategory.AUTH.value, "auth"):
            return None

    return {
        "rule_id": "RULE-003",
        "decision": VerificationDecision.REQUIRE_HUMAN_REVIEW,
        "reasoning": (
            f"Agent '{event.agent_id}' is modifying authentication code "
            f"'{event.target_file}'. All auth code changes require human review. "
            f"Change summary: {event.details.get('change_summary', 'N/A')}"
        ),
        "risk_score": 0.6,
    }


def check_rule_004(event: AgentEvent, context: dict) -> Optional[dict]:
    """Rule 4: Agents cannot access credentials or API keys."""
    if event.event_type not in (
        EventType.FILE_ACCESS,
        EventType.CREDENTIAL_ACCESS,
        EventType.CODE_MODIFICATION,
    ):
        return None

    if not is_credential_file(event.target_file):
        return None

    return {
        "rule_id": "RULE-004",
        "decision": VerificationDecision.BLOCK,
        "reasoning": (
            f"BLOCKED: Agent '{event.agent_id}' attempted to access credential file "
            f"'{event.target_file}'. Agents are prohibited from accessing "
            "credentials or API keys. This is a critical security violation."
        ),
        "risk_score": 0.95,
    }


def check_rule_005(event: AgentEvent, context: dict) -> Optional[dict]:
    """Rule 5: Code that handles PII must pass data flow analysis."""
    if event.event_type != EventType.CODE_MODIFICATION:
        return None

    file_data = context.get("file_data", {})
    handles_pii = file_data.get("handles_pii", False)

    if not handles_pii:
        return None

    return {
        "rule_id": "RULE-005",
        "decision": VerificationDecision.WARN,
        "reasoning": (
            f"Agent '{event.agent_id}' is modifying PII-handling code "
            f"'{event.target_file}'. Data flow analysis required to ensure "
            "PII is not leaked or improperly handled."
        ),
        "risk_score": 0.5,
    }


RULE_CHECKS = [
    check_rule_001,
    check_rule_002,
    check_rule_003,
    check_rule_004,
    check_rule_005,
]


# ─────────────────────────────────────────────
# Verifier Agent (LangGraph-compatible)
# ─────────────────────────────────────────────

class VerifierAgent:
    """
    Autonomous Verifier Agent that validates agent actions against
    security rules, using the Context Graph for context-aware decisions.

    Workflow:
    1. Enrich context from the graph
    2. Apply deterministic rules
    3. (Optional) LLM reasoning for nuanced cases
    4. Produce VerificationResult
    """

    def __init__(self, context_graph: ContextGraph, use_llm: bool = False):
        self.graph = context_graph
        self.use_llm = use_llm
        self._llm = None

    def _get_llm(self):
        if self._llm is None and self.use_llm:
            from .utils import get_llm
            self._llm = get_llm()
        return self._llm

    def verify(self, event: AgentEvent) -> VerificationResult:
        """
        Main entry point: verify an agent event.
        Returns a VerificationResult with decision, reasoning, and context.
        """
        # Step 1: Enrich context
        context = self._enrich_context(event)

        # Step 2: Apply rules
        rule_results = self._apply_rules(event, context)

        # Step 3: Determine final decision
        result = self._synthesize_decision(event, context, rule_results)

        logger.info(
            "Verified event %s: decision=%s risk=%.2f rules_violated=%s",
            event.id, result.decision.value, result.risk_score, result.rules_violated,
        )
        return result

    def _enrich_context(self, event: AgentEvent) -> dict:
        """Gather context from the graph for the event."""
        context: dict[str, Any] = {}

        # Agent history
        agent_history = self.graph.get_agent_history(event.agent_id)
        context["agent_history"] = agent_history
        context["agent_action_count"] = len(agent_history)

        # Agent trust score
        agent_data = self.graph.get_node_data(event.agent_id)
        context["agent_data"] = agent_data or {}
        context["agent_trust_score"] = (agent_data or {}).get("trust_score", 0.5)

        # Target file data
        if event.target_file:
            file_data = self.graph.get_code_file_by_path(event.target_file)
            context["file_data"] = file_data or {}

            # Provenance
            provenance = self.graph.get_provenance(event.target_file)
            context["file_provenance"] = provenance

        # Check if agent has accessed credentials before
        cred_accesses = [
            a for a in agent_history
            if a.get("action_type") in (EventType.CREDENTIAL_ACCESS.value, "credential_access")
        ]
        context["has_accessed_credentials_before"] = len(cred_accesses) > 0

        return context

    def _apply_rules(self, event: AgentEvent, context: dict) -> list[dict]:
        """Apply all verification rules and collect results."""
        results = []
        for check_fn in RULE_CHECKS:
            result = check_fn(event, context)
            if result is not None:
                results.append(result)
        return results

    def _synthesize_decision(
        self,
        event: AgentEvent,
        context: dict,
        rule_results: list[dict],
    ) -> VerificationResult:
        """Combine rule results into a final VerificationResult."""
        if not rule_results:
            return VerificationResult(
                event_id=event.id,
                decision=VerificationDecision.ALLOW,
                reasoning=f"No rules triggered for event {event.event_type.value} on '{event.target_file}'. Action ALLOWED.",
                risk_score=0.0,
                rules_evaluated=[r.rule_id for r in RULES],
                rules_violated=[],
                confidence=1.0,
                context_used=self._summarize_context(context),
            )

        # Find the most severe result
        severity_order = {
            VerificationDecision.BLOCK: 4,
            VerificationDecision.REQUIRE_HUMAN_REVIEW: 3,
            VerificationDecision.WARN: 2,
            VerificationDecision.ALLOW: 1,
        }
        rule_results.sort(key=lambda r: severity_order.get(r["decision"], 0), reverse=True)
        most_severe = rule_results[0]

        # Aggregate reasoning
        all_reasoning = "\n".join(
            f"[{r['rule_id']}] {r['reasoning']}" for r in rule_results
        )

        violated = [
            r["rule_id"] for r in rule_results
            if r["decision"] in (VerificationDecision.BLOCK, VerificationDecision.REQUIRE_HUMAN_REVIEW, VerificationDecision.WARN)
        ]

        # LLM reasoning for nuanced cases
        llm_reasoning = ""
        if self.use_llm and most_severe["decision"] in (
            VerificationDecision.WARN, VerificationDecision.REQUIRE_HUMAN_REVIEW
        ):
            llm_reasoning = self._llm_reason(event, context, rule_results)

        final_reasoning = all_reasoning
        if llm_reasoning:
            final_reasoning += f"\n\n[LLM Analysis] {llm_reasoning}"

        return VerificationResult(
            event_id=event.id,
            decision=most_severe["decision"],
            reasoning=final_reasoning,
            risk_score=max(r["risk_score"] for r in rule_results),
            rules_evaluated=[r.rule_id for r in RULES],
            rules_violated=violated,
            confidence=0.9 if not llm_reasoning else 0.85,
            context_used=self._summarize_context(context),
        )

    def _llm_reason(
        self, event: AgentEvent, context: dict, rule_results: list[dict]
    ) -> str:
        """Use LLM for nuanced reasoning about the event."""
        llm = self._get_llm()
        if llm is None:
            return ""

        prompt = f"""You are a security verification agent. Analyze this agent action and provide reasoning.

Event:
- Agent: {event.agent_id}
- Action: {event.event_type.value}
- Target: {event.target_file}
- Details: {event.details}

Context:
- Agent trust score: {context.get('agent_trust_score', 'N/A')}
- Agent prior actions: {context.get('agent_action_count', 0)}
- Has accessed credentials before: {context.get('has_accessed_credentials_before', False)}
- File category: {context.get('file_data', {}).get('function_category', 'N/A')}

Rules triggered:
{chr(10).join(f"- {r['rule_id']}: {r['reasoning']}" for r in rule_results)}

Provide a concise security analysis (2-3 sentences) explaining:
1. Why this action is suspicious or safe
2. What additional context influenced your assessment
3. Your confidence level and recommendation
"""
        try:
            response = llm.invoke(prompt)
            return response.content if hasattr(response, 'content') else str(response)
        except Exception as e:
            logger.warning("LLM reasoning failed: %s", e)
            return ""

    def _summarize_context(self, context: dict) -> dict:
        """Create a JSON-safe summary of context used."""
        return {
            "agent_trust_score": context.get("agent_trust_score"),
            "agent_action_count": context.get("agent_action_count"),
            "has_accessed_credentials_before": context.get("has_accessed_credentials_before"),
            "file_category": (context.get("file_data") or {}).get("function_category"),
            "file_deployed": (context.get("file_data") or {}).get("is_deployed"),
        }


# ─────────────────────────────────────────────
# LangGraph Graph (optional, for advanced usage)
# ─────────────────────────────────────────────

def build_verifier_graph(context_graph: ContextGraph, use_llm: bool = False):
    """
    Build a LangGraph StateGraph for the verifier agent workflow.
    This provides the full stateful graph execution model.
    """
    try:
        from typing import TypedDict
        from langgraph.graph import StateGraph, START, END

        class VerifierState(TypedDict):
            event: dict
            context: dict
            rule_results: list
            verification_result: dict
            needs_human_review: bool

        verifier = VerifierAgent(context_graph, use_llm=use_llm)

        def enrich_context(state: VerifierState) -> dict:
            event = AgentEvent(**state["event"])
            context = verifier._enrich_context(event)
            return {"context": context}

        def apply_rules(state: VerifierState) -> dict:
            event = AgentEvent(**state["event"])
            context = state.get("context", {})
            results = verifier._apply_rules(event, context)
            needs_review = any(
                r["decision"] in (VerificationDecision.REQUIRE_HUMAN_REVIEW, VerificationDecision.BLOCK)
                for r in results
            )
            return {"rule_results": results, "needs_human_review": needs_review}

        def synthesize(state: VerifierState) -> dict:
            event = AgentEvent(**state["event"])
            context = state.get("context", {})
            rule_results = state.get("rule_results", [])
            result = verifier._synthesize_decision(event, context, rule_results)
            return {"verification_result": result.model_dump(mode="json")}

        def should_escalate(state: VerifierState) -> str:
            if state.get("needs_human_review", False):
                return "escalate"
            return "synthesize"

        def escalate(state: VerifierState) -> dict:
            """Mark for human review and synthesize."""
            event = AgentEvent(**state["event"])
            context = state.get("context", {})
            rule_results = state.get("rule_results", [])
            result = verifier._synthesize_decision(event, context, rule_results)
            return {"verification_result": result.model_dump(mode="json")}

        graph = StateGraph(VerifierState)
        graph.add_node("enrich_context", enrich_context)
        graph.add_node("apply_rules", apply_rules)
        graph.add_node("synthesize", synthesize)
        graph.add_node("escalate", escalate)

        graph.add_edge(START, "enrich_context")
        graph.add_edge("enrich_context", "apply_rules")
        graph.add_conditional_edges("apply_rules", should_escalate, {
            "escalate": "escalate",
            "synthesize": "synthesize",
        })
        graph.add_edge("synthesize", END)
        graph.add_edge("escalate", END)

        return graph.compile()

    except ImportError:
        logger.warning("LangGraph not installed. Using direct VerifierAgent instead.")
        return None
