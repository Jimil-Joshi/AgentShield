"""
AgentShield Triage Agent (Part 5)
Autonomous vulnerability triage agent using LangGraph.
Combines SAST findings + runtime context → intelligent prioritization.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Annotated, Any, Optional

from .context_graph import ContextGraph
from .exploitability_analyzer import ExploitabilityAnalyzer
from .models import (
    ExploitabilityAssessment,
    RemediationGuidance,
    SASTFinding,
    SASTSeverity,
    TriagePriority,
    TriageResult,
    VulnType,
)
from .remediation_generator import RemediationGenerator
from .risk_calculator import RiskCalculator

logger = logging.getLogger("agentshield.triage")


class TriageAgent:
    """
    Autonomous vulnerability triage agent.
    Orchestrates: exploitability analysis → risk calculation → remediation.
    Uses context graph for runtime context enrichment.
    """

    def __init__(
        self,
        context_graph: ContextGraph,
        use_llm: bool = False,
    ):
        self.graph = context_graph
        self.exploitability_analyzer = ExploitabilityAnalyzer()
        self.risk_calculator = RiskCalculator()
        self.remediation_generator = RemediationGenerator(use_llm=use_llm)
        self.use_llm = use_llm
        self._llm = None

    def triage_finding(self, finding: SASTFinding) -> TriageResult:
        """
        Triage a single SAST finding.
        Gathers runtime context, analyzes exploitability, calculates risk,
        generates remediation.
        """
        logger.info("Triaging finding %s: %s in %s", finding.id, finding.vuln_type.value, finding.file_path)

        # Step 1: Gather runtime context
        runtime_context = self._gather_runtime_context(finding)
        code_context = self._gather_code_context(finding)

        # Step 2: Analyze exploitability
        exploitability = self.exploitability_analyzer.analyze(
            finding, runtime_context, code_context,
        )

        # Step 3: Calculate risk & priority
        priority, risk_score, risk_reasoning = self.risk_calculator.calculate(
            exploitability, finding, code_context,
        )

        # Step 4: Generate remediation
        remediation = self.remediation_generator.generate(
            finding, priority, code_context,
        )

        # Step 5: Synthesize reasoning
        reasoning = self._synthesize_reasoning(
            finding, exploitability, priority, risk_score,
            risk_reasoning, runtime_context, code_context,
        )

        result = TriageResult(
            finding_id=finding.id,
            original_severity=finding.severity,
            final_priority=priority,
            exploitability=exploitability,
            business_risk_score=risk_score,
            reasoning=reasoning,
            remediation=remediation,
            runtime_context_used={
                "runtime": runtime_context or {},
                "code": {k: v for k, v in (code_context or {}).items() if k != "node_type"},
            },
        )

        logger.info(
            "Triage complete: %s → %s (was %s), exploitability=%.2f, risk=%.2f",
            finding.id, priority.value, finding.severity.value,
            exploitability.score, risk_score,
        )

        return result

    def triage_all(self, findings: list[SASTFinding]) -> list[TriageResult]:
        """Triage all SAST findings and return sorted results."""
        results = [self.triage_finding(f) for f in findings]

        # Sort by priority (URGENT first) then by risk score (highest first)
        priority_order = {
            TriagePriority.URGENT: 5,
            TriagePriority.HIGH: 4,
            TriagePriority.MEDIUM: 3,
            TriagePriority.LOW: 2,
            TriagePriority.INFO: 1,
        }
        results.sort(
            key=lambda r: (priority_order.get(r.final_priority, 0), r.business_risk_score),
            reverse=True,
        )
        return results

    def _gather_runtime_context(self, finding: SASTFinding) -> Optional[dict]:
        """Get runtime context for the finding's file from the context graph."""
        # Try direct file lookup
        ctx = self.graph.get_runtime_context_for_file(finding.file_path)
        if ctx:
            return ctx

        # Try via vulnerability node
        for nid, data in self.graph.graph.nodes(data=True):
            if (
                data.get("node_type") == "Vulnerability"
                and data.get("file_path") == finding.file_path
            ):
                ctx = self.graph.get_runtime_context_for_vulnerability(nid)
                if ctx:
                    return ctx

        return None

    def _gather_code_context(self, finding: SASTFinding) -> Optional[dict]:
        """Get code file context from the context graph."""
        return self.graph.get_code_file_by_path(finding.file_path)

    def _synthesize_reasoning(
        self,
        finding: SASTFinding,
        exploitability: ExploitabilityAssessment,
        priority: TriagePriority,
        risk_score: float,
        risk_reasoning: str,
        runtime_context: Optional[dict],
        code_context: Optional[dict],
    ) -> str:
        """Generate human-readable reasoning for the triage decision."""
        lines = [
            f"═══ Triage Analysis for {finding.vuln_type.value.upper()} ═══",
            f"File: {finding.file_path}:{finding.line_number}",
            f"CWE: {finding.cwe_id or 'N/A'}",
            "",
            f"Original SAST Severity: {finding.severity.value}",
            f"Final Priority: {priority.value}",
            f"Exploitability Score: {exploitability.score:.2f}/1.00",
            f"Business Risk Score: {risk_score:.2f}/1.00",
            "",
            "── Exploitability Factors ──",
        ]

        for factor in exploitability.factors:
            lines.append(f"  • {factor}")

        lines.extend([
            "",
            "── Risk Assessment ──",
            risk_reasoning,
            "",
            "── Runtime Context ──",
        ])

        if runtime_context:
            lines.append(f"  Environment: {runtime_context.get('environment', 'unknown')}")
            lines.append(f"  Deployed: {runtime_context.get('is_deployed', 'unknown')}")
            lines.append(f"  Internet-facing: {runtime_context.get('is_internet_facing', 'unknown')}")
            lines.append(f"  Handles PII: {runtime_context.get('handles_pii', 'unknown')}")
            lines.append(f"  Has Auth: {runtime_context.get('has_auth', 'unknown')}")
            if runtime_context.get('recently_modified_by_ai'):
                lines.append("  ⚠ Recently modified by AI agent")
        else:
            lines.append("  No runtime context available — using code-level analysis only")

        if code_context:
            lines.extend([
                "",
                "── Code Context ──",
                f"  Function category: {code_context.get('function_category', 'unknown')}",
                f"  Language: {code_context.get('language', 'unknown')}",
                f"  Deployed: {code_context.get('is_deployed', 'unknown')}",
            ])

        return "\n".join(lines)


# ─────────────────────────────────────────────
# LangGraph Graph (full stateful workflow)
# ─────────────────────────────────────────────

def build_triage_graph(context_graph: ContextGraph, use_llm: bool = False):
    """
    Build a LangGraph StateGraph for the triage agent workflow.
    Processes SAST findings one-by-one through the triage pipeline.
    """
    try:
        from typing import TypedDict
        from langgraph.graph import StateGraph, START, END

        class TriageState(TypedDict):
            findings: list  # list of SASTFinding dicts
            current_index: int
            triage_results: list  # list of TriageResult dicts
            context_graph_ref: str  # placeholder, graph passed via closure

        agent = TriageAgent(context_graph, use_llm=use_llm)

        def ingest_findings(state: TriageState) -> dict:
            """Validate and prepare findings."""
            findings = state.get("findings", [])
            validated = []
            for f in findings:
                if isinstance(f, dict):
                    validated.append(f)
                elif isinstance(f, SASTFinding):
                    validated.append(f.model_dump(mode="json"))
            return {"findings": validated, "current_index": 0, "triage_results": []}

        def process_finding(state: TriageState) -> dict:
            """Process the current finding through the full triage pipeline."""
            findings = state["findings"]
            idx = state.get("current_index", 0)

            if idx >= len(findings):
                return {}

            finding_data = findings[idx]
            finding = SASTFinding(**finding_data) if isinstance(finding_data, dict) else finding_data

            result = agent.triage_finding(finding)
            results = state.get("triage_results", [])
            results.append(result.model_dump(mode="json"))

            return {"triage_results": results, "current_index": idx + 1}

        def should_continue(state: TriageState) -> str:
            idx = state.get("current_index", 0)
            findings = state.get("findings", [])
            if idx < len(findings):
                return "process"
            return "done"

        graph = StateGraph(TriageState)
        graph.add_node("ingest", ingest_findings)
        graph.add_node("process", process_finding)

        graph.add_edge(START, "ingest")
        graph.add_edge("ingest", "process")
        graph.add_conditional_edges("process", should_continue, {
            "process": "process",
            "done": END,
        })

        return graph.compile()

    except ImportError:
        logger.warning("LangGraph not installed. Using direct TriageAgent instead.")
        return None
