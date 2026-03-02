"""
AgentShield Risk Calculator (Part 5 sub-component)
Combines exploitability with business impact to determine priority.
"""

from __future__ import annotations

import logging
from typing import Optional

from .models import (
    ExploitabilityAssessment,
    FunctionCategory,
    SASTFinding,
    SASTSeverity,
    TriagePriority,
)

logger = logging.getLogger("agentshield.risk")


# Business impact by function category
BUSINESS_IMPACT = {
    "auth": 1.0,
    "payment": 1.0,
    "admin": 0.8,
    "general": 0.5,
    "test": 0.1,
    "dev_script": 0.1,
}


class RiskCalculator:
    """
    Calculates business risk and determines triage priority.

    Formula: combined_score = 0.6 * exploitability + 0.4 * business_impact

    Priority thresholds:
        >= 0.85 → URGENT
        >= 0.65 → HIGH
        >= 0.40 → MEDIUM
        >= 0.20 → LOW
        <  0.20 → INFO
    """

    WEIGHT_EXPLOITABILITY = 0.6
    WEIGHT_BUSINESS_IMPACT = 0.4

    PRIORITY_THRESHOLDS = [
        (0.85, TriagePriority.URGENT),
        (0.65, TriagePriority.HIGH),
        (0.40, TriagePriority.MEDIUM),
        (0.20, TriagePriority.LOW),
        (0.00, TriagePriority.INFO),
    ]

    def calculate(
        self,
        exploitability: ExploitabilityAssessment,
        finding: SASTFinding,
        code_context: Optional[dict] = None,
    ) -> tuple[TriagePriority, float, str]:
        """
        Calculate business risk and determine priority.

        Returns:
            (priority, risk_score, reasoning)
        """
        code_context = code_context or {}

        # ── Business impact score ──────────────────────────────
        function_category = code_context.get("function_category", "general")
        if isinstance(function_category, FunctionCategory):
            function_category = function_category.value

        business_impact = BUSINESS_IMPACT.get(function_category, 0.5)

        # Modifiers
        impact_factors = [f"Function category: {function_category} (base impact: {business_impact:.2f})"]

        if code_context.get("handles_pii", False):
            business_impact = min(business_impact + 0.15, 1.0)
            impact_factors.append("PII handling: +0.15 impact")

        if code_context.get("is_deployed", False):
            business_impact = min(business_impact + 0.1, 1.0)
            impact_factors.append("Deployed to production: +0.10 impact")

        if code_context.get("is_internet_facing", False):
            business_impact = min(business_impact + 0.05, 1.0)
            impact_factors.append("Internet-facing: +0.05 impact")

        # ── Combined risk score ────────────────────────────────
        combined = (
            exploitability.score * self.WEIGHT_EXPLOITABILITY
            + business_impact * self.WEIGHT_BUSINESS_IMPACT
        )
        combined = max(0.0, min(1.0, combined))

        # ── Determine priority ─────────────────────────────────
        priority = TriagePriority.INFO
        for threshold, prio in self.PRIORITY_THRESHOLDS:
            if combined >= threshold:
                priority = prio
                break

        # ── Generate reasoning ─────────────────────────────────
        reasoning = (
            f"Risk Score: {combined:.2f} → Priority: {priority.value}\n"
            f"  Exploitability: {exploitability.score:.2f} (weight: {self.WEIGHT_EXPLOITABILITY})\n"
            f"  Business Impact: {business_impact:.2f} (weight: {self.WEIGHT_BUSINESS_IMPACT})\n"
            f"  Original SAST severity: {finding.severity.value}\n"
        )

        # Note upgrades/downgrades
        sast_to_priority = {
            SASTSeverity.CRITICAL: TriagePriority.URGENT,
            SASTSeverity.HIGH: TriagePriority.HIGH,
            SASTSeverity.MEDIUM: TriagePriority.MEDIUM,
            SASTSeverity.LOW: TriagePriority.LOW,
            SASTSeverity.INFO: TriagePriority.INFO,
        }
        expected = sast_to_priority.get(finding.severity, TriagePriority.MEDIUM)
        priority_order = {
            TriagePriority.URGENT: 5,
            TriagePriority.HIGH: 4,
            TriagePriority.MEDIUM: 3,
            TriagePriority.LOW: 2,
            TriagePriority.INFO: 1,
        }

        if priority_order[priority] > priority_order[expected]:
            reasoning += (
                f"  ** UPGRADED from {expected.value} → {priority.value} "
                f"based on runtime context and business impact analysis **\n"
            )
        elif priority_order[priority] < priority_order[expected]:
            reasoning += (
                f"  ** DOWNGRADED from {expected.value} → {priority.value} "
                f"based on runtime context (e.g., non-production, test code) **\n"
            )

        reasoning += "  Impact factors: " + "; ".join(impact_factors)

        logger.info(
            "Risk calculation: %s → priority=%s risk=%.2f",
            finding.id, priority.value, combined,
        )

        return priority, round(combined, 2), reasoning
