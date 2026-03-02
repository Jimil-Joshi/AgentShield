"""Tests for Autonomous Vulnerability Triage Agent (Part 5).

Covers Test Cases 5, 6, and 7 from the specification.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.models import (
    SASTFinding,
    SASTSeverity,
    VulnType,
    TriagePriority,
    RuntimeContextNode,
    CodeFileNode,
    FunctionCategory,
)
from src.context_graph import ContextGraph
from src.exploitability_analyzer import ExploitabilityAnalyzer
from src.risk_calculator import RiskCalculator
from src.remediation_generator import RemediationGenerator
from src.triage_agent import TriageAgent


@pytest.fixture
def analyzer():
    return ExploitabilityAnalyzer()


@pytest.fixture
def calculator():
    return RiskCalculator()


@pytest.fixture
def generator():
    return RemediationGenerator()


def _build_graph_for_triage():
    """Build a context graph with runtime contexts for triage tests."""
    g = ContextGraph()

    # Payment file (production, internet-facing, PII)
    g.add_node(CodeFileNode(
        id="file_payment",
        file_path="src/payment/process.py",
        function_category=FunctionCategory.PAYMENT,
        is_deployed=True,
        is_internet_facing=True,
        handles_pii=True,
    ))
    ctx_prod = RuntimeContextNode(
        id="ctx_prod",
        environment="production",
        is_deployed=True,
        is_internet_facing=True,
        handles_pii=True,
    )
    g.add_runtime_context(ctx_prod, ["file_payment"])

    # Dev script (not deployed)
    g.add_node(CodeFileNode(
        id="file_dev",
        file_path="scripts/dev_setup.py",
        function_category=FunctionCategory.DEV_SCRIPT,
        is_deployed=False,
    ))
    ctx_dev = RuntimeContextNode(
        id="ctx_dev",
        environment="development",
        is_deployed=False,
        is_internet_facing=False,
    )
    g.add_runtime_context(ctx_dev, ["file_dev"])

    # Admin panel (production, internet-facing, AI-modified)
    g.add_node(CodeFileNode(
        id="file_admin",
        file_path="src/admin/panel.py",
        function_category=FunctionCategory.ADMIN,
        is_deployed=True,
        is_internet_facing=True,
    ))
    ctx_admin = RuntimeContextNode(
        id="ctx_admin",
        environment="production",
        is_deployed=True,
        is_internet_facing=True,
        recently_modified_by_ai=True,
    )
    g.add_runtime_context(ctx_admin, ["file_admin"])

    return g


@pytest.fixture
def triage_agent():
    g = _build_graph_for_triage()
    return TriageAgent(context_graph=g)


# ─── Exploitability Analyzer ────────────────────────────────────────

class TestExploitabilityAnalyzer:
    def test_high_exploitability_deployed_sqli(self, analyzer):
        """SQL injection in deployed, internet-facing payment code → very high score."""
        finding = SASTFinding(
            id="sqli_payment",
            severity=SASTSeverity.HIGH,
            vuln_type=VulnType.SQL_INJECTION,
            file_path="src/payment/process.py",
            line_number=42,
            description="Unsanitized input in SQL query",
        )
        runtime_ctx = {
            "environment": "production",
            "is_deployed": True,
            "is_internet_facing": True,
            "handles_pii": True,
            "has_auth": True,
        }
        code_ctx = {
            "function_category": "payment",
            "is_deployed": True,
            "is_internet_facing": True,
            "handles_pii": True,
        }
        assessment = analyzer.analyze(finding, runtime_ctx, code_ctx)
        assert assessment.score >= 0.85
        assert assessment.is_deployed is True

    def test_low_exploitability_test_file(self, analyzer):
        """Vulnerability in a test helper file → low score."""
        finding = SASTFinding(
            id="sqli_test",
            severity=SASTSeverity.HIGH,
            vuln_type=VulnType.SQL_INJECTION,
            file_path="tests/test_helpers.py",
            line_number=10,
            description="SQL in test setup",
        )
        runtime_ctx = {
            "environment": "development",
            "is_deployed": False,
            "is_internet_facing": False,
        }
        code_ctx = {
            "function_category": "test",
            "is_deployed": False,
        }
        assessment = analyzer.analyze(finding, runtime_ctx, code_ctx)
        assert assessment.score <= 0.25

    def test_medium_exploitability(self, analyzer):
        finding = SASTFinding(
            id="xss_admin",
            severity=SASTSeverity.MEDIUM,
            vuln_type=VulnType.XSS,
            file_path="src/admin/panel.py",
            line_number=100,
            description="Reflected XSS",
        )
        runtime_ctx = {
            "environment": "production",
            "is_deployed": True,
            "is_internet_facing": False,
        }
        code_ctx = {
            "function_category": "admin",
            "is_deployed": True,
        }
        assessment = analyzer.analyze(finding, runtime_ctx, code_ctx)
        assert 0.25 <= assessment.score <= 0.85


# ─── Risk Calculator ────────────────────────────────────────────────

class TestRiskCalculator:
    def test_urgent_priority(self, calculator, analyzer):
        """Test Case 5: SQL injection in prod payment → URGENT, exploit ≥ 0.90."""
        finding = SASTFinding(
            id="sqli_prod",
            severity=SASTSeverity.HIGH,
            vuln_type=VulnType.SQL_INJECTION,
            file_path="src/payment/process.py",
            line_number=42,
            description="Direct string concatenation in SQL",
        )
        runtime_ctx = {
            "is_deployed": True,
            "is_internet_facing": True,
            "handles_pii": True,
            "has_auth": True,
        }
        code_ctx = {
            "function_category": "payment",
            "is_deployed": True,
            "is_internet_facing": True,
            "handles_pii": True,
        }
        exploit = analyzer.analyze(finding, runtime_ctx, code_ctx)
        priority, risk_score, reasoning = calculator.calculate(exploit, finding, code_ctx)
        assert exploit.score >= 0.90
        assert priority == TriagePriority.URGENT

    def test_low_priority(self, calculator, analyzer):
        """Test Case 6: Hardcoded secret in dev script → LOW, exploit ≤ 0.10."""
        finding = SASTFinding(
            id="secret_dev",
            severity=SASTSeverity.MEDIUM,
            vuln_type=VulnType.HARDCODED_SECRET,
            file_path="scripts/dev_setup.py",
            line_number=5,
            description="API key found in development script",
        )
        runtime_ctx = {
            "is_deployed": False,
            "is_internet_facing": False,
        }
        code_ctx = {
            "function_category": "dev_script",
            "is_deployed": False,
        }
        exploit = analyzer.analyze(finding, runtime_ctx, code_ctx)
        priority, risk_score, reasoning = calculator.calculate(exploit, finding, code_ctx)
        assert exploit.score <= 0.10
        assert priority in (TriagePriority.LOW, TriagePriority.INFO)

    def test_high_upgraded(self, calculator, analyzer):
        """Test Case 7: Medium SAST XSS, but AI-modified + internet-facing → upgraded to HIGH."""
        finding = SASTFinding(
            id="xss_admin",
            severity=SASTSeverity.MEDIUM,
            vuln_type=VulnType.XSS,
            file_path="src/admin/panel.py",
            line_number=100,
            description="Reflected XSS in search parameter",
        )
        runtime_ctx = {
            "is_deployed": True,
            "is_internet_facing": True,
            "recently_modified_by_ai": True,
        }
        code_ctx = {
            "function_category": "admin",
            "is_deployed": True,
            "is_internet_facing": True,
        }
        exploit = analyzer.analyze(finding, runtime_ctx, code_ctx)
        priority, risk_score, reasoning = calculator.calculate(exploit, finding, code_ctx)
        # Exploitability should be around 0.75 and priority upgraded to HIGH
        assert 0.60 <= exploit.score <= 0.85
        assert priority in (TriagePriority.HIGH, TriagePriority.URGENT)


# ─── Remediation Generator ──────────────────────────────────────────

class TestRemediationGenerator:
    def test_sql_injection_remediation(self, generator):
        finding = SASTFinding(
            id="sqli",
            severity=SASTSeverity.HIGH,
            vuln_type=VulnType.SQL_INJECTION,
            file_path="src/db.py",
            line_number=10,
            description="SQL injection",
        )
        remediation = generator.generate(finding, TriagePriority.URGENT)
        assert remediation is not None
        assert remediation.description != ""
        assert remediation.effort_estimate != ""
        assert any("CWE" in ref or "OWASP" in ref or "owasp" in ref or "cwe" in ref
                    for ref in remediation.references)

    def test_xss_remediation(self, generator):
        finding = SASTFinding(
            id="xss",
            severity=SASTSeverity.MEDIUM,
            vuln_type=VulnType.XSS,
            file_path="src/web.py",
            line_number=20,
            description="XSS",
        )
        remediation = generator.generate(finding, TriagePriority.HIGH)
        assert remediation.description != ""

    def test_hardcoded_secret_remediation(self, generator):
        finding = SASTFinding(
            id="secret",
            severity=SASTSeverity.HIGH,
            vuln_type=VulnType.HARDCODED_SECRET,
            file_path="src/config.py",
            line_number=5,
            description="Hardcoded API key",
        )
        remediation = generator.generate(finding, TriagePriority.URGENT)
        # Should mention secrets management
        assert remediation.description != ""


# ─── Triage Agent Integration ───────────────────────────────────────

class TestTriageAgentIntegration:
    def test_triage_single_finding(self, triage_agent):
        finding = SASTFinding(
            id="sqli_1",
            severity=SASTSeverity.HIGH,
            vuln_type=VulnType.SQL_INJECTION,
            file_path="src/payment/process.py",
            line_number=42,
            description="SQL injection in payment",
        )
        result = triage_agent.triage_finding(finding)
        assert result is not None
        assert result.finding_id == "sqli_1"
        assert result.final_priority == TriagePriority.URGENT
        assert result.exploitability is not None
        assert result.remediation is not None
        assert result.business_risk_score > 0

    def test_triage_all_findings(self, triage_agent):
        findings = [
            SASTFinding(
                id="f1", severity=SASTSeverity.HIGH,
                vuln_type=VulnType.SQL_INJECTION, file_path="src/payment/process.py",
                line_number=42, description="SQL injection",
            ),
            SASTFinding(
                id="f2", severity=SASTSeverity.MEDIUM,
                vuln_type=VulnType.HARDCODED_SECRET, file_path="scripts/dev_setup.py",
                line_number=5, description="Hardcoded secret",
            ),
        ]
        results = triage_agent.triage_all(findings)
        assert len(results) == 2
        # Results should be sorted by priority (URGENT first)
        priority_order = {
            TriagePriority.URGENT: 5,
            TriagePriority.HIGH: 4,
            TriagePriority.MEDIUM: 3,
            TriagePriority.LOW: 2,
            TriagePriority.INFO: 1,
        }
        assert priority_order[results[0].final_priority] >= priority_order[results[1].final_priority]
