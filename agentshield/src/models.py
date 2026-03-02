"""
AgentShield Data Models
All Pydantic v2 models for the AgentShield security platform.
Covers: graph nodes/edges, events, verification, triage, integrity, MCP.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, Optional, Union

from pydantic import BaseModel, Field


# ─────────────────────────────────────────────
# Enums
# ─────────────────────────────────────────────

class EventType(str, Enum):
    FILE_ACCESS = "file_access"
    CODE_MODIFICATION = "code_modification"
    TOOL_CALL = "tool_call"
    DEPENDENCY_ADDITION = "dependency_addition"
    SECURITY_VIOLATION = "security_violation"
    CREDENTIAL_ACCESS = "credential_access"


class VerificationDecision(str, Enum):
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"
    REQUIRE_HUMAN_REVIEW = "REQUIRE_HUMAN_REVIEW"


class TriagePriority(str, Enum):
    URGENT = "URGENT"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class SASTSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnType(str, Enum):
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    HARDCODED_SECRET = "hardcoded_secret"
    PATH_TRAVERSAL = "path_traversal"
    MISSING_AUTH = "missing_auth"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    COMMAND_INJECTION = "command_injection"
    SSRF = "ssrf"
    BROKEN_ACCESS_CONTROL = "broken_access_control"
    OTHER = "other"


class FunctionCategory(str, Enum):
    AUTH = "auth"
    PAYMENT = "payment"
    ADMIN = "admin"
    GENERAL = "general"
    TEST = "test"
    DEV_SCRIPT = "dev_script"


class AgentRole(str, Enum):
    ADMIN = "admin"
    READER = "reader"
    WRITER = "writer"
    SECURITY_SCANNER = "security_scanner"


class AnomalySeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ─────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uid(prefix: str = "") -> str:
    short = uuid.uuid4().hex[:12]
    return f"{prefix}_{short}" if prefix else short


# ─────────────────────────────────────────────
# Graph Node Models
# ─────────────────────────────────────────────

class AgentNode(BaseModel):
    """An AI agent that interacts with code."""
    node_type: Literal["Agent"] = "Agent"
    id: str = Field(default_factory=lambda: _uid("agent"))
    name: str
    role: AgentRole = AgentRole.READER
    trust_score: float = Field(default=0.5, ge=0.0, le=1.0)
    created_at: datetime = Field(default_factory=_now)
    description: str = ""


class CodeFileNode(BaseModel):
    """A source code file in the repository."""
    node_type: Literal["CodeFile"] = "CodeFile"
    id: str = Field(default_factory=lambda: _uid("file"))
    file_path: str
    language: str = "python"
    is_deployed: bool = False
    is_internet_facing: bool = False
    handles_pii: bool = False
    function_category: FunctionCategory = FunctionCategory.GENERAL
    repo: str = ""
    branch: str = "main"


class DependencyNode(BaseModel):
    """An external dependency / package."""
    node_type: Literal["Dependency"] = "Dependency"
    id: str = Field(default_factory=lambda: _uid("dep"))
    name: str
    version: str = "latest"
    source: str = "pypi"
    is_trusted: bool = True
    introduced_by: str = ""  # agent_id


class SecurityRuleNode(BaseModel):
    """A security rule in the verification engine."""
    node_type: Literal["SecurityRule"] = "SecurityRule"
    id: str = Field(default_factory=lambda: _uid("rule"))
    rule_id: str
    description: str
    severity: str = "HIGH"


class ActionNode(BaseModel):
    """An action performed by an agent."""
    node_type: Literal["Action"] = "Action"
    id: str = Field(default_factory=lambda: _uid("action"))
    action_type: EventType
    timestamp: datetime = Field(default_factory=_now)
    agent_id: str = ""
    target: str = ""
    details: dict[str, Any] = Field(default_factory=dict)


class VulnerabilityNode(BaseModel):
    """A vulnerability found by SAST or manual analysis."""
    node_type: Literal["Vulnerability"] = "Vulnerability"
    id: str = Field(default_factory=lambda: _uid("vuln"))
    vuln_type: VulnType
    sast_severity: SASTSeverity = SASTSeverity.MEDIUM
    cwe_id: str = ""
    description: str = ""
    file_path: str = ""
    line_number: int = 0


class RuntimeContextNode(BaseModel):
    """Runtime context about a service / deployment."""
    node_type: Literal["RuntimeContext"] = "RuntimeContext"
    id: str = Field(default_factory=lambda: _uid("ctx"))
    environment: str = "production"  # production / staging / dev
    service_name: str = ""
    is_deployed: bool = True
    has_auth: bool = True
    is_internet_facing: bool = False
    handles_pii: bool = False
    last_deploy: Optional[datetime] = None
    recently_modified_by_ai: bool = False


# Union of all node types
GraphNode = Union[
    AgentNode, CodeFileNode, DependencyNode, SecurityRuleNode,
    ActionNode, VulnerabilityNode, RuntimeContextNode,
]


# ─────────────────────────────────────────────
# Graph Edge Models
# ─────────────────────────────────────────────

class AccessedEdge(BaseModel):
    edge_type: Literal["accessed"] = "accessed"
    source: str
    target: str
    timestamp: datetime = Field(default_factory=_now)
    access_type: str = "read"


class ModifiedEdge(BaseModel):
    edge_type: Literal["modified"] = "modified"
    source: str
    target: str
    timestamp: datetime = Field(default_factory=_now)
    change_summary: str = ""


class DependsOnEdge(BaseModel):
    edge_type: Literal["depends_on"] = "depends_on"
    source: str
    target: str
    introduced_by: str = ""


class TriggeredEdge(BaseModel):
    edge_type: Literal["triggered"] = "triggered"
    source: str
    target: str
    timestamp: datetime = Field(default_factory=_now)


class ViolatedEdge(BaseModel):
    edge_type: Literal["violated"] = "violated"
    source: str
    target: str
    rule_id: str = ""
    severity: str = "HIGH"


class AffectsEdge(BaseModel):
    edge_type: Literal["affects"] = "affects"
    source: str
    target: str
    impact_scope: str = ""


class ExploitsEdge(BaseModel):
    edge_type: Literal["exploits"] = "exploits"
    source: str
    target: str
    exploitability_score: float = 0.0


GraphEdge = Union[
    AccessedEdge, ModifiedEdge, DependsOnEdge, TriggeredEdge,
    ViolatedEdge, AffectsEdge, ExploitsEdge,
]


# ─────────────────────────────────────────────
# Event Model (input to the context graph)
# ─────────────────────────────────────────────

class AgentEvent(BaseModel):
    """An event generated by an AI agent."""
    id: str = Field(default_factory=lambda: _uid("evt"))
    agent_id: str
    agent_name: str = ""
    event_type: EventType
    target_file: str = ""
    timestamp: datetime = Field(default_factory=_now)
    details: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


# ─────────────────────────────────────────────
# Verification Models
# ─────────────────────────────────────────────

class VerificationResult(BaseModel):
    """Result of the Verifier Agent's analysis of an agent action."""
    event_id: str = ""
    decision: VerificationDecision
    reasoning: str
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    rules_evaluated: list[str] = Field(default_factory=list)
    rules_violated: list[str] = Field(default_factory=list)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    context_used: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=_now)


class VerificationRule(BaseModel):
    """A verification rule definition."""
    rule_id: str
    name: str
    description: str
    severity: str = "HIGH"


# ─────────────────────────────────────────────
# SAST / Triage Models
# ─────────────────────────────────────────────

class SASTFinding(BaseModel):
    """A finding from a SAST (Static Application Security Testing) scan."""
    id: str = Field(default_factory=lambda: _uid("sast"))
    vuln_type: VulnType
    severity: SASTSeverity
    file_path: str
    line_number: int = 0
    description: str = ""
    cwe_id: str = ""
    snippet: str = ""


class ExploitabilityAssessment(BaseModel):
    """Assessment of how exploitable a vulnerability is."""
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    factors: list[str] = Field(default_factory=list)
    is_deployed: bool = False
    is_internet_facing: bool = False
    handles_pii: bool = False
    requires_auth: bool = True
    reasoning: str = ""


class RemediationGuidance(BaseModel):
    """Actionable remediation guidance for a vulnerability."""
    description: str
    code_snippet: str = ""
    effort_estimate: str = "1-2 hours"
    references: list[str] = Field(default_factory=list)


class TriageResult(BaseModel):
    """Complete triage result for a SAST finding."""
    finding_id: str
    original_severity: SASTSeverity
    final_priority: TriagePriority
    exploitability: ExploitabilityAssessment
    business_risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    reasoning: str = ""
    remediation: Optional[RemediationGuidance] = None
    runtime_context_used: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=_now)


# ─────────────────────────────────────────────
# Integrity / Supply Chain Models
# ─────────────────────────────────────────────

class DecisionTrace(BaseModel):
    """A signed trace of an agent's decision for tamper detection."""
    trace_id: str = Field(default_factory=lambda: _uid("trace"))
    sequence_number: int = 0
    agent_id: str
    timestamp: datetime = Field(default_factory=_now)
    action: str
    inputs: dict[str, Any] = Field(default_factory=dict)
    reasoning: str = ""
    output: dict[str, Any] = Field(default_factory=dict)
    previous_hash: str = ""
    signature: str = ""


class AnomalyAlert(BaseModel):
    """An alert raised by the anomaly detector."""
    id: str = Field(default_factory=lambda: _uid("alert"))
    agent_id: str
    alert_type: str  # volume_anomaly, scope_anomaly, temporal_anomaly, pattern_anomaly
    baseline_value: str = ""
    observed_value: str = ""
    description: str
    severity: AnomalySeverity = AnomalySeverity.MEDIUM
    timestamp: datetime = Field(default_factory=_now)


# ─────────────────────────────────────────────
# MCP Models
# ─────────────────────────────────────────────

class MCPToolCall(BaseModel):
    """A tool call made through the MCP server."""
    id: str = Field(default_factory=lambda: _uid("mcp"))
    tool_name: str
    agent_id: str
    parameters: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=_now)


class MCPAuditLog(BaseModel):
    """Audit log entry for an MCP tool call."""
    tool_call: MCPToolCall
    result_summary: str = ""
    duration_ms: float = 0.0
    security_violations: list[str] = Field(default_factory=list)
    allowed: bool = True
    timestamp: datetime = Field(default_factory=_now)


class AgentRegistryEntry(BaseModel):
    """An entry in the agent registry for auth/authz."""
    agent_id: str
    agent_name: str
    role: AgentRole
    allowed_repos: list[str] = Field(default_factory=list)
    allowed_branches: list[str] = Field(default_factory=lambda: ["main"])
    is_active: bool = True
    created_at: datetime = Field(default_factory=_now)
