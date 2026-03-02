"""
AgentShield Integrity Monitor (Part 4)
Detects tampering or compromise in agent decision chains.
Implements: decision trace capture, cryptographic signing, anomaly detection.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import statistics
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Optional

from .context_graph import ContextGraph
from .models import (
    AnomalyAlert,
    AnomalySeverity,
    DecisionTrace,
    EventType,
)

logger = logging.getLogger("agentshield.integrity")


# ─────────────────────────────────────────────
# Cryptographic Signing
# ─────────────────────────────────────────────

def _get_signing_key() -> bytes:
    """Get the HMAC signing key from environment or generate one."""
    key = os.getenv("AGENTSHIELD_SIGNING_KEY", "agentshield-default-key-change-in-production")
    return key.encode("utf-8")


def sign_payload(payload: dict) -> str:
    """Create HMAC-SHA256 signature for a payload."""
    canonical = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hmac.new(_get_signing_key(), canonical, hashlib.sha256).hexdigest()


def verify_signature(payload: dict, expected_signature: str) -> bool:
    """Verify a payload's HMAC-SHA256 signature."""
    canonical = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    computed = hmac.new(_get_signing_key(), canonical, hashlib.sha256).hexdigest()
    return hmac.compare_digest(computed, expected_signature)


def hash_payload(payload: dict) -> str:
    """SHA-256 hash of a payload (for chaining)."""
    canonical = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


# ─────────────────────────────────────────────
# Decision Trace Store
# ─────────────────────────────────────────────

class DecisionTraceStore:
    """
    Append-only store for signed decision traces.
    Implements blockchain-like chaining for tamper detection.
    """

    def __init__(self):
        self.traces: list[DecisionTrace] = []
        self._sequence = 0

    def record(
        self,
        agent_id: str,
        action: str,
        inputs: dict[str, Any],
        reasoning: str,
        output: dict[str, Any],
    ) -> DecisionTrace:
        """Record a new decision trace with cryptographic signature."""
        self._sequence += 1

        # Get previous hash for chaining
        previous_hash = ""
        if self.traces:
            prev = self.traces[-1]
            previous_hash = hash_payload(prev.model_dump(mode="json", exclude={"signature"}))

        # Build the trace (without signature first)
        trace = DecisionTrace(
            sequence_number=self._sequence,
            agent_id=agent_id,
            action=action,
            inputs=inputs,
            reasoning=reasoning,
            output=output,
            previous_hash=previous_hash,
        )

        # Sign the trace
        signable = trace.model_dump(mode="json", exclude={"signature"})
        trace.signature = sign_payload(signable)

        self.traces.append(trace)
        logger.info(
            "Recorded trace #%d: agent=%s action=%s",
            self._sequence, agent_id, action,
        )
        return trace

    def verify_trace(self, trace_id: str) -> tuple[bool, str]:
        """Verify a single trace's signature."""
        trace = self._find_trace(trace_id)
        if not trace:
            return False, f"Trace '{trace_id}' not found"

        signable = trace.model_dump(mode="json", exclude={"signature"})
        if verify_signature(signable, trace.signature):
            return True, "Signature valid"
        return False, "TAMPER DETECTED: Signature mismatch"

    def verify_chain(self) -> tuple[bool, list[str]]:
        """
        Verify the entire chain of traces.
        Checks: signatures + hash chaining (blockchain-style).
        """
        errors = []
        for i, trace in enumerate(self.traces):
            # Verify signature
            signable = trace.model_dump(mode="json", exclude={"signature"})
            if not verify_signature(signable, trace.signature):
                errors.append(
                    f"Trace #{trace.sequence_number} ({trace.trace_id}): SIGNATURE INVALID"
                )

            # Verify chain link
            if i > 0:
                prev = self.traces[i - 1]
                expected_hash = hash_payload(
                    prev.model_dump(mode="json", exclude={"signature"})
                )
                if trace.previous_hash != expected_hash:
                    errors.append(
                        f"Trace #{trace.sequence_number}: CHAIN BROKEN - "
                        f"previous_hash mismatch (expected {expected_hash[:16]}…)"
                    )

            # Verify sequence
            if trace.sequence_number != i + 1:
                errors.append(
                    f"Trace #{trace.sequence_number}: SEQUENCE GAP at position {i}"
                )

        is_valid = len(errors) == 0
        return is_valid, errors

    def detect_gaps(self) -> list[int]:
        """Find missing sequence numbers in the chain."""
        if not self.traces:
            return []
        numbers = {t.sequence_number for t in self.traces}
        expected = set(range(1, max(numbers) + 1))
        return sorted(expected - numbers)

    def get_traces_by_agent(self, agent_id: str) -> list[DecisionTrace]:
        """Get all traces for a specific agent."""
        return [t for t in self.traces if t.agent_id == agent_id]

    def _find_trace(self, trace_id: str) -> Optional[DecisionTrace]:
        for t in self.traces:
            if t.trace_id == trace_id:
                return t
        return None


# ─────────────────────────────────────────────
# Identity Verification
# ─────────────────────────────────────────────

class IdentityVerifier:
    """Verify agent identities haven't been spoofed."""

    def __init__(self):
        self._known_agents: dict[str, dict] = {}

    def register_agent(
        self, agent_id: str, fingerprint: str, metadata: dict = None
    ) -> None:
        self._known_agents[agent_id] = {
            "fingerprint": fingerprint,
            "metadata": metadata or {},
            "registered_at": datetime.now(timezone.utc).isoformat(),
        }

    def verify_identity(
        self, agent_id: str, claimed_fingerprint: str
    ) -> tuple[bool, str]:
        """Verify an agent's claimed identity."""
        if agent_id not in self._known_agents:
            return False, f"Agent '{agent_id}' is not registered"

        expected = self._known_agents[agent_id]["fingerprint"]
        if hmac.compare_digest(expected, claimed_fingerprint):
            return True, "Identity verified"
        return False, f"IDENTITY SPOOFING DETECTED: Agent '{agent_id}' fingerprint mismatch"

    def detect_result_manipulation(
        self, tool_name: str, result: Any, expected_type: type = dict
    ) -> tuple[bool, str]:
        """Check if tool call results have been manipulated."""
        if not isinstance(result, expected_type):
            return False, (
                f"Result type mismatch for tool '{tool_name}': "
                f"expected {expected_type.__name__}, got {type(result).__name__}"
            )
        return True, "Result structure valid"


# ─────────────────────────────────────────────
# Anomaly Detection
# ─────────────────────────────────────────────

class AnomalyDetector:
    """
    Detects behavioral anomalies in agent actions.
    Builds baselines from historical data, alerts on deviations.
    """

    def __init__(self, context_graph: ContextGraph):
        self.graph = context_graph
        self._baselines: dict[str, dict] = {}

    def build_baseline(self, agent_id: str) -> dict:
        """
        Build a behavioral baseline for an agent from the context graph.
        Tracks: file access volume, file types, directories, resource types accessed.
        """
        history = self.graph.get_agent_history(agent_id)

        if not history:
            baseline = {
                "agent_id": agent_id,
                "total_actions": 0,
                "file_access_count": 0,
                "code_modification_count": 0,
                "credential_access_count": 0,
                "unique_files": set(),
                "action_types": defaultdict(int),
                "accessed_categories": set(),
                "avg_actions_per_session": 0,
                "has_accessed_credentials": False,
                "has_accessed_auth_code": False,
            }
        else:
            action_types: dict[str, int] = defaultdict(int)
            unique_files: set[str] = set()
            accessed_cats: set[str] = set()
            cred_count = 0
            auth_count = 0

            for action in history:
                at = action.get("action_type", "")
                action_types[at] = action_types.get(at, 0) + 1
                target = action.get("target", "")
                if target:
                    unique_files.add(target)
                    # Check category
                    from .utils import is_credential_file, is_auth_file
                    if is_credential_file(target):
                        cred_count += 1
                        accessed_cats.add("credentials")
                    if is_auth_file(target):
                        auth_count += 1
                        accessed_cats.add("auth")

            baseline = {
                "agent_id": agent_id,
                "total_actions": len(history),
                "file_access_count": action_types.get(EventType.FILE_ACCESS.value, 0),
                "code_modification_count": action_types.get(EventType.CODE_MODIFICATION.value, 0),
                "credential_access_count": cred_count,
                "unique_files_count": len(unique_files),
                "action_types": dict(action_types),
                "accessed_categories": accessed_cats,
                "avg_actions_per_session": len(history),  # simplified
                "has_accessed_credentials": cred_count > 0,
                "has_accessed_auth_code": auth_count > 0,
            }

        self._baselines[agent_id] = baseline
        return baseline

    def check_anomaly(
        self, agent_id: str, action_type: str, target: str = "", details: dict = None
    ) -> Optional[AnomalyAlert]:
        """
        Check if the current action is anomalous compared to baseline.
        Returns an AnomalyAlert if anomaly detected, None otherwise.
        """
        baseline = self._baselines.get(agent_id)
        if baseline is None:
            baseline = self.build_baseline(agent_id)

        details = details or {}

        # ── Check 1: Volume anomaly ────────────────────────────
        # If agent usually does N actions, and suddenly does >> N
        current_count = baseline.get("total_actions", 0)
        volume_threshold = max(current_count * 3, 10)  # 3x or min 10

        file_access_claimed = details.get("batch_size", 1)
        if file_access_claimed > volume_threshold and current_count > 0:
            return AnomalyAlert(
                agent_id=agent_id,
                alert_type="volume_anomaly",
                baseline_value=f"{current_count} total actions historically",
                observed_value=f"{file_access_claimed} files in single batch",
                description=(
                    f"Agent '{agent_id}' is accessing {file_access_claimed} files, "
                    f"far exceeding historical baseline of {current_count} total actions."
                ),
                severity=AnomalySeverity.HIGH,
            )

        # ── Check 2: Scope anomaly (new resource type) ────────
        from .utils import is_credential_file, is_auth_file

        if target and is_credential_file(target):
            if not baseline.get("has_accessed_credentials", False):
                return AnomalyAlert(
                    agent_id=agent_id,
                    alert_type="scope_anomaly",
                    baseline_value="Never accessed credentials before",
                    observed_value=f"Attempting to access '{target}'",
                    description=(
                        f"ALERT: Agent '{agent_id}' has NEVER accessed credentials before, "
                        f"but is now attempting to access '{target}'. "
                        "This is a significant behavioral anomaly."
                    ),
                    severity=AnomalySeverity.CRITICAL,
                )

        if target and is_auth_file(target):
            if not baseline.get("has_accessed_auth_code", False):
                return AnomalyAlert(
                    agent_id=agent_id,
                    alert_type="scope_anomaly",
                    baseline_value="Never accessed auth code before",
                    observed_value=f"Attempting to access '{target}'",
                    description=(
                        f"Agent '{agent_id}' has never accessed authentication code before, "
                        f"but is now targeting '{target}'. Why now?"
                    ),
                    severity=AnomalySeverity.HIGH,
                )

        # ── Check 3: Pattern anomaly (unusual action type) ────
        action_types = baseline.get("action_types", {})
        if action_type not in action_types and current_count > 5:
            return AnomalyAlert(
                agent_id=agent_id,
                alert_type="pattern_anomaly",
                baseline_value=f"Known action types: {list(action_types.keys())}",
                observed_value=f"New action type: {action_type}",
                description=(
                    f"Agent '{agent_id}' is performing action type '{action_type}' "
                    f"for the first time. Previous action types: {list(action_types.keys())}"
                ),
                severity=AnomalySeverity.MEDIUM,
            )

        return None


# ─────────────────────────────────────────────
# Integrity Monitor (combines all subsystems)
# ─────────────────────────────────────────────

class IntegrityMonitor:
    """
    Combined integrity monitoring system.
    Integrates: Decision traces, identity verification, anomaly detection.
    """

    def __init__(self, context_graph: ContextGraph):
        self.trace_store = DecisionTraceStore()
        self.identity_verifier = IdentityVerifier()
        self.anomaly_detector = AnomalyDetector(context_graph)
        self.graph = context_graph
        self.alerts: list[AnomalyAlert] = []

    def record_decision(
        self,
        agent_id: str,
        action: str,
        inputs: dict,
        reasoning: str,
        output: dict,
    ) -> DecisionTrace:
        """Record a decision trace with signing."""
        return self.trace_store.record(agent_id, action, inputs, reasoning, output)

    def check_action(
        self, agent_id: str, action_type: str, target: str = "", details: dict = None
    ) -> Optional[AnomalyAlert]:
        """
        Check an agent action for anomalies.
        Returns alert if anomalous, None otherwise.
        """
        alert = self.anomaly_detector.check_anomaly(
            agent_id, action_type, target, details
        )
        if alert:
            self.alerts.append(alert)
            logger.warning(
                "ANOMALY: agent=%s type=%s severity=%s: %s",
                agent_id, alert.alert_type, alert.severity.value, alert.description,
            )
        return alert

    def verify_chain_integrity(self) -> tuple[bool, list[str]]:
        """Verify the full decision trace chain."""
        return self.trace_store.verify_chain()

    def get_all_alerts(self) -> list[AnomalyAlert]:
        """Get all anomaly alerts."""
        return self.alerts

    def build_agent_baseline(self, agent_id: str) -> dict:
        """Build behavioral baseline for an agent."""
        return self.anomaly_detector.build_baseline(agent_id)

    def get_integrity_report(self) -> dict:
        """Generate a full integrity report."""
        chain_valid, chain_errors = self.trace_store.verify_chain()
        gaps = self.trace_store.detect_gaps()

        return {
            "total_traces": len(self.trace_store.traces),
            "chain_valid": chain_valid,
            "chain_errors": chain_errors,
            "sequence_gaps": gaps,
            "total_alerts": len(self.alerts),
            "alerts_by_severity": {
                s.value: len([a for a in self.alerts if a.severity == s])
                for s in AnomalySeverity
            },
            "alerts_by_agent": {
                agent_id: len([a for a in self.alerts if a.agent_id == agent_id])
                for agent_id in set(a.agent_id for a in self.alerts)
            },
        }
