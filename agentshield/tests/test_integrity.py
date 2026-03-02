"""Tests for Agent Supply Chain Integrity (Part 4).

Covers Test Case 4: Behavioral anomaly detection,
plus HMAC signing, tamper detection, chain integrity.
"""

import sys
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.integrity_monitor import (
    sign_payload,
    verify_signature,
    hash_payload,
    DecisionTraceStore,
    AnomalyDetector,
    IdentityVerifier,
    IntegrityMonitor,
)
from src.context_graph import ContextGraph
from src.models import (
    AgentNode,
    CodeFileNode,
    AgentEvent,
    EventType,
    FunctionCategory,
    AnomalySeverity,
)


@pytest.fixture
def empty_graph():
    return ContextGraph()


@pytest.fixture
def populated_graph():
    """Graph with some agent history for baseline building."""
    g = ContextGraph()
    g.add_node(AgentNode(id="agent_normal", name="Normal Agent", trust_score=0.8))
    g.add_node(CodeFileNode(id="f1", file_path="src/utils/helper.py"))
    g.add_node(CodeFileNode(id="f2", file_path="src/main.py"))

    # Record some history via event ingestion
    for i in range(5):
        event = AgentEvent(
            agent_id="agent_normal",
            agent_name="Normal Agent",
            event_type=EventType.FILE_ACCESS,
            target_file="src/utils/helper.py",
        )
        g.ingest_event(event)

    return g


class TestCryptographicPrimitives:
    def test_sign_and_verify(self):
        payload = {"action": "modify", "file": "auth.py"}
        sig = sign_payload(payload)
        assert verify_signature(payload, sig) is True

    def test_tamper_detection(self):
        """Modifying the payload after signing should fail verification."""
        payload = {"action": "modify", "file": "auth.py"}
        sig = sign_payload(payload)
        # Tamper
        tampered = {"action": "modify", "file": "malicious.py"}
        assert verify_signature(tampered, sig) is False

    def test_different_payloads(self):
        sig1 = sign_payload({"a": 1})
        sig2 = sign_payload({"a": 2})
        assert sig1 != sig2

    def test_hash_consistency(self):
        payload = {"key": "value"}
        h1 = hash_payload(payload)
        h2 = hash_payload(payload)
        assert h1 == h2

    def test_hash_different_payloads(self):
        h1 = hash_payload({"a": 1})
        h2 = hash_payload({"a": 2})
        assert h1 != h2


class TestDecisionTraceStore:
    @pytest.fixture
    def store(self):
        return DecisionTraceStore()

    def test_record_trace(self, store):
        trace = store.record(
            agent_id="agent_1",
            action="modify_file",
            inputs={"file": "auth.py"},
            reasoning="Updating auth logic",
            output={"decision": "ALLOW"},
        )
        assert trace.signature != ""
        assert trace.sequence_number == 1

    def test_chain_integrity_valid(self, store):
        """Multiple traces should form a valid chain."""
        for i in range(5):
            store.record(
                agent_id=f"agent_{i}",
                action=f"action_{i}",
                inputs={"step": i},
                reasoning=f"Step {i}",
                output={"result": "ok"},
            )
        is_valid, errors = store.verify_chain()
        assert is_valid is True
        assert len(errors) == 0

    def test_chain_integrity_tampered(self, store):
        """Tampering with a trace should break chain verification."""
        for i in range(5):
            store.record(
                agent_id="agent_1",
                action=f"action_{i}",
                inputs={"step": i},
                reasoning=f"Step {i}",
                output={"result": "ok"},
            )
        # Tamper with the middle trace
        if len(store.traces) >= 3:
            store.traces[2].action = "tampered_action"
        is_valid, errors = store.verify_chain()
        assert is_valid is False
        assert len(errors) > 0

    def test_get_traces_by_agent(self, store):
        store.record("a1", "x", {}, "r1", {"out": 1})
        store.record("a2", "y", {}, "r2", {"out": 2})
        store.record("a1", "z", {}, "r3", {"out": 3})
        a1_traces = store.get_traces_by_agent("a1")
        assert len(a1_traces) == 2


class TestAnomalyDetector:
    def test_no_anomaly_for_new_agent(self, empty_graph):
        """New agent with no baseline — should build on first check."""
        detector = AnomalyDetector(empty_graph)
        # Unknown agent will have an empty baseline; first action won't trigger volume or pattern
        alert = detector.check_anomaly("new_agent", "read_file", "src/main.py")
        # With no history, scope anomaly happens if it's a credential/auth file
        # Normal file → no alert
        assert alert is None

    def test_anomaly_credential_access(self, populated_graph):
        """Test Case 4: Agent suddenly accessing credentials → anomaly alert."""
        detector = AnomalyDetector(populated_graph)
        detector.build_baseline("agent_normal")

        # Agent_normal never accessed credentials before
        alert = detector.check_anomaly(
            "agent_normal",
            "file_access",
            ".env.production",  # credential file
        )
        assert alert is not None
        assert alert.severity in (AnomalySeverity.HIGH, AnomalySeverity.CRITICAL)

    def test_anomaly_auth_code_access(self, populated_graph):
        """Agent suddenly accessing auth code → anomaly alert."""
        detector = AnomalyDetector(populated_graph)
        detector.build_baseline("agent_normal")

        alert = detector.check_anomaly(
            "agent_normal",
            "code_modification",
            "src/auth/login.py",
        )
        assert alert is not None
        assert alert.severity in (AnomalySeverity.HIGH, AnomalySeverity.MEDIUM)


class TestIdentityVerifier:
    @pytest.fixture
    def verifier(self):
        v = IdentityVerifier()
        v.register_agent("agent_1", fingerprint="fp_abc123")
        return v

    def test_verify_valid(self, verifier):
        ok, msg = verifier.verify_identity("agent_1", "fp_abc123")
        assert ok is True

    def test_verify_wrong_fingerprint(self, verifier):
        ok, msg = verifier.verify_identity("agent_1", "fp_wrong")
        assert ok is False
        assert "SPOOFING" in msg or "mismatch" in msg

    def test_verify_unknown_agent(self, verifier):
        ok, msg = verifier.verify_identity("agent_unknown", "fp_x")
        assert ok is False


class TestIntegrityMonitorIntegration:
    @pytest.fixture
    def monitor(self, empty_graph):
        return IntegrityMonitor(context_graph=empty_graph)

    def test_record_and_verify_chain(self, monitor):
        monitor.record_decision(
            agent_id="agent_1", action="read_file",
            inputs={"file": "main.py"}, reasoning="Reading file",
            output={"decision": "ALLOW"},
        )
        monitor.record_decision(
            agent_id="agent_1", action="modify_file",
            inputs={"file": "auth.py"}, reasoning="Updating auth",
            output={"decision": "BLOCK"},
        )
        is_valid, errors = monitor.verify_chain_integrity()
        assert is_valid is True

    def test_check_action_anomaly(self, populated_graph):
        """Test anomaly checking via the IntegrityMonitor."""
        monitor = IntegrityMonitor(context_graph=populated_graph)
        monitor.build_agent_baseline("agent_normal")

        alert = monitor.check_action(
            "agent_normal", "file_access", ".env.production"
        )
        assert alert is not None

    def test_full_report(self, monitor):
        monitor.record_decision("a1", "x", {}, "r", {"o": 1})
        report = monitor.get_integrity_report()
        assert "chain_valid" in report
        assert report["total_traces"] == 1
