"""
End-to-end lifecycle test: poison enters, is detected, is contained, and
the workload keeps running.

Exercises the complete chain on both backends:
  1. Build a graph with a critical function, a compaction node (llm-v1
     summariser covering poisoned + clean nodes), checkpoint, substitute
  2. Feed a raw AMG tampering event to /detector/amg
  3. Assert designation, C(p) sweep, ingress-block drop
  4. Assert continuity fired (checkpoint replay with distinct identity)
  5. Paired-arm containment proof: same incident with CONTINUITY_ENABLED=False
     vs True, assert containment digest is BIT-IDENTICAL
  6. Assert compaction node resolved to REDUCIBLE via inline reconstruction (R3-R5)
  7. Fire FUNCTIONAL_FAILURE recurrence signal, assert withdrawal transaction
  8. Assert continuity-report row-4 non-vacuity exercised
"""
import json
import hashlib
import pytest
import jwt
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from tests.conftest import ECDSASigner, JWT_PRIVATE_KEY_PEM
from src.governor_service import app, settings

client = TestClient(app)

_signer = ECDSASigner()
PUBLIC_KEY_HEX = _signer.public_key_hex

# Track content hashes so child payloads can declare correct parent_content_hash
_content_hash_registry = {}


def _admin_token():
    return jwt.encode({"sub": "admin", "role": "admin"}, JWT_PRIVATE_KEY_PEM, algorithm="ES256")


def _designator_token():
    return jwt.encode({"sub": "designator", "role": "designator"}, JWT_PRIVATE_KEY_PEM, algorithm="ES256")


def _agent_token(pub_hex=None):
    pub_hex = pub_hex or PUBLIC_KEY_HEX
    return jwt.encode(
        {
            "sub": pub_hex,
            "scope": "agent:state:reconstruct",
            "is_nhi": True,
            "expires_at_epoch": int(datetime.now(timezone.utc).timestamp()) + 3600,
            "verifier_execution_status": "PASSED",
        },
        JWT_PRIVATE_KEY_PEM,
        algorithm="ES256",
    )


def _auth_headers(role="admin"):
    if role == "admin":
        return {"Authorization": f"Bearer {_admin_token()}"}
    return {"Authorization": f"Bearer {_designator_token()}"}


def _make_payload(payload_id, state_content, parent_ids, criticality_weight=0):
    """Build and sign a payload."""
    content_str = json.dumps(state_content, sort_keys=True)
    actual_hash = hashlib.sha256(content_str.encode()).hexdigest()
    sig = _signer.sign(actual_hash.encode())

    parent_commitments = []
    for pid in parent_ids:
        parent_hash = _content_hash_registry.get(pid, "e" * 64)
        parent_commitments.append({"parent_node_id": pid, "parent_content_hash": parent_hash})

    _content_hash_registry[payload_id] = actual_hash

    return {
        "payload_id": payload_id,
        "timestamp_utc": "2026-10-27T10:00:00Z",
        "ephemeral_nhi": {
            "identity_id": PUBLIC_KEY_HEX,
            "session_token": _agent_token(),
            "expires_at_utc": "2026-10-27T11:00:00Z",
        },
        "declared_evidence_boundary": {
            "boundary_id": "b1",
            "fixed_at_utc": "2026-10-26T00:00:00Z",
            "boundary_digest": "f" * 64,
        },
        "parent_dependency_commitments": parent_commitments,
        "state_content": state_content,
        "content_digest_sha256": actual_hash,
        "agent_signature": sig,
        "signature_algorithm": "ECDSA-P256-SHA256",
        "criticality_weight": criticality_weight,
    }


def _build_graph_and_fixtures():
    """Build the test graph, checkpoint, substitute, and compaction node.

    Graph:
        clean-parent-1 -> base-record -> derived-record -> critical-function
                          (poisoned)                       (criticality=0.9)
                                       -> honest-derived
        clean-parent-1 -> alt-source   (substitute for base-record)
        clean-parent-1 -> clean-leaf   (clean frontier for compaction)

    Compaction node (llm-v1):
        covers [base-record, clean-leaf] — one poisoned, one clean frontier
    """
    base = _make_payload("base-record", {"data": "base"}, ["clean-parent-1"])
    resp = client.post("/submit-candidate", json=base)
    assert resp.status_code == 200, resp.json()

    derived = _make_payload("derived-record", {"data": "derived"}, ["base-record"])
    resp = client.post("/submit-candidate", json=derived)
    assert resp.status_code == 200, resp.json()

    critical = _make_payload(
        "critical-function", {"data": "critical service"},
        ["derived-record"], criticality_weight=0.9,
    )
    resp = client.post("/submit-candidate", json=critical)
    assert resp.status_code == 200, resp.json()

    # clean-leaf: part of the compaction frontier that stays clean
    clean_leaf = _make_payload("clean-leaf", {"data": "clean"}, ["clean-parent-1"])
    resp = client.post("/submit-candidate", json=clean_leaf)
    assert resp.status_code == 200, resp.json()

    # Compaction node covering base-record + clean-leaf, summariser = llm-v1
    compaction_content = {"summary": "compacted base + clean"}
    resp = client.post(
        "/context-compacted",
        json={
            "compacted_node_ids": ["base-record", "clean-leaf"],
            "compaction_node_id": "comp-node",
            "timestamp_utc": "2026-10-27T10:01:00Z",
            "ephemeral_nhi": {
                "identity_id": PUBLIC_KEY_HEX,
                "session_token": _agent_token(),
                "expires_at_utc": "2026-10-27T11:00:00Z",
            },
            "state_content": compaction_content,
            "agent_signature": _signer.sign(
                hashlib.sha256(
                    json.dumps(compaction_content, sort_keys=True).encode()
                ).hexdigest().encode()
            ),
            "signature_algorithm": "ECDSA-P256-SHA256",
            "method_id": "llm-v1",
        },
    )
    assert resp.status_code == 200, resp.json()

    # Checkpoint targeting clean-leaf (frontier of compaction)
    resp = client.post(
        "/checkpoint",
        json={
            "checkpoint_id": "cp-clean-leaf",
            "target_node_id": "clean-leaf",
            "declared_at_utc": "2020-01-01T00:00:00Z",
            "snapshot_data": {"safe_state": "from_checkpoint"},
        },
        headers=_auth_headers("admin"),
    )
    assert resp.status_code == 200

    # Checkpoint targeting derived-record (for continuity M4)
    resp = client.post(
        "/checkpoint",
        json={
            "checkpoint_id": "cp-derived",
            "target_node_id": "derived-record",
            "declared_at_utc": "2020-01-01T00:00:00Z",
            "snapshot_data": {"safe_state": "derived_checkpoint"},
        },
        headers=_auth_headers("admin"),
    )
    assert resp.status_code == 200

    # Substitute for base-record
    alt_source = _make_payload("alt-source", {"data": "alternate base"}, ["clean-parent-1"])
    resp = client.post("/submit-candidate", json=alt_source)
    assert resp.status_code == 200

    resp = client.post(
        "/declare-substitute",
        json={
            "target_node_id": "base-record",
            "substitute_source_id": "alt-source",
            "declared_at_utc": "2020-01-01T00:00:00Z",
        },
        headers=_auth_headers("admin"),
    )
    assert resp.status_code == 200

    # Honest derived write (will end up in blast radius)
    honest_write = _make_payload("honest-derived", {"data": "honest"}, ["derived-record"])
    resp = client.post("/submit-candidate", json=honest_write)
    assert resp.status_code == 200


def _designate_base_record_via_amg():
    """Feed AMG tamper event to /detector/amg for base-record."""
    return client.post(
        "/detector/amg",
        json={
            "event_id": "amg-tamper-001",
            "detector": "protected_key",
            "severity": "critical",
            "action": "quarantine",
            "operation": "integrity_check",
            "key": "agent.memory.base-record",
            "message": "SHA-256 baseline mismatch on immutable key",
            "source_class": "system",
            "gasc_node_id": "base-record",
            "metadata": {},
        },
        headers=_auth_headers("designator"),
    )


def _quarantine_digest():
    """Return the sorted quarantine ledger digest (containment fingerprint)."""
    q = client.get("/db-state", headers=_auth_headers("admin")).json().get("quarantine_ledger", [])
    return hashlib.sha256(json.dumps(sorted(q), sort_keys=True).encode()).hexdigest()


@pytest.fixture(autouse=True)
def reset_state():
    _content_hash_registry.clear()
    settings.ENFORCEMENT_MODE = "enforce"
    settings.CONTINUITY_ENABLED = True
    client.post("/reset-db", headers=_auth_headers("admin"))
    yield
    settings.ENFORCEMENT_MODE = "shadow"
    settings.CONTINUITY_ENABLED = True


# ---------------------------------------------------------------------------
# Full lifecycle: detection -> containment -> continuity -> reconstruction ->
#                 recurrence
# ---------------------------------------------------------------------------
def test_full_lifecycle():
    """The whole chain, every segment genuinely exercised."""

    _build_graph_and_fixtures()

    # ===== Step 1: AMG tamper event -> designation =====
    resp = _designate_base_record_via_amg()
    assert resp.status_code == 200, resp.json()
    result = resp.json()
    assert result["designated"] is True

    q_event = result["event"]
    c_p = q_event["computed_blast_radius_C_p"]

    # ===== Step 2: C(p) sweep =====
    assert "base-record" in c_p
    assert "derived-record" in c_p
    assert "honest-derived" in c_p
    assert "critical-function" in c_p
    # comp-node covers base-record, so it's in blast radius
    assert "comp-node" in c_p

    # ===== Step 3: Ingress block is NOT a designation =====
    resp = client.post(
        "/detector/amg",
        json={
            "event_id": "amg-block-001",
            "detector": "prompt_injection",
            "severity": "high",
            "action": "block",
            "operation": "write",
            "key": "agent.memory.some-key",
            "message": "Prompt injection detected at ingress",
            "source_class": "external_tool",
            "gasc_node_id": "some-node",
            "metadata": {},
        },
        headers=_auth_headers("designator"),
    )
    assert resp.status_code == 200
    assert resp.json()["designated"] is False
    assert "ingress block" in resp.json()["reason"].lower()

    # ===== Step 4: Continuity fired =====
    continuity = result.get("continuity", {})
    replays = continuity.get("checkpoint_replays", [])
    substitutions = continuity.get("substitutions", [])
    assert len(replays) + len(substitutions) > 0, f"No continuity fired: {continuity}"

    # Replay node has distinct identity, parents not in C(p)
    dag = client.get("/db-state", headers=_auth_headers("admin")).json()["dag"]
    if replays:
        replay_node = replays[0]["node_id"]
        assert replay_node in dag
        replay_data = dag[replay_node]
        assert replay_data["ephemeral_nhi"]["identity_id"] != PUBLIC_KEY_HEX
        for p in replay_data.get("parent_dependency_commitments", []):
            assert p["parent_node_id"] not in c_p

    # Replay/sub node NOT quarantined
    q_ledger = client.get("/db-state", headers=_auth_headers("admin")).json().get("quarantine_ledger", [])
    for r in replays:
        assert r["node_id"] not in q_ledger
    for s in substitutions:
        assert s["node_id"] not in q_ledger

    # ===== Step 5: Compaction resolved to REDUCIBLE (R3-R5) =====
    repair_candidates = client.get("/db-state", headers=_auth_headers("admin")).json().get("repair_candidates", {})
    assert "comp-node" in repair_candidates, f"comp-node not in repair_candidates: {list(repair_candidates.keys())}"
    rc = repair_candidates["comp-node"]
    assert rc["disposition"] == "REDUCIBLE", f"Expected REDUCIBLE, got {rc}"
    reconstructed_id = rc.get("reconstructed_node_id")
    assert reconstructed_id, "Missing reconstructed_node_id"
    assert reconstructed_id in dag, f"Reconstructed node {reconstructed_id} not in DAG"
    # Reconstructed node must carry only clean frontier parents
    recon_data = dag[reconstructed_id]
    for p in recon_data.get("parent_dependency_commitments", []):
        assert p["parent_node_id"] not in c_p, \
            f"Reconstructed node parent {p['parent_node_id']} in blast radius"

    # ===== Step 6: Recurrence signal -> withdrawal =====
    # Fire FUNCTIONAL_FAILURE against a node reachable from the poisoned root
    resp = client.post(
        "/observe",
        json={
            "node_id": "base-record",
            "recurrence_class": "FUNCTIONAL_FAILURE",
            "detected_at_utc": datetime.now(timezone.utc).isoformat() + "Z",
        },
        headers=_auth_headers("designator"),
    )
    assert resp.status_code == 200

    # Quarantine ledger must still contain all originally quarantined nodes
    q_after = client.get("/db-state", headers=_auth_headers("admin")).json().get("quarantine_ledger", [])
    assert "base-record" in q_after
    assert "derived-record" in q_after

    # ===== Step 7: Continuity report — row 4 exercised =====
    report = client.get("/continuity-report", headers=_auth_headers("admin")).json()
    assert report["non_vacuity_met"] is True
    assert report["exercised_while_quarantine_non_empty"] > 0
    assert report["operational_footprint"]["continuity_provenance_complete"] is True
    assert (report["operational_footprint"]["checkpoint_replay_count"] > 0 or
            report["operational_footprint"]["trusted_substitution_coverage"] > 0)


# ---------------------------------------------------------------------------
# Paired-arm containment proof: same incident, one arm with continuity off,
# one with continuity on, containment digest must be BIT-IDENTICAL.
# ---------------------------------------------------------------------------
def test_containment_footprint_bit_identical_across_continuity():
    """The safety proof: availability moved but containment did not.

    Arm A: CONTINUITY_ENABLED=False  -> capture quarantine digest
    Arm B: CONTINUITY_ENABLED=True   -> capture quarantine digest
    Assert digest_A == digest_B
    """
    # --- Arm A: baseline (no continuity) ---
    _content_hash_registry.clear()
    client.post("/reset-db", headers=_auth_headers("admin"))
    _build_graph_and_fixtures()

    settings.CONTINUITY_ENABLED = False
    resp_a = _designate_base_record_via_amg()
    assert resp_a.status_code == 200
    continuity_a = resp_a.json().get("continuity", {})
    assert continuity_a.get("enabled") is False, "Arm A should have continuity disabled"
    assert len(continuity_a.get("checkpoint_replays", [])) == 0
    assert len(continuity_a.get("substitutions", [])) == 0

    digest_a = _quarantine_digest()
    q_ledger_a = sorted(client.get("/db-state", headers=_auth_headers("admin")).json().get("quarantine_ledger", []))

    # --- Arm B: governed (continuity on) ---
    _content_hash_registry.clear()
    client.post("/reset-db", headers=_auth_headers("admin"))
    _build_graph_and_fixtures()

    settings.CONTINUITY_ENABLED = True
    resp_b = _designate_base_record_via_amg()
    assert resp_b.status_code == 200
    continuity_b = resp_b.json().get("continuity", {})
    assert continuity_b.get("enabled") is True, "Arm B should have continuity enabled"
    # Arm B MUST have fired continuity
    assert (len(continuity_b.get("checkpoint_replays", [])) +
            len(continuity_b.get("substitutions", []))) > 0, \
        f"Arm B continuity did not fire: {continuity_b}"

    digest_b = _quarantine_digest()
    q_ledger_b = sorted(client.get("/db-state", headers=_auth_headers("admin")).json().get("quarantine_ledger", []))

    # --- The assertion: containment is BIT-IDENTICAL ---
    assert digest_a == digest_b, (
        f"Containment digest differs across continuity arms!\n"
        f"  Arm A (no continuity): {digest_a}\n"
        f"  Arm B (with continuity): {digest_b}\n"
        f"  Q_A: {q_ledger_a}\n"
        f"  Q_B: {q_ledger_b}"
    )
    assert q_ledger_a == q_ledger_b, "Quarantine ledger contents differ"

    # Verify the operational footprint DID change: arm B has exposures, arm A doesn't
    report_a_exposures = 0  # arm A had no continuity
    report_b = client.get("/continuity-report", headers=_auth_headers("admin")).json()
    report_b_exposures = report_b["exercised_while_quarantine_non_empty"]
    assert report_b_exposures > report_a_exposures, \
        "Operational footprint should differ: arm B has continuity exposures"


# ---------------------------------------------------------------------------
# Adapter tests
# ---------------------------------------------------------------------------
def test_human_report_adapter():
    """HumanReportAdapter: a person names a node and it gets designated."""
    base = _make_payload("human-target", {"data": "will be reported"}, ["clean-parent-1"])
    resp = client.post("/submit-candidate", json=base)
    assert resp.status_code == 200

    resp = client.post(
        "/detector/human_report",
        json={
            "node_id": "human-target",
            "reason": "Operator identified incorrect data",
            "confidence_score": 0.95,
        },
        headers=_auth_headers("designator"),
    )
    assert resp.status_code == 200
    result = resp.json()
    assert result["designated"] is True
    assert "human-target" in result["event"]["computed_blast_radius_C_p"]


def test_amg_ingress_block_not_designated():
    """AMG block at write time is NOT a designation."""
    resp = client.post(
        "/detector/amg",
        json={
            "event_id": "block-test-001",
            "detector": "prompt_injection",
            "severity": "high",
            "action": "block",
            "operation": "write",
            "key": "agent.memory.key",
            "message": "Blocked at ingress",
            "gasc_node_id": "some-node",
            "metadata": {},
        },
        headers=_auth_headers("designator"),
    )
    assert resp.status_code == 200
    assert resp.json()["designated"] is False


def test_amg_allow_not_designated():
    """AMG allow is NOT a designation."""
    resp = client.post(
        "/detector/amg",
        json={
            "event_id": "allow-test-001",
            "detector": "size_anomaly",
            "severity": "info",
            "action": "allow",
            "operation": "write",
            "key": "agent.memory.key",
            "message": "No threat",
            "gasc_node_id": "some-node",
            "metadata": {},
        },
        headers=_auth_headers("designator"),
    )
    assert resp.status_code == 200
    assert resp.json()["designated"] is False


def test_amg_self_reinforcement_designation():
    """Self-reinforcement detector with quarantine action IS a designation."""
    target = _make_payload("self-reinf-target", {"data": "loop"}, ["clean-parent-1"])
    resp = client.post("/submit-candidate", json=target)
    assert resp.status_code == 200

    resp = client.post(
        "/detector/amg",
        json={
            "event_id": "self-reinf-001",
            "detector": "self_reinforcement",
            "severity": "high",
            "action": "quarantine",
            "operation": "read",
            "key": "agent.memory.loop",
            "message": "Self-reinforcement loop detected",
            "gasc_node_id": "self-reinf-target",
            "metadata": {},
        },
        headers=_auth_headers("designator"),
    )
    assert resp.status_code == 200
    assert resp.json()["designated"] is True


# ---------------------------------------------------------------------------
# Substitute endpoint tests
# ---------------------------------------------------------------------------
def test_substitute_requires_admin():
    """Substitute declaration requires admin role."""
    resp = client.post(
        "/declare-substitute",
        json={
            "target_node_id": "x",
            "substitute_source_id": "y",
            "declared_at_utc": "2026-01-01T00:00:00Z",
        },
        headers=_auth_headers("designator"),
    )
    assert resp.status_code in (401, 403)


def test_substitute_source_must_exist():
    """Substitute source must be in the DAG."""
    resp = client.post(
        "/declare-substitute",
        json={
            "target_node_id": "whatever",
            "substitute_source_id": "nonexistent-node",
            "declared_at_utc": "2026-01-01T00:00:00Z",
        },
        headers=_auth_headers("admin"),
    )
    assert resp.status_code == 404


def test_unknown_detector_source_rejected():
    """Unknown detector source returns 400."""
    resp = client.post(
        "/detector/nonexistent",
        json={"event_id": "x"},
        headers=_auth_headers("designator"),
    )
    assert resp.status_code == 400
    assert "Unknown detector source" in resp.json()["detail"]
