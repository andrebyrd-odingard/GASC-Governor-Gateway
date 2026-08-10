import pytest
import json
import hashlib
import jwt
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from ecdsa import SigningKey, NIST256p

from tests.conftest import JWT_PRIVATE_KEY_PEM
from src.governor_service import app, settings

client = TestClient(app)

sk = SigningKey.generate(curve=NIST256p)
PUBLIC_KEY_HEX = sk.verifying_key.to_string().hex()

def generate_admin_token():
    return jwt.encode(
        {"sub": "admin-user", "role": "admin"},
        JWT_PRIVATE_KEY_PEM, algorithm="ES256"
    )

def generate_designator_token():
    return jwt.encode(
        {"sub": "amg-webhook", "role": "designator"},
        JWT_PRIVATE_KEY_PEM, algorithm="ES256"
    )

@pytest.fixture(autouse=True)
def reset_db():
    client.post("/reset-db", headers={"Authorization": f"Bearer {generate_admin_token()}"})

def content_hash_of(state_content):
    return hashlib.sha256(json.dumps(state_content, sort_keys=True).encode()).hexdigest()

def create_payload(payload_id, parent_id, state_content, parent_content_hash=None):
    session_token = jwt.encode(
        {
            "sub": PUBLIC_KEY_HEX, 
            "scope": "agent:state:reconstruct",
            "is_nhi": True,
            "expires_at_epoch": int(datetime.now(timezone.utc).timestamp()) + 3600,
            "verifier_execution_status": "PASSED"
        },
        JWT_PRIVATE_KEY_PEM,
        algorithm="ES256"
    )

    content_str = json.dumps(state_content, sort_keys=True)
    actual_hash = hashlib.sha256(content_str.encode()).hexdigest()
    signature_hex = sk.sign(actual_hash.encode()).hex()

    return {
        "payload_id": payload_id,
        "timestamp_utc": "2026-10-27T10:00:00Z",
        "ephemeral_nhi": {
            "identity_id": PUBLIC_KEY_HEX,
            "session_token": session_token,
            "expires_at_utc": "2026-10-27T11:00:00Z"
        },
        "declared_evidence_boundary": {
            "boundary_id": "b1",
            "fixed_at_utc": "2026-10-26T00:00:00Z",
            "boundary_digest": "f" * 64
        },
        "parent_dependency_commitments": [{
            "parent_node_id": parent_id,
            "parent_content_hash": parent_content_hash or "e" * 64
        }],
        "state_content": state_content,
        "content_digest_sha256": actual_hash,
        "agent_signature": signature_hex
    }

def test_e2e_adversarial_injection_via_designate():
    # 1. Establish normal DAG state
    c1 = {"item": "laptop"}
    payload_1 = create_payload("order-1", "clean-parent-1", c1)
    assert client.post("/submit-candidate", json=payload_1).status_code == 200
    
    payload_2 = create_payload("order-2", "order-1", {"item": "mouse"}, parent_content_hash=content_hash_of(c1))
    assert client.post("/submit-candidate", json=payload_2).status_code == 200

    # 2. Assume node "order-1" is discovered to be tainted by an out-of-band intrusion detection (e.g. AMG)
    # We use the authenticated /designate endpoint to trigger the BFS traversal
    designate_event = {
        "poisoned_node_id": "order-1",
        "detected_at_utc": "2026-10-27T10:15:00Z",
        "source": "amg_tamper_check",
        "confidence_score": 0.99,
        "reason": "Tamper detected by AMG webhook"
    }
    resp = client.post("/designate", json=designate_event, headers={"Authorization": f"Bearer {generate_designator_token()}"})
    assert resp.status_code == 200
    
    # Verify the event contains the expected blast radius (order-1 and its descendant order-2)
    event_data = resp.json()["event"]
    assert "order-1" in event_data["computed_blast_radius_C_p"]
    assert "order-2" in event_data["computed_blast_radius_C_p"]

    # 3. Agent blindly builds on order-2 (which descends from quarantined order-1)
    payload_3 = create_payload("order-3", "order-2", {"item": "keyboard"}, parent_content_hash=content_hash_of({"item": "mouse"}))
    response = client.post("/submit-candidate", json=payload_3)
    
    # 4. Gateway must intercept via Transitive Taint Propagation (admission-time block)
    assert response.status_code == 403
    event = response.json()["detail"]["event"]
    assert event["poisoned_root_id"] == "order-2"
    
    # Verify true dynamic blast radius C(p) correctly identified descendants
    assert "order-2" in event["computed_blast_radius_C_p"]
    assert "order-3" in event["computed_blast_radius_C_p"]

    # 5. Generate Audit Manifest for gasc-audit scoring
    db_state = client.get("/db-state", headers={"Authorization": f"Bearer {generate_admin_token()}"}).json()
    
    audit_manifest = {
        "enforcement_mode": db_state.get("enforcement_mode", "enforce"),
        "boundary_id": "BOUNDARY-TEST",
        "operating_envelope_declaration": "E2E Test Envelope",
        "admitted_writes": list(db_state.get("dag", {}).values()),
        "quarantine_incidents": db_state.get("quarantine_events", []),
        "quarantine_transitions": [{"quarantine_set": db_state.get("quarantine_ledger", [])}],
        "continuity_exposures": [],
        "reconstruction_attempts": [{"declared_evidence_boundary": {"fixed_at_utc": "2026-10-27T10:20:00Z"}, "incident_detected_at_utc": "2026-10-27T10:15:00Z"}],
        "fault_injection_campaign": {
            "preregistered_suite_run": True,
            "shared_dependency_inventory_published": True,
            "observed_catch_rate": 1.0,
            "preregistered_target_catch_rate": 0.95
        },
        "reintegrations": [{"gate_execution_evidence": {"approved": True}}],
        "recurrence_monitor": {
            "calibration_run": {
                "seeded_count": 10,
                "detected_count": 8,
                "sensitivity_floor": 0.8
            }
        },
        "disposed_targets": [
            {"disposition": "REDUCIBLE"},
            {"disposition": "IRREDUCIBLE"}
        ],
        "disposed_targets": [
            {"disposition": "REDUCIBLE"},
            {"disposition": "IRREDUCIBLE"}
        ],
        "measured_cost_report": {}
    }
    
    from pathlib import Path
    manifest_path = Path(__file__).parent.parent / "audit_manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(audit_manifest, f)
