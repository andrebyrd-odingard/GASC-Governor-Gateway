import pytest
import uuid
import json
from pathlib import Path
from fastapi.testclient import TestClient
from src.governor_service import app
from src.gasc_audit_engine import GASCAuditEngine

client = TestClient(app)

@pytest.fixture(autouse=True)
def reset_db():
    client.post("/reset-db")

def create_payload(action, parent_id):
    return {
        "payload_id": str(uuid.uuid4()),
        "timestamp_utc": "2026-10-27T10:00:00Z",
        "ephemeral_nhi": {
            "identity_id": "agent-test",
            "session_token": "token",
            "expires_at_utc": "2026-10-27T11:00:00Z"
        },
        "declared_evidence_boundary": {
            "boundary_id": "b1",
            "fixed_at_utc": "2026-10-26T00:00:00Z",
            "boundary_digest": "f" * 64
        },
        "parent_dependency_commitments": [{
            "parent_node_id": parent_id,
            "parent_content_hash": "e" * 64
        }],
        "state_content": {"action": action},
        "content_digest_sha256": "d" * 64,
        "agent_signature": "signature"
    }

def test_adversarial_fault_injection():
    # 1. Agent A creates an order
    order_payload = create_payload("create_order", "clean-parent-1")
    response_a = client.post("/submit-candidate", json=order_payload)
    assert response_a.status_code == 200
    
    order_id = order_payload["payload_id"]
    
    # 2. Inject Poison Pill (Zero-Day bypasses Governor and directly alters DB)
    db_state = client.get("/db-state").json()
    # We simulate discovering the node is poisoned by adding it to the quarantine ledger
    # In reality, a separate monitor or intrusion detection system would do this.
    db_state["quarantine_ledger"].append(order_id)
    
    # We have to patch the in-memory db directly for this test since /db-state is read-only
    # Let's use the app's internal db object
    from src.governor_service import db
    db["quarantine_ledger"].append(order_id)
    
    # 3. Agent B processes payment based on the poisoned order
    payment_payload = create_payload("process_payment", order_id)
    response_b = client.post("/submit-candidate", json=payment_payload)
    
    # 4. Assertions
    # Assertion 1 (Containment): Governor rejects write
    assert response_b.status_code == 403
    error_detail = response_b.json()["detail"]
    assert error_detail["error"] == "TAINTED_PARENT"
    
    # Assertion 2 (Blast Radius): Correctly calculate C(p)
    event = error_detail["event"]
    assert order_id in event["computed_blast_radius_C_p"]
    assert payment_payload["payload_id"] in event["computed_blast_radius_C_p"]
    
    # Assertion 3 (Audit Trail): Verify with Audit Engine
    db_state = client.get("/db-state").json()
    
    audit_manifest = {
        "boundary_id": "BOUNDARY-TEST",
        "operating_envelope_declaration": "E2E Test Envelope",
        "admitted_writes": [order_payload],
        "quarantine_incidents": db_state["quarantine_events"],
        "quarantine_transitions": [
            {"quarantine_set": ["quarantined-node-A"]},
            {"quarantine_set": ["quarantined-node-A", order_id]},
            {"quarantine_set": ["quarantined-node-A", order_id, payment_payload["payload_id"]]}
        ],
        "fault_injection_campaign": {
            "preregistered_suite_run": True,
            "shared_dependency_inventory_published": True,
            "observed_catch_rate": 1.0,
            "preregistered_target_catch_rate": 0.95
        }
    }
    
    manifest_path = Path(__file__).parent / "temp_audit_manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(audit_manifest, f)
        
    engine = GASCAuditEngine(str(manifest_path))
    results = engine.run_full_audit()
    manifest_path.unlink()
    
    assert results["conformance_summary"]["overall_audit_passed"] is True
    
    # Specifically check REQ-002 (Transitive Containment)
    req_2_result = next(r for r in results["row_by_row_results"] if r["req_id"] == "GASC-REQ-002")
    assert req_2_result["status"] == "PASS"
