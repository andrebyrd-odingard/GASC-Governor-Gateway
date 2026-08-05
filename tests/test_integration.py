import pytest
from fastapi.testclient import TestClient
from src.governor_service import app
import uuid

client = TestClient(app)

@pytest.fixture(autouse=True)
def reset_db():
    client.post("/reset-db")

def create_valid_payload(parent_id="clean-parent-1"):
    return {
        "payload_id": str(uuid.uuid4()),
        "timestamp_utc": "2026-10-27T10:00:00Z",
        "ephemeral_nhi": {
            "identity_id": "agent-1",
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
        "state_content": {"action": "create_order"},
        "content_digest_sha256": "d" * 64,
        "agent_signature": "signature"
    }

def test_integration_submit_valid_payload():
    payload = create_valid_payload()
    response = client.post("/submit-candidate", json=payload)
    
    assert response.status_code == 200
    assert response.json()["status"] == "success"
    
    db_state = client.get("/db-state").json()
    assert payload["payload_id"] in db_state["dag"]

def test_integration_submit_lineage_failure():
    # Provide a parent that doesn't exist
    payload = create_valid_payload(parent_id="non-existent-parent")
    response = client.post("/submit-candidate", json=payload)
    
    assert response.status_code == 400
    assert "Lineage or Monotonicity Invalid" in response.json()["detail"]

def test_integration_submit_tainted_parent():
    # Use a parent known to be in the quarantine ledger
    payload = create_valid_payload(parent_id="quarantined-node-A")
    response = client.post("/submit-candidate", json=payload)
    
    # Should get 403 and the event should be logged
    assert response.status_code == 403
    error_detail = response.json()["detail"]
    assert error_detail["error"] == "TAINTED_PARENT"
    assert error_detail["event"]["poisoned_root_id"] == "quarantined-node-A"

def test_integration_submit_verification_failure():
    # Payload valid structurally, but has forbidden "justification" output
    payload = create_valid_payload()
    payload["state_content"]["justification"] = "Because I said so"
    
    response = client.post("/submit-candidate", json=payload)
    
    assert response.status_code == 403
    assert "Verification Separation Policy Failed" in response.json()["detail"]
