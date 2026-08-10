import pytest
import json
import hashlib
import jwt
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from tests.conftest import JWT_PRIVATE_KEY_PEM
from src.governor_service import app, settings
from tests.test_integration import create_valid_payload, _signer

client = TestClient(app)

@pytest.fixture(autouse=True)
def shadow_mode_override():
    # Make sure we're testing shadow mode behavior
    original_mode = settings.ENFORCEMENT_MODE
    settings.ENFORCEMENT_MODE = "shadow"
    yield
    settings.ENFORCEMENT_MODE = original_mode

def generate_admin_token():
    return jwt.encode({"sub": "admin-user", "role": "admin"}, JWT_PRIVATE_KEY_PEM, algorithm="ES256")

def generate_designator_token():
    return jwt.encode({"sub": "designator", "role": "designator"}, JWT_PRIVATE_KEY_PEM, algorithm="ES256")

@pytest.fixture(autouse=True)
def reset_db():
    client.post("/reset-db", headers={"Authorization": f"Bearer {generate_admin_token()}"})

def test_shadow_mode_invalid_signature_is_blocked():
    payload = create_valid_payload()
    payload["agent_signature"] = "bad"
    payload["signature_algorithm"] = "ECDSA-P256-SHA256"
    
    response = client.post("/submit-candidate", json=payload)
    assert response.status_code == 401

def test_shadow_mode_invalid_schema_is_blocked():
    response = client.post("/submit-candidate", json={"missing": "fields"})
    assert response.status_code == 400

def test_shadow_mode_policy_violation_admitted_and_recorded():
    # Create valid node
    payload1 = create_valid_payload()
    payload1["payload_id"] = "test-1"
    response = client.post("/submit-candidate", json=payload1)
    assert response.status_code == 200
    
    # Designate node as compromised
    designate_event = {
        "poisoned_node_id": "test-1",
        "detected_at_utc": "2026-10-27T10:15:00Z",
        "source": "human_report",
        "confidence_score": 0.99,
        "reason": "Test"
    }
    resp = client.post("/designate", json=designate_event, headers={"Authorization": f"Bearer {generate_designator_token()}"})
    assert resp.status_code == 200
    
    # Build on quarantined node
    payload2 = create_valid_payload()
    payload2["payload_id"] = "test-2"
    payload2["parent_dependency_commitments"] = [{"parent_node_id": "test-1", "parent_content_hash": payload1["content_digest_sha256"]}]
    content_str = json.dumps(payload2["state_content"], sort_keys=True)
    actual_hash = hashlib.sha256(content_str.encode()).hexdigest()
    payload2["content_digest_sha256"] = actual_hash
    payload2["agent_signature"] = _signer.sign(actual_hash.encode())
    payload2["signature_algorithm"] = "ECDSA-P256-SHA256"
    
    # In enforcement mode, this returns 403. In shadow, it returns 200.
    response2 = client.post("/submit-candidate", json=payload2)
    assert response2.status_code == 200
    
    # Verify shadow decision was recorded
    report = client.get("/shadow-report", headers={"Authorization": f"Bearer {generate_admin_token()}"})
    assert report.status_code == 200
    report_data = report.json()
    assert report_data["counterfactual_rejections"] > 0
    assert "caveat" in report_data

def test_shadow_mode_verification_violation_admitted_and_recorded():
    payload = create_valid_payload()
    payload["payload_id"] = "test-v-fail"
    payload["state_content"]["justification"] = "Because I said so"
    
    content_str = json.dumps(payload["state_content"], sort_keys=True)
    actual_hash = hashlib.sha256(content_str.encode()).hexdigest()
    payload["content_digest_sha256"] = actual_hash
    payload["agent_signature"] = _signer.sign(actual_hash.encode())
    payload["signature_algorithm"] = "ECDSA-P256-SHA256"
    
    response = client.post("/submit-candidate", json=payload)
    assert response.status_code == 200
    
    report = client.get("/shadow-report", headers={"Authorization": f"Bearer {generate_admin_token()}"})
    assert report.status_code == 200
    report_data = report.json()
    # It might be 1 or more depending on db state but > 0 ensures it got recorded
    assert report_data["counterfactual_rejections"] > 0
