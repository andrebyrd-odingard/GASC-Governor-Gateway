import pytest
import json
import hashlib
import jwt
from datetime import datetime, timezone
from ecdsa import SigningKey, NIST256p
from fastapi.testclient import TestClient

from tests.conftest import JWT_PRIVATE_KEY_PEM
from src.governor_service import app, settings

client = TestClient(app)

# 2. Generate Identity Keypair (ECDSA)
sk = SigningKey.generate(curve=NIST256p)
vk = sk.verifying_key
PUBLIC_KEY_HEX = vk.to_string().hex()

def generate_admin_token():
    return jwt.encode({"sub": "admin", "role": "admin"}, JWT_PRIVATE_KEY_PEM, algorithm="ES256")

@pytest.fixture(autouse=True)
def reset_db():
    client.post("/reset-db", headers={"Authorization": f"Bearer {generate_admin_token()}"})

def create_valid_payload(parent_id="clean-parent-1"):
    # Create valid JWT
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

    state_content = {"action": "create_order"}
    content_str = json.dumps(state_content, sort_keys=True)
    actual_hash = hashlib.sha256(content_str.encode()).hexdigest()

    # Sign the actual hash
    signature_bytes = sk.sign(actual_hash.encode())
    signature_hex = signature_bytes.hex()

    return {
        "payload_id": "payload-" + hashlib.md5(str(datetime.now()).encode()).hexdigest(),
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
            "parent_content_hash": "e" * 64
        }],
        "state_content": state_content,
        "content_digest_sha256": actual_hash,
        "agent_signature": signature_hex
    }

def test_integration_submit_valid_payload():
    payload = create_valid_payload()
    response = client.post("/submit-candidate", json=payload)
    
    print(response.json())
    assert response.status_code == 200
    assert response.json()["status"] == "success"
    
    db_state = client.get("/db-state", headers={"Authorization": f"Bearer {generate_admin_token()}"}).json()
    assert payload["payload_id"] in db_state["dag"]

def test_integration_submit_invalid_signature():
    payload = create_valid_payload()
    payload["agent_signature"] = "deadbeef" * 8  # invalid sig
    response = client.post("/submit-candidate", json=payload)
    assert response.status_code == 401
    assert "Cryptographic signature verification failed" in response.json()["detail"]

def test_integration_submit_invalid_jwt():
    payload = create_valid_payload()
    payload["ephemeral_nhi"]["session_token"] = "invalid.jwt.token"
    response = client.post("/submit-candidate", json=payload)
    assert response.status_code == 401
    assert "Invalid Session Token" in response.json()["detail"]

def test_integration_submit_jwt_identity_mismatch():
    payload = create_valid_payload()
    # Provide a different pubkey in the payload to spoof identity
    sk2 = SigningKey.generate(curve=NIST256p)
    payload["ephemeral_nhi"]["identity_id"] = sk2.verifying_key.to_string().hex()
    
    response = client.post("/submit-candidate", json=payload)
    assert response.status_code == 401
    assert "JWT subject does not match payload identity" in response.json()["detail"]

def test_integration_submit_lineage_failure():
    payload = create_valid_payload(parent_id="non-existent-parent")
    response = client.post("/submit-candidate", json=payload)
    

    assert response.status_code == 400
    assert "Lineage or Monotonicity Invalid" in response.json()["detail"]

def test_integration_submit_tainted_parent():
    payload = create_valid_payload(parent_id="quarantined-node-A")
    response = client.post("/submit-candidate", json=payload)
    
    assert response.status_code == 403
    error_detail = response.json()["detail"]
    assert error_detail["error"] == "TAINTED_PARENT"
    assert error_detail["event"]["poisoned_root_id"] == "quarantined-node-A"
    assert payload["payload_id"] in error_detail["event"]["computed_blast_radius_C_p"]
    assert "quarantined-node-A" in error_detail["event"]["computed_blast_radius_C_p"]

def test_integration_submit_verification_failure():
    payload = create_valid_payload()
    payload["state_content"]["justification"] = "Because I said so"
    
    # Must resign because content changed
    content_str = json.dumps(payload["state_content"], sort_keys=True)
    actual_hash = hashlib.sha256(content_str.encode()).hexdigest()
    payload["content_digest_sha256"] = actual_hash
    payload["agent_signature"] = sk.sign(actual_hash.encode()).hex()
    
    response = client.post("/submit-candidate", json=payload)
    
    assert response.status_code == 403
    assert "Verification Separation Policy Failed" in response.json()["detail"]
