import pytest
import json
import hashlib
import jwt
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from ecdsa import SigningKey, NIST256p
from src.governor_service import app, settings

client = TestClient(app)

sk = SigningKey.generate(curve=NIST256p)
PUBLIC_KEY_HEX = sk.verifying_key.to_string().hex()

@pytest.fixture(autouse=True)
def reset_db():
    client.post("/reset-db")

def create_payload(payload_id, parent_id, state_content):
    session_token = jwt.encode(
        {
            "sub": PUBLIC_KEY_HEX, 
            "scope": "agent:state:reconstruct",
            "is_nhi": True,
            "expires_at_epoch": int(datetime.now(timezone.utc).timestamp()) + 3600
        },
        settings.JWT_SECRET,
        algorithm="HS256"
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
            "parent_content_hash": "e" * 64
        }],
        "state_content": state_content,
        "content_digest_sha256": actual_hash,
        "agent_signature": signature_hex
    }

def test_e2e_adversarial_injection():
    # 1. Establish normal DAG state
    payload_1 = create_payload("order-1", "clean-parent-1", {"item": "laptop"})
    assert client.post("/submit-candidate", json=payload_1).status_code == 200
    
    payload_2 = create_payload("order-2", "order-1", {"item": "mouse"})
    assert client.post("/submit-candidate", json=payload_2).status_code == 200

    # 2. Assume node "order-1" is discovered to be tainted by an out-of-band intrusion detection
    # We patch the DB to quarantine order-1 and its descendants (simulate the detection)
    from src.governor_service import backend
    import asyncio
    async def simulate_detection():
        c_p = await backend.compute_blast_radius("order-1")
        for node in c_p:
            await backend.add_to_quarantine_ledger(node)
    asyncio.run(simulate_detection())

    # 3. Agent blindly builds on order-2 (which descends from quarantined order-1)
    payload_3 = create_payload("order-3", "order-2", {"item": "keyboard"})
    response = client.post("/submit-candidate", json=payload_3)
    
    # 4. Gateway must intercept via Transitive Taint Propagation
    assert response.status_code == 403
    event = response.json()["detail"]["event"]
    assert event["poisoned_root_id"] == "order-2"
    
    # Verify true dynamic blast radius C(p) correctly identified descendants
    assert "order-2" in event["computed_blast_radius_C_p"]
    assert "order-3" in event["computed_blast_radius_C_p"]
