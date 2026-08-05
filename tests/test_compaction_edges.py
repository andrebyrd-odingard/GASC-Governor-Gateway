import pytest
import json
import hashlib
import jwt
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from ecdsa import SigningKey, NIST256p

from tests.conftest import JWT_PRIVATE_KEY_PEM
from src.governor_service import app

client = TestClient(app)

sk = SigningKey.generate(curve=NIST256p)
PUBLIC_KEY_HEX = sk.verifying_key.to_string().hex()

def generate_admin_token():
    return jwt.encode({"sub": "admin", "role": "admin"}, JWT_PRIVATE_KEY_PEM, algorithm="ES256")

def generate_designator_token():
    return jwt.encode({"sub": "webhook", "role": "designator"}, JWT_PRIVATE_KEY_PEM, algorithm="ES256")

def generate_generic_token():
    return jwt.encode({"sub": "user", "role": "user"}, JWT_PRIVATE_KEY_PEM, algorithm="ES256")

@pytest.fixture(autouse=True)
def reset_db():
    client.post("/reset-db", headers={"Authorization": f"Bearer {generate_admin_token()}"})

def create_payload(payload_id, parent_id, state_content, is_compaction=False):
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

    payload = {
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
    
    if is_compaction:
        payload["node_type"] = "COMPACTION"
        payload["covers"] = [parent_id]
        payload["summarizer"] = {"method_id": "llm-v1", "config_digest": "..."}
        payload["parent_dependency_commitments"][0]["edge_class"] = "CARRIED"
        
    return payload

def test_compaction_edge_fail_closed_routing():
    # 1. Standard node-a
    p1 = create_payload("node-a", "clean-parent-1", {"data": "raw data"})
    assert client.post("/submit-candidate", json=p1).status_code == 200
    
    # 2. Compaction node summarizing node-a
    p2 = create_payload("compaction-1", "node-a", {"data": "summarized"}, is_compaction=True)
    assert client.post("/submit-candidate", json=p2).status_code == 200
    
    # 3. Downstream node building on the summary (1 hop past compaction)
    p3 = create_payload("node-b", "compaction-1", {"data": "post-compaction action"})
    assert client.post("/submit-candidate", json=p3).status_code == 200

    # 4. Another downstream node building on node-b (2 hops past compaction)
    p4 = create_payload("node-c", "node-b", {"data": "2nd-hop-action"})
    assert client.post("/submit-candidate", json=p4).status_code == 200
    
    # 5. Designate the upstream node-a as poisoned
    designate_event = {
        "poisoned_node_id": "node-a",
        "detected_at_utc": "2026-10-27T10:15:00Z",
        "source": "amg_tamper_check",
        "confidence_score": 0.99,
        "reason": "Poisoned before compaction"
    }
    resp = client.post("/designate", json=designate_event, headers={"Authorization": f"Bearer {generate_designator_token()}"})
    assert resp.status_code == 200
    
    # Assertions on the blast radius computation
    event_data = resp.json()["event"]
    c_p = event_data["computed_blast_radius_C_p"]
    
    # The compaction node MUST be in C_p 
    assert "compaction-1" in c_p
    # The descendants MUST be in C_p (2 hops past compaction proves no depth-bounding)
    assert "node-b" in c_p
    assert "node-c" in c_p
    
    # 6. Assertions on the repair candidates & ledger (auditability)
    db_state = client.get("/db-state", headers={"Authorization": f"Bearer {generate_admin_token()}"}).json()
    repair_candidates = db_state["repair_candidates"]
    ledger = db_state["quarantine_ledger"]
    
    # Compaction node is in BOTH repair_candidates and quarantine_ledger
    assert "compaction-1" in repair_candidates
    assert "compaction-1" in ledger
    assert repair_candidates["compaction-1"]["disposition"] == "IRREDUCIBLE"
    assert repair_candidates["compaction-1"]["reason"] == "no_reconstruction_backend"
    
    # Descendants are in quarantine_ledger
    assert "node-b" in ledger
    assert "node-c" in ledger
    
    # Conformance Row 9 Assertion: Irreducible fraction is 100%. 
    # This mathematically scores as NOT-EXERCISED per CSR-PUB-0005 §7.3 
    # since no node is successfully re-derived.
    for node_id, data in repair_candidates.items():
        assert data["disposition"] == "IRREDUCIBLE"

def test_designate_auth_failures():
    designate_event = {
        "poisoned_node_id": "clean-parent-1",
        "detected_at_utc": "2026-10-27T10:15:00Z",
        "source": "amg_tamper_check",
        "confidence_score": 0.99,
        "reason": "Tamper detected"
    }
    # No token
    assert client.post("/designate", json=designate_event).status_code == 401
    # Invalid token (non-designator)
    assert client.post("/designate", json=designate_event, headers={"Authorization": f"Bearer {generate_generic_token()}"}).status_code == 401

def test_reset_db_auth_failures():
    # No token
    assert client.post("/reset-db").status_code == 401
    # Invalid token (non-admin)
    assert client.post("/reset-db", headers={"Authorization": f"Bearer {generate_generic_token()}"}).status_code == 401

def test_designate_idempotency():
    # Designate clean-parent-1
    designate_event = {
        "poisoned_node_id": "clean-parent-1",
        "detected_at_utc": "2026-10-27T10:15:00Z",
        "source": "amg_tamper_check",
        "confidence_score": 0.99,
        "reason": "Tamper detected"
    }
    resp1 = client.post("/designate", json=designate_event, headers={"Authorization": f"Bearer {generate_designator_token()}"})
    assert resp1.status_code == 200
    
    db_state_1 = client.get("/db-state", headers={"Authorization": f"Bearer {generate_admin_token()}"}).json()
    ledger_count_1 = len(db_state_1["quarantine_ledger"])
    
    # Designate again
    resp2 = client.post("/designate", json=designate_event, headers={"Authorization": f"Bearer {generate_designator_token()}"})
    assert resp2.status_code == 200
    assert resp2.json()["message"] == "Node already in quarantine ledger"
    
    db_state_2 = client.get("/db-state", headers={"Authorization": f"Bearer {generate_admin_token()}"}).json()
    ledger_count_2 = len(db_state_2["quarantine_ledger"])
    
    # Ensure ledger didn't duplicate
    assert ledger_count_1 == ledger_count_2
