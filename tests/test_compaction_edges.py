import pytest
import json
import hashlib
import jwt
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from tests.conftest import ECDSASigner
from tests.conftest import JWT_PRIVATE_KEY_PEM
from src.governor_service import app

client = TestClient(app)

_signer = ECDSASigner()
PUBLIC_KEY_HEX = _signer.public_key_hex

def generate_admin_token():
    return jwt.encode({"sub": "admin", "role": "admin"}, JWT_PRIVATE_KEY_PEM, algorithm="ES256")

def generate_designator_token():
    return jwt.encode({"sub": "webhook", "role": "designator"}, JWT_PRIVATE_KEY_PEM, algorithm="ES256")

def generate_generic_token():
    return jwt.encode({"sub": "user", "role": "user"}, JWT_PRIVATE_KEY_PEM, algorithm="ES256")

def content_hash_of(state_content):
    """Compute the content_digest_sha256 for a given state_content dict."""
    return hashlib.sha256(json.dumps(state_content, sort_keys=True).encode()).hexdigest()

@pytest.fixture(autouse=True)
def reset_db():
    client.post("/reset-db", headers={"Authorization": f"Bearer {generate_admin_token()}"})

def create_payload(payload_id, parent_id, state_content, is_compaction=False, parent_content_hash=None):
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
    signature_hex = _signer.sign(actual_hash.encode())

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
            "parent_content_hash": parent_content_hash or "e" * 64
        }],
        "state_content": state_content,
        "content_digest_sha256": actual_hash,
        "agent_signature": signature_hex,
        "signature_algorithm": "ECDSA-P256-SHA256"
    }
    
    if is_compaction:
        payload["node_type"] = "COMPACTION"
        payload["covers"] = [parent_id]
        payload["summarizer"] = {"method_id": "llm-v1", "config_digest": "..."}
        payload["parent_dependency_commitments"][0]["edge_class"] = "CARRIED"
        
    return payload

def test_compaction_edge_fail_closed_routing():
    # 1. Standard node-a
    node_a_content = {"data": "raw data"}
    p1 = create_payload("node-a", "clean-parent-1", node_a_content)
    assert client.post("/submit-candidate", json=p1).status_code == 200
    
    # 2. Compaction node summarizing node-a
    comp_content = {"data": "summarized"}
    p2 = create_payload("compaction-1", "node-a", comp_content, is_compaction=True, parent_content_hash=content_hash_of(node_a_content))
    p2["covers"] = ["clean-parent-1", "node-a"]
    p2["summarizer"] = {"method_id": "llm-v1"}
    assert client.post("/submit-candidate", json=p2).status_code == 200
    
    # 3. Downstream node building on the summary (1 hop past compaction)
    node_b_content = {"data": "post-compaction action"}
    p3 = create_payload("node-b", "compaction-1", node_b_content, parent_content_hash=content_hash_of(comp_content))
    assert client.post("/submit-candidate", json=p3).status_code == 200

    # 4. Another downstream node building on node-b (2 hops past compaction)
    p4 = create_payload("node-c", "node-b", {"data": "2nd-hop-action"}, parent_content_hash=content_hash_of(node_b_content))
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
    assert repair_candidates["compaction-1"]["reason"] == "no_admissible_checkpoint"
    
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

def test_covers_interval_gap_computation():
    # Chain: node-1 -> node-2 -> node-3
    c1 = {"data": "1"}
    p1 = create_payload("node-1", "clean-parent-1", c1)
    assert client.post("/submit-candidate", json=p1).status_code == 200
    
    c2 = {"data": "2"}
    p2 = create_payload("node-2", "node-1", c2, parent_content_hash=content_hash_of(c1))
    assert client.post("/submit-candidate", json=p2).status_code == 200
    
    c3 = {"data": "3"}
    p3 = create_payload("node-3", "node-2", c3, parent_content_hash=content_hash_of(c2))
    assert client.post("/submit-candidate", json=p3).status_code == 200
    
    # Compaction covering node-1 and node-3, omitting node-2
    p4 = create_payload("compaction-gap", "node-3", {"data": "summary"}, is_compaction=True, parent_content_hash=content_hash_of(c3))
    p4["covers"] = ["node-1", "node-3"]
    assert client.post("/submit-candidate", json=p4).status_code == 200
    
    db_state = client.get("/db-state", headers={"Authorization": f"Bearer {generate_admin_token()}"}).json()
    gap = db_state["dag"]["compaction-gap"]["covers_interval_gap"]
    
import respx

def test_checkpoint_api_auth():
    chk = {
        "checkpoint_id": "cp1",
        "target_node_id": "node-1",
        "declared_at_utc": "2026-10-27T00:00:00Z",
        "snapshot_data": {}
    }
    # No auth
    assert client.post("/checkpoint", json=chk).status_code == 401
    # Designator auth
    assert client.post("/checkpoint", json=chk, headers={"Authorization": f"Bearer {generate_designator_token()}"}).status_code == 401
    # Admin auth
    assert client.post("/checkpoint", json=chk, headers={"Authorization": f"Bearer {generate_admin_token()}"}).status_code == 200

def test_reconstruction_failure_paths():
    # Setup chain: node-1 -> comp
    c1 = {"data": "1"}
    p1 = create_payload("node-1", "clean-parent-1", c1)
    assert client.post("/submit-candidate", json=p1).status_code == 200
    
    comp = create_payload("comp-fail", "node-1", {"data": "summary"}, is_compaction=True, parent_content_hash=content_hash_of(c1))
    comp["covers"] = ["clean-parent-1", "node-1"]
    comp["summarizer"] = {"method_id": "llm-v1"}
    assert client.post("/submit-candidate", json=comp).status_code == 200
    
    # 1. No checkpoint -> no_admissible_checkpoint
    desig = {
        "poisoned_node_id": "node-1",
        "detected_at_utc": "2026-10-27T10:15:00Z",
        "source": "amg_tamper_check",
        "confidence_score": 0.99,
        "reason": "Test"
    }
    client.post("/designate", json=desig, headers={"Authorization": f"Bearer {generate_designator_token()}"})
    state = client.get("/db-state", headers={"Authorization": f"Bearer {generate_admin_token()}"}).json()
    assert state["repair_candidates"]["comp-fail"]["reason"] == "no_admissible_checkpoint"
    assert state["repair_candidates"]["comp-fail"]["disposition"] == "IRREDUCIBLE"

@respx.mock
def test_reconstruction_success_path():
    # Setup chain: clean-root -> clean-child -> comp
    # Poison clean-root. clean-child is in frontier.
    c0 = {"data": "0"}
    p0 = create_payload("clean-root", "clean-parent-1", c0)
    client.post("/submit-candidate", json=p0)
    c1 = {"data": "1"}
    p1 = create_payload("clean-child", "clean-root", c1, parent_content_hash=content_hash_of(c0))
    client.post("/submit-candidate", json=p1)
    
    comp = create_payload("comp-succ", "clean-child", {"data": "sum"}, is_compaction=True, parent_content_hash=content_hash_of(c1))
    comp["covers"] = ["clean-root", "clean-child"]
    comp["summarizer"] = {"method_id": "llm-v1"}
    client.post("/submit-candidate", json=comp)
    
    # Declare checkpoint for clean-root (since clean-child will be poisoned)
    chk = {
        "checkpoint_id": "cp1",
        "target_node_id": "clean-root",
        "declared_at_utc": "2026-10-27T00:00:00Z",
        "snapshot_data": {}
    }
    client.post("/checkpoint", json=chk, headers={"Authorization": f"Bearer {generate_admin_token()}"})
    
    # Enable adapter
    from src.governor_service import settings
    settings.RECOVERY_ADAPTER_URL = "http://mock-adapter"
    settings.RECOVERY_ADAPTER_PUBLIC_KEY = PUBLIC_KEY_HEX
    
    # Mock adapter response
    rec_candidate = create_payload("reconstructed-comp", "clean-root", {"data": "new sum"})
    rec_candidate["covers"] = ["clean-root"] # matches frontier
    
    respx.post("http://mock-adapter/reconstruct").respond(200, json={"candidate": rec_candidate})
    
    # Designate clean-child as poisoned
    desig = {
        "poisoned_node_id": "clean-child",
        "detected_at_utc": "2026-10-27T10:15:00Z",
        "source": "amg_tamper_check",
        "confidence_score": 0.99,
        "reason": "Test"
    }
    client.post("/designate", json=desig, headers={"Authorization": f"Bearer {generate_designator_token()}"})
    
    state = client.get("/db-state", headers={"Authorization": f"Bearer {generate_admin_token()}"}).json()
    assert state["repair_candidates"]["comp-succ"]["disposition"] == "REDUCIBLE"
    assert "reconstructed-comp" in state["dag"]
    
    settings.RECOVERY_ADAPTER_URL = None

