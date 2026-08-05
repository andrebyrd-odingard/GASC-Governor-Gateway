import pytest
import jwt
import json
import hashlib
from datetime import datetime, timezone
from ecdsa import SigningKey, NIST256p
from httpx import AsyncClient

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

from src.governor_service import app, backend
from src.config import settings

from tests.conftest import JWT_PRIVATE_KEY_PEM, JWT_PUBLIC_KEY

# Generate Identity Keypair (ECDSA)
sk = SigningKey.generate(curve=NIST256p)
vk = sk.verifying_key
PUBLIC_KEY_HEX = vk.to_string().hex()


@pytest.fixture
def auth_headers():
    token = jwt.encode(
        {
            "sub": PUBLIC_KEY_HEX, 
            "role": "agent",
            "scope": "agent:state:reconstruct",
            "is_nhi": True,
            "expires_at_epoch": int(datetime.now(timezone.utc).timestamp()) + 3600,
            "verifier_execution_status": "PASSED"
        },
        JWT_PRIVATE_KEY_PEM,
        algorithm="ES256"
    )
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
def admin_headers():
    token = jwt.encode(
        {"sub": "admin-user", "role": "admin"},
        JWT_PRIVATE_KEY_PEM,
        algorithm="ES256"
    )
    return {"Authorization": f"Bearer {token}"}

def create_valid_payload(node_id, session_token, state_content):
    content_str = json.dumps(state_content, sort_keys=True)
    actual_hash = hashlib.sha256(content_str.encode()).hexdigest()
    
    signature_bytes = sk.sign(actual_hash.encode())
    signature_hex = signature_bytes.hex()
    
    return {
        "payload_id": node_id,
        "timestamp_utc": datetime.now(timezone.utc).isoformat() + "Z",
        "ephemeral_nhi": {
            "identity_id": PUBLIC_KEY_HEX,
            "session_token": session_token,
            "expires_at_utc": "2030-01-01T00:00:00Z"
        },
        "declared_evidence_boundary": {
            "boundary_id": "bnd-1",
            "fixed_at_utc": datetime.now(timezone.utc).isoformat() + "Z",
            "boundary_digest": "0" * 64
        },
        "parent_dependency_commitments": [
            {"parent_node_id": "clean-parent-1", "parent_content_hash": "0" * 64}
        ],
        "state_content": state_content,
        "content_digest_sha256": actual_hash,
        "agent_signature": signature_hex
    }

@pytest.mark.asyncio
async def test_context_compacted_endpoint(auth_headers, admin_headers):
    async with AsyncClient(app=app, base_url="http://test") as ac:
        await ac.post("/reset-db", headers=admin_headers)
    
    session_token = auth_headers["Authorization"].split(" ")[1]
    
    # 1. Create a normal node first so we have something to compact
    payload = create_valid_payload("test-node-1", session_token, {"msg": "hello"})
    
    async with AsyncClient(app=app, base_url="http://test") as ac:
        resp = await ac.post("/submit-candidate", json=payload, headers=auth_headers)
        if resp.status_code != 200:
            raise ValueError(f"SUBMIT FAIL: {resp.status_code} {resp.text}")
        
    # 2. Call /context-compacted
    compaction_state = {"summary": "User said hello"}
    c_str = json.dumps(compaction_state, sort_keys=True)
    c_hash = hashlib.sha256(c_str.encode()).hexdigest()
    c_sig = sk.sign(c_hash.encode()).hex()
    
    compaction_event = {
        "compacted_node_ids": ["test-node-1"],
        "compaction_node_id": "compaction-node-2",
        "timestamp_utc": datetime.now(timezone.utc).isoformat() + "Z",
        "ephemeral_nhi": payload["ephemeral_nhi"],
        "state_content": compaction_state,
        "agent_signature": c_sig
    }
    
    async with AsyncClient(app=app, base_url="http://test") as ac:
        resp = await ac.post("/context-compacted", json=compaction_event, headers=auth_headers)
        assert resp.status_code == 200
        
    # Verify the DAG
    from src.governor_service import backend as app_backend
    dag = await app_backend.get_dag()
    assert "compaction-node-2" in dag
    assert dag["compaction-node-2"]["node_type"] == "COMPACTION"
    assert dag["compaction-node-2"]["covers"] == ["test-node-1"]
    parents = dag["compaction-node-2"]["parent_dependency_commitments"]
    assert len(parents) == 1
    assert parents[0]["parent_node_id"] == "test-node-1"
    assert parents[0]["edge_class"] == "CARRIED"

@pytest.mark.asyncio
async def test_semantic_rollback_hazard(auth_headers, admin_headers):
    async with AsyncClient(app=app, base_url="http://test") as ac:
        await ac.post("/reset-db", headers=admin_headers)
    
    session_token = auth_headers["Authorization"].split(" ")[1]
    
    # 1. Create a normal node
    payload = create_valid_payload("test-node-1", session_token, {"msg": "hello"})
    
    async with AsyncClient(app=app, base_url="http://test") as ac:
        resp = await ac.post("/submit-candidate", json=payload, headers=auth_headers)
        if resp.status_code != 200:
            raise ValueError(f"HAZARD FAIL 1: {resp.status_code} {resp.text}")
        
    # 2. Add an external effect for this node
    ext_effect = {
        "idempotency_key": "payment-123",
        "node_id": "test-node-1",
        "effect_type": "api_call"
    }
    async with AsyncClient(app=app, base_url="http://test") as ac:
        resp = await ac.post("/declare-external-effect", json=ext_effect, headers=admin_headers)
        assert resp.status_code == 200
        
    # 3. Create a compaction node that carried this node
    compaction_state = {"summary": "User said hello"}
    c_str = json.dumps(compaction_state, sort_keys=True)
    c_hash = hashlib.sha256(c_str.encode()).hexdigest()
    c_sig = sk.sign(c_hash.encode()).hex()
    
    compaction_event = {
        "compacted_node_ids": ["test-node-1"],
        "compaction_node_id": "compaction-node-2",
        "timestamp_utc": datetime.now(timezone.utc).isoformat() + "Z",
        "ephemeral_nhi": payload["ephemeral_nhi"],
        "state_content": compaction_state,
        "agent_signature": c_sig
    }
    
    async with AsyncClient(app=app, base_url="http://test") as ac:
        resp = await ac.post("/context-compacted", json=compaction_event, headers=auth_headers)
        assert resp.status_code == 200
        
    # 4. Now designate test-node-1 as poisoned
    from src.governor_service import DesignationSource
    designation = {
        "poisoned_node_id": "test-node-1",
        "detected_at_utc": datetime.now(timezone.utc).isoformat() + "Z",
        "source": DesignationSource.HUMAN_REPORT,
        "confidence_score": 1.0,
        "reason": "Test"
    }
    
    d_token = jwt.encode(
        {"sub": "designator-user", "role": "designator"},
        JWT_PRIVATE_KEY_PEM,
        algorithm="ES256"
    )
    d_headers = {"Authorization": f"Bearer {d_token}"}
    
    async with AsyncClient(app=app, base_url="http://test") as ac:
        resp = await ac.post("/designate", json=designation, headers=d_headers)
        assert resp.status_code == 200
        
    # 5. Check repair candidates
    from src.governor_service import backend as app_backend
    rc = await app_backend.get_repair_candidates()
    assert "compaction-node-2" in rc
    assert rc["compaction-node-2"]["disposition"] == "IRREDUCIBLE"
    assert rc["compaction-node-2"]["reason"] == "semantic_rollback_hazard"
