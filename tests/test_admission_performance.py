import pytest
import datetime
from fastapi.testclient import TestClient
from src.governor_service import app, backend
import json
from unittest.mock import patch, AsyncMock

@pytest.fixture(autouse=True)
async def setup_db():
    if hasattr(backend, "init_db"):
        await backend.init_db()
    await backend.reset()
    yield

def test_submit_candidate_no_dag_load():
    client = TestClient(app)
    
    payload = {
        "payload_id": "test-node-1",
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z",
        "ephemeral_nhi": {
            "identity_id": "agent-1",
            "session_token": "mocked",
            "expires_at_utc": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).isoformat() + "Z"
        },
        "node_type": "STANDARD",
        "declared_evidence_boundary": {
            "boundary_id": "b1",
            "fixed_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z",
            "boundary_digest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        },
        "parent_dependency_commitments": [{"parent_node_id": "p1", "parent_content_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}],
        "content_digest_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "agent_signature": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "signature_algorithm": "ECDSA-P256-SHA256",
        "state_content": {}
    }

    import src.governor_service as gs
    
    valid_auth = {
        "is_nhi": True,
        "expires_at_epoch": int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 3600,
        "scope": "agent:state:reconstruct",
        "verifier_execution_status": "PASSED"
    }
    
    with patch('src.governor_service.verify_nhi_jwt', return_value=valid_auth):
        with patch('src.governor_service.verify_cryptographic_signature', return_value=True):
            with patch.object(gs.backend, 'nodes_exist', new_callable=AsyncMock) as mock_exist:
                mock_exist.return_value = {"p1": True}
                with patch.object(gs.backend, 'get_dag', wraps=gs.backend.get_dag) as mock_get_dag:
                    res = client.post("/submit-candidate", json=payload)
                    assert res.status_code == 200
                    mock_get_dag.assert_not_called()

def test_submit_candidate_quarantined_parent_refused():
    import src.governor_service as gs
    client = TestClient(app)
    import asyncio
    
    # We must patch asyncio.run for the setup if we are in an event loop
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
        
    event = {"quarantine_event_id": "e1", "poisoned_node_id": "q1", "detected_at_utc": "2026-08-04T12:00:00Z", "computed_blast_radius_C_p": ["q1"], "monotonic_ledger_digest_post_transition": "123"}
        
    if loop and loop.is_running():
        import threading
        def run_it():
            asyncio.run(gs.backend.apply_quarantine_transaction(event, ["q1"]))
        t = threading.Thread(target=run_it)
        t.start()
        t.join()
    else:
        asyncio.run(gs.backend.apply_quarantine_transaction(event, ["q1"]))

    
    payload = {
        "payload_id": "test-node-2",
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z",
        "ephemeral_nhi": {
            "identity_id": "agent-1",
            "session_token": "mocked",
            "expires_at_utc": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).isoformat() + "Z"
        },
        "node_type": "STANDARD",
        "declared_evidence_boundary": {
            "boundary_id": "b1",
            "fixed_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z",
            "boundary_digest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        },
        "parent_dependency_commitments": [{"parent_node_id": "q1", "parent_content_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}],
        "content_digest_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "agent_signature": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        "signature_algorithm": "ECDSA-P256-SHA256",
        "state_content": {}
    }
    
    valid_auth = {
        "is_nhi": True,
        "expires_at_epoch": int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 3600,
        "scope": "agent:state:reconstruct",
        "verifier_execution_status": "PASSED"
    }

    with patch('src.governor_service.verify_nhi_jwt', return_value=valid_auth):
        with patch('src.governor_service.verify_cryptographic_signature', return_value=True):
            with patch.object(gs.backend, 'nodes_exist', new_callable=AsyncMock) as mock_exist:
                mock_exist.return_value = {"q1": True}
                res = client.post("/submit-candidate", json=payload)
                print("debug test 2:", res.json())
                assert res.status_code == 403
                assert res.json()["detail"]["error"] == "TAINTED_PARENT"
