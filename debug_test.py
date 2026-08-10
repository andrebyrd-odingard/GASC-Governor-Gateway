import pytest
import datetime
from fastapi.testclient import TestClient
from src.governor_service import app, backend
import json
from unittest.mock import patch, AsyncMock

def test_debug():
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
            "boundary_digest": "dummy"
        },
        "parent_dependency_commitments": [],
        "content_digest_sha256": "dummy",
        "agent_signature": "dummy",
        "signature_algorithm": "ECDSA-P256-SHA256",
        "state_content": {}
    }

    with patch('src.governor_service.verify_nhi_jwt', return_value={}):
        with patch('src.governor_service.verify_cryptographic_signature', return_value=True):
            with patch.object(backend, 'get_dag', wraps=backend.get_dag) as mock_get_dag:
                res = client.post("/submit-candidate", json=payload)
                print(res.json())

if __name__ == "__main__":
    test_debug()
