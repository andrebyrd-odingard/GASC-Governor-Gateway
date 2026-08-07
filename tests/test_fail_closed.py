"""Fail-closed policy path tests."""
import pytest
from fastapi.testclient import TestClient
import jwt
import json
import hashlib
from datetime import datetime, timezone
from ecdsa import SigningKey, NIST256p

from tests.conftest import JWT_PRIVATE_KEY_PEM
from src.governor_service import app


sk = SigningKey.generate(curve=NIST256p)
PUBLIC_KEY_HEX = sk.verifying_key.to_string().hex()


def _admin_token():
    return jwt.encode({"sub": "admin", "role": "admin"}, JWT_PRIVATE_KEY_PEM, algorithm="ES256")


def _valid_payload():
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
    signature_hex = sk.sign(actual_hash.encode()).hex()

    return {
        "payload_id": "fail-closed-payload",
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
            "parent_node_id": "clean-parent-1",
            "parent_content_hash": "e" * 64
        }],
        "state_content": state_content,
        "content_digest_sha256": actual_hash,
        "agent_signature": signature_hex
    }


class TestFailClosedPolicyPath:
    """
    C.4: Policy engine failure must result in 503, never admission.
    """

    def test_policy_failure_returns_503_never_admission(self, monkeypatch):
        """If evaluate_admission raises PolicyEvaluationError, the write is refused with 503."""
        from src import governor_service

        def _explode(*args, **kwargs):
            raise governor_service.PolicyEvaluationError("simulated policy engine failure")

        with TestClient(app) as client:
            client.post("/reset-db", headers={"Authorization": f"Bearer {_admin_token()}"})
            monkeypatch.setattr("src.governor_service.evaluate_admission", _explode)
            response = client.post("/submit-candidate", json=_valid_payload())
            assert response.status_code == 503
            assert "Policy engine unavailable" in response.json()["detail"]

            # The node must NOT have been admitted
            db = client.get("/db-state", headers={"Authorization": f"Bearer {_admin_token()}"}).json()
            assert "fail-closed-payload" not in db["dag"]
