"""
Regression tests for SHA-1 retirement from the ECDSA signature path.

These tests guard against silent reintroduction of SHA-1 in the signature
construction. Test 2 (SHA-1 rejection) signs with the real ecdsa library
to produce an authentic SHA-1 signature rather than simulating one.
Test 6 (grep guard) catches reintroduction from any direction.
"""
import json
import hashlib
import subprocess
import jwt
import pytest
from datetime import datetime, timezone
from pathlib import Path
from fastapi.testclient import TestClient

from tests.conftest import ECDSASigner, JWT_PRIVATE_KEY_PEM
from src.governor_service import app
from src.config import settings

client = TestClient(app)

_signer = ECDSASigner()
PUBLIC_KEY_HEX = _signer.public_key_hex


def _admin_token():
    return jwt.encode({"sub": "admin", "role": "admin"}, JWT_PRIVATE_KEY_PEM, algorithm="ES256")


def _agent_token():
    return jwt.encode(
        {
            "sub": PUBLIC_KEY_HEX,
            "scope": "agent:state:reconstruct",
            "is_nhi": True,
            "expires_at_epoch": int(datetime.now(timezone.utc).timestamp()) + 3600,
            "verifier_execution_status": "PASSED",
        },
        JWT_PRIVATE_KEY_PEM,
        algorithm="ES256",
    )


@pytest.fixture(autouse=True)
def reset_db():
    client.post("/reset-db", headers={"Authorization": f"Bearer {_admin_token()}"})


def _make_payload(state_content=None, signer=None, sig_alg="ECDSA-P256-SHA256"):
    """Build a valid payload. Override signer or sig_alg for negative tests."""
    signer = signer or _signer
    state_content = state_content or {"data": "sha256-test"}
    content_str = json.dumps(state_content, sort_keys=True)
    actual_hash = hashlib.sha256(content_str.encode()).hexdigest()
    signature_hex = signer.sign(actual_hash.encode())

    payload = {
        "payload_id": f"sha-test-{hashlib.md5(str(datetime.now()).encode()).hexdigest()}",
        "timestamp_utc": "2026-10-27T10:00:00Z",
        "ephemeral_nhi": {
            "identity_id": signer.public_key_hex,
            "session_token": _agent_token() if signer is _signer else jwt.encode(
                {
                    "sub": signer.public_key_hex,
                    "scope": "agent:state:reconstruct",
                    "is_nhi": True,
                    "expires_at_epoch": int(datetime.now(timezone.utc).timestamp()) + 3600,
                    "verifier_execution_status": "PASSED",
                },
                JWT_PRIVATE_KEY_PEM,
                algorithm="ES256",
            ),
            "expires_at_utc": "2026-10-27T11:00:00Z",
        },
        "declared_evidence_boundary": {
            "boundary_id": "b1",
            "fixed_at_utc": "2026-10-26T00:00:00Z",
            "boundary_digest": "f" * 64,
        },
        "parent_dependency_commitments": [
            {"parent_node_id": "clean-parent-1", "parent_content_hash": "e" * 64}
        ],
        "state_content": state_content,
        "content_digest_sha256": actual_hash,
        "agent_signature": signature_hex,
        "signature_algorithm": sig_alg,
    }
    return payload


# --- Test 1: SHA-256 signed payload verifies ---

def test_sha256_signature_accepted():
    payload = _make_payload()
    resp = client.post("/submit-candidate", json=payload)
    assert resp.status_code == 200, resp.json()


# --- Test 2: SHA-1 signed payload is REJECTED ---
# This is the primary regression guard. It signs with the real ecdsa library
# (which defaults to SHA-1) and asserts the gateway refuses it.

def test_sha1_signature_rejected():
    from cryptography.hazmat.primitives.asymmetric import ec, utils as asy_utils
    from cryptography.hazmat.primitives import hashes

    # Generate a key pair
    private_key = ec.generate_private_key(ec.SECP256R1())
    pub_numbers = private_key.public_key().public_numbers()
    pub_hex = (pub_numbers.x.to_bytes(32, "big") + pub_numbers.y.to_bytes(32, "big")).hex()

    state_content = {"data": "sha1-reject-test"}
    content_str = json.dumps(state_content, sort_keys=True)
    actual_hash = hashlib.sha256(content_str.encode()).hexdigest()

    # Sign with SHA-1 (the old, insecure path)
    der_sig = private_key.sign(actual_hash.encode(), ec.ECDSA(hashes.SHA1()))
    r, s = asy_utils.decode_dss_signature(der_sig)
    sha1_sig_hex = (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()

    session_token = jwt.encode(
        {
            "sub": pub_hex,
            "scope": "agent:state:reconstruct",
            "is_nhi": True,
            "expires_at_epoch": int(datetime.now(timezone.utc).timestamp()) + 3600,
            "verifier_execution_status": "PASSED",
        },
        JWT_PRIVATE_KEY_PEM,
        algorithm="ES256",
    )

    payload = {
        "payload_id": f"sha1-reject-{hashlib.md5(str(datetime.now()).encode()).hexdigest()}",
        "timestamp_utc": "2026-10-27T10:00:00Z",
        "ephemeral_nhi": {
            "identity_id": pub_hex,
            "session_token": session_token,
            "expires_at_utc": "2026-10-27T11:00:00Z",
        },
        "declared_evidence_boundary": {
            "boundary_id": "b1",
            "fixed_at_utc": "2026-10-26T00:00:00Z",
            "boundary_digest": "f" * 64,
        },
        "parent_dependency_commitments": [
            {"parent_node_id": "clean-parent-1", "parent_content_hash": "e" * 64}
        ],
        "state_content": state_content,
        "content_digest_sha256": actual_hash,
        "agent_signature": sha1_sig_hex,
        "signature_algorithm": "ECDSA-P256-SHA256",
    }
    resp = client.post("/submit-candidate", json=payload)
    assert resp.status_code == 401, f"SHA-1 signature should be rejected, got {resp.status_code}: {resp.json()}"


# --- Test 3: VERIFIER_CONTRADICTION with SHA-256 adapter signature accepted ---

def test_adapter_sha256_accepted():
    # First create a node to observe
    payload = _make_payload()
    resp = client.post("/submit-candidate", json=payload)
    assert resp.status_code == 200

    adapter_signer = ECDSASigner()
    settings.RECOVERY_ADAPTER_PUBLIC_KEY = adapter_signer.public_key_hex

    sig = adapter_signer.sign(payload["payload_id"].encode())

    designator_token = jwt.encode(
        {"sub": "designator", "role": "designator"}, JWT_PRIVATE_KEY_PEM, algorithm="ES256"
    )
    resp = client.post(
        "/observe",
        json={
            "node_id": payload["payload_id"],
            "recurrence_class": "VERIFIER_CONTRADICTION",
            "detected_at_utc": "2026-01-01T00:00:00Z",
            "adapter_signature": sig,
        },
        headers={"Authorization": f"Bearer {designator_token}"},
    )
    assert resp.status_code == 200, resp.json()


# --- Test 3b: VERIFIER_CONTRADICTION with SHA-1 adapter signature REJECTED ---

def test_adapter_sha1_rejected():
    from cryptography.hazmat.primitives.asymmetric import ec, utils as asy_utils
    from cryptography.hazmat.primitives import hashes

    payload = _make_payload()
    resp = client.post("/submit-candidate", json=payload)
    assert resp.status_code == 200

    # Generate adapter key, sign with SHA-1
    adapter_key = ec.generate_private_key(ec.SECP256R1())
    pub_numbers = adapter_key.public_key().public_numbers()
    adapter_pub_hex = (
        pub_numbers.x.to_bytes(32, "big") + pub_numbers.y.to_bytes(32, "big")
    ).hex()
    settings.RECOVERY_ADAPTER_PUBLIC_KEY = adapter_pub_hex

    der_sig = adapter_key.sign(payload["payload_id"].encode(), ec.ECDSA(hashes.SHA1()))
    r, s = asy_utils.decode_dss_signature(der_sig)
    sha1_sig = (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()

    designator_token = jwt.encode(
        {"sub": "designator", "role": "designator"}, JWT_PRIVATE_KEY_PEM, algorithm="ES256"
    )
    resp = client.post(
        "/observe",
        json={
            "node_id": payload["payload_id"],
            "recurrence_class": "VERIFIER_CONTRADICTION",
            "detected_at_utc": "2026-01-01T00:00:00Z",
            "adapter_signature": sha1_sig,
        },
        headers={"Authorization": f"Bearer {designator_token}"},
    )
    assert resp.status_code == 403, f"SHA-1 adapter sig should be rejected, got {resp.status_code}: {resp.json()}"


# --- Test 4: Payload missing signature_algorithm is rejected ---

def test_missing_signature_algorithm_rejected():
    payload = _make_payload()
    del payload["signature_algorithm"]
    resp = client.post("/submit-candidate", json=payload)
    assert resp.status_code == 400, resp.json()
    assert "signature_algorithm" in resp.json()["detail"].lower()


# --- Test 5: Payload naming unsupported algorithm is rejected ---

def test_unsupported_algorithm_rejected():
    payload = _make_payload(sig_alg="ECDSA-P256-SHA1")
    resp = client.post("/submit-candidate", json=payload)
    assert resp.status_code == 400, resp.json()
    assert "ECDSA-P256-SHA256" in resp.json()["detail"]


# --- Test 6: No SHA-1 references in src/ ---
# Catches reintroduction from any direction.

def test_no_sha1_in_source():
    src_dir = Path(__file__).parent.parent / "src"
    result = subprocess.run(
        ["grep", "-rnI", "SHA1\\|sha1", str(src_dir)],
        capture_output=True,
        text=True,
    )
    matches = [
        line for line in result.stdout.strip().split("\n")
        if line and not line.strip().startswith("#")
    ]
    assert not matches, f"SHA-1 references found in src/:\n" + "\n".join(matches)
