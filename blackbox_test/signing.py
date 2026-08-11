"""Client-side construction helpers for GASC state-write requests."""

from __future__ import annotations

import hashlib
import json
import os
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils


SERVER_JWT_PRIVATE_KEY = Path(
    os.environ.get(
        "GASC_JWT_PRIVATE_KEY",
        "/tmp/gasc-governor-jwt-private.pem",
    )
)
PARENT_HASH_FOR_RESET_SEED = "e" * 64


def _public_key_hex(private_key: ec.EllipticCurvePrivateKey) -> str:
    numbers = private_key.public_key().public_numbers()
    return (
        numbers.x.to_bytes(32, "big") + numbers.y.to_bytes(32, "big")
    ).hex()


def make_agent_keypair() -> tuple[ec.EllipticCurvePrivateKey, str]:
    """Return an agent P-256 private key and its raw x||y public-key hex."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    return private_key, _public_key_hex(private_key)


def make_session_token(identity_id: str, role: str = "agent", **extra: Any) -> str:
    """Create the ES256 session JWT bound to ``identity_id``."""
    claims: dict[str, Any] = {
        "sub": identity_id,
        "role": role,
        "scope": "agent:state:reconstruct",
        "is_nhi": True,
        "expires_at_epoch": int(
            (datetime.now(timezone.utc) + timedelta(hours=1)).timestamp()
        ),
        "verifier_execution_status": "PASSED",
    }
    claims.update(extra)
    return jwt.encode(
        claims,
        SERVER_JWT_PRIVATE_KEY.read_text(),
        algorithm="ES256",
    )


def _raw_signature_hex(
    private_key: ec.EllipticCurvePrivateKey, message: bytes
) -> str:
    der = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = utils.decode_dss_signature(der)
    return (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()


def sign_candidate(
    payload_dict: dict[str, Any],
    agent_private_key: ec.EllipticCurvePrivateKey,
) -> dict[str, Any]:
    """Fill the content digest and raw ECDSA signature in a candidate."""
    content_bytes = json.dumps(
        payload_dict.get("state_content", {}), sort_keys=True
    ).encode()
    digest = hashlib.sha256(content_bytes).hexdigest()
    payload_dict["content_digest_sha256"] = digest
    payload_dict["agent_signature"] = _raw_signature_hex(
        agent_private_key, digest.encode()
    )
    payload_dict["signature_algorithm"] = "ECDSA-P256-SHA256"
    return payload_dict


def build_valid_candidate(
    parent_node_ids: list[str],
    state_content: dict[str, Any],
    identity_id: str = "agent-1",
    role: str = "agent",
) -> dict[str, Any]:
    """Build a schema-valid candidate bound to a newly generated agent key."""
    agent_private_key, bound_identity_id = make_agent_keypair()
    del identity_id  # The wire identity is the generated public-key binding.
    now = datetime.now(timezone.utc)
    expires = now + timedelta(hours=1)
    payload: dict[str, Any] = {
        "payload_id": str(uuid.uuid4()),
        "timestamp_utc": now.isoformat().replace("+00:00", "Z"),
        "ephemeral_nhi": {
            "identity_id": bound_identity_id,
            "session_token": make_session_token(bound_identity_id, role=role),
            "expires_at_utc": expires.isoformat().replace("+00:00", "Z"),
        },
        "declared_evidence_boundary": {
            "boundary_id": str(uuid.uuid4()),
            "fixed_at_utc": now.isoformat().replace("+00:00", "Z"),
            "boundary_digest": "f" * 64,
        },
        "parent_dependency_commitments": [
            {
                "parent_node_id": parent_id,
                "parent_content_hash": PARENT_HASH_FOR_RESET_SEED,
            }
            for parent_id in parent_node_ids
        ],
        "state_content": state_content,
    }
    return sign_candidate(payload, agent_private_key)
