import json
import pytest
from pathlib import Path
from jsonschema import validate, ValidationError

ROOT_DIR = Path(__file__).parent.parent
SCHEMAS_DIR = ROOT_DIR / "schemas"

def load_schema(name):
    with open(SCHEMAS_DIR / name, "r") as f:
        return json.load(f)

# GASC_StateWritePayload
def get_valid_state_write_payload():
    return {
        "payload_id": "a1b2c3d4-e5f6-7890-1234-567890abcdef",
        "timestamp_utc": "2026-10-27T10:00:00Z",
        "ephemeral_nhi": {
            "identity_id": "agent-007",
            "session_token": "some-jwt-token",
            "expires_at_utc": "2026-10-27T11:00:00Z"
        },
        "declared_evidence_boundary": {
            "boundary_id": "prod-us-east-1-v3",
            "fixed_at_utc": "2026-10-26T00:00:00Z",
            "boundary_digest": "f" * 64
        },
        "parent_dependency_commitments": [{
            "parent_node_id": "f6e5d4c3-b2a1-0987-6543-210987fedcba",
            "parent_content_hash": "e" * 64
        }],
        "state_content": {"key": "value"},
        "content_digest_sha256": "d" * 64,
        "agent_signature": "c" * 64,
        "signature_algorithm": "ECDSA-P256-SHA256"
    }

def test_valid_payload_passes_validation():
    payload = get_valid_state_write_payload()
    schema = load_schema("state_write_payload.json")
    try:
        validate(instance=payload, schema=schema)
    except ValidationError as e:
        pytest.fail(f"Validation failed unexpectedly: {e}")

def test_invalid_payload_missing_required_field_fails():
    payload = get_valid_state_write_payload()
    schema = load_schema("state_write_payload.json")
    del payload["agent_signature"] 
    with pytest.raises(ValidationError) as excinfo:
        validate(instance=payload, schema=schema)
    assert "'agent_signature' is a required property" in str(excinfo.value)

def test_invalid_payload_bad_pattern_fails():
    payload = get_valid_state_write_payload()
    schema = load_schema("state_write_payload.json")
    payload["content_digest_sha256"] = "not-a-sha256-hash"
    with pytest.raises(ValidationError) as excinfo:
        validate(instance=payload, schema=schema)
    assert "does not match" in str(excinfo.value)

# GASC_QuarantineEvent
def get_valid_quarantine_event():
    return {
        "quarantine_event_id": "b1b2c3d4-e5f6-7890-1234-567890abcdef",
        "detected_at_utc": "2026-10-27T10:00:00Z",
        "poisoned_root_id": "c1b2c3d4-e5f6-7890-1234-567890abcdef",
        "computed_blast_radius_C_p": ["c1b2c3d4-e5f6-7890-1234-567890abcdef"],
        "monotonic_ledger_digest_post_transition": "b" * 64
    }

def test_valid_quarantine_event():
    payload = get_valid_quarantine_event()
    schema = load_schema("quarantine_event.json")
    validate(instance=payload, schema=schema)

def test_invalid_quarantine_event_bad_hash_format():
    payload = get_valid_quarantine_event()
    schema = load_schema("quarantine_event.json")
    payload["independent_snapshot_hash"] = "short-hash"
    with pytest.raises(ValidationError):
        validate(instance=payload, schema=schema)

# GASC_GovernedReconstructionRequest
def get_valid_reconstruction_req():
    return {
        "reconstruction_id": "d1b2c3d4-e5f6-7890-1234-567890abcdef",
        "target_replaced_node_id": "e1b2c3d4-e5f6-7890-1234-567890abcdef",
        "new_candidate_node_id": "f1b2c3d4-e5f6-7890-1234-567890abcdef",
        "admissible_frontier_parent_ids": ["g1b2c3d4-e5f6-7890-1234-567890abcdef"],
        "reconstruction_method": "CHECKPOINT_REPLAY",
        "candidate_payload": {"some": "state"}
    }

def test_valid_reconstruction_req():
    payload = get_valid_reconstruction_req()
    schema = load_schema("governed_reconstruction_request.json")
    validate(instance=payload, schema=schema)
