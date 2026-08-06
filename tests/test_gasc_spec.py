import json
import subprocess
import pytest
from pathlib import Path
from jsonschema import validate, ValidationError

# Paths
ROOT_DIR = Path(__file__).parent.parent
SCHEMAS_DIR = ROOT_DIR / "schemas"
POLICIES_DIR = ROOT_DIR / "policies"
OPA_BIN = ROOT_DIR / "bin" / "opa"

def load_schema(name):
    with open(SCHEMAS_DIR / name, "r") as f:
        return json.load(f)

def run_opa(policy_file, query, input_data):
    input_file = ROOT_DIR / "tests" / "temp_input.json"
    with open(input_file, "w") as f:
        json.dump(input_data, f)
        
    cmd = [
        str(OPA_BIN), "eval",
        "-d", str(POLICIES_DIR / policy_file),
        "-i", str(input_file),
        query
    ]
    
    result = subprocess.run(cmd, capture_output=True, text=True)
    if input_file.exists():
        input_file.unlink()
        
    if result.returncode != 0:
        raise Exception(f"OPA failed: {result.stderr}")
        
    output = json.loads(result.stdout)
    if not output.get("result"):
        return False
    
    return output["result"][0]["expressions"][0]["value"]

def test_schema_state_write_payload_valid():
    schema = load_schema("state_write_payload.json")
    valid_payload = {
        "payload_id": "123e4567-e89b-12d3-a456-426614174000",
        "timestamp_utc": "2026-08-04T12:00:00Z",
        "ephemeral_nhi": {
            "identity_id": "agent-1",
            "session_token": "abc",
            "expires_at_utc": "2026-08-04T13:00:00Z"
        },
        "declared_evidence_boundary": {
            "boundary_id": "b1",
            "fixed_at_utc": "2026-08-04T12:00:00Z",
            "boundary_digest": "a" * 64
        },
        "parent_dependency_commitments": [
            {
                "parent_node_id": "123e4567-e89b-12d3-a456-426614174001",
                "parent_content_hash": "b" * 64
            }
        ],
        "state_content": {"key": "value"},
        "content_digest_sha256": "c" * 64,
        "agent_signature": "signature"
    }
    validate(instance=valid_payload, schema=schema)

def test_schema_state_write_payload_invalid():
    schema = load_schema("state_write_payload.json")
    invalid_payload = {
        "payload_id": "not-uuid"
    }
    with pytest.raises(ValidationError):
        validate(instance=invalid_payload, schema=schema)

def test_rego_verification_separation_pass():
    input_data = {
        "candidate_submission": {
            "new_candidate_node_id": "1",
            "target_replaced_node_id": "2",
            "admissible_frontier_parent_ids": ["3"]
        },
        "quarantine_set_Q": ["4"],
        "auth_context": {
            "is_nhi": True,
            "expires_at_epoch": 2000000000,
            "scope": "agent:state:reconstruct"
        },
        "request_timestamp_epoch": 1000000000,
        "verifier_execution_status": "PASSED"
    }
    allowed = run_opa("gasc_verification_separation.rego", "data.gasc.governor.verification.allow_reintegration", input_data)
    assert allowed == True

def test_rego_verification_separation_fail_planner_output():
    input_data = {
        "candidate_submission": {
            "new_candidate_node_id": "1",
            "target_replaced_node_id": "2",
            "admissible_frontier_parent_ids": ["3"],
            "planner_score": 0.99
        },
        "quarantine_set_Q": ["4"],
        "auth_context": {
            "is_nhi": True,
            "expires_at_epoch": 2000000000,
            "scope": "agent:state:reconstruct"
        },
        "request_timestamp_epoch": 1000000000,
        "verifier_execution_status": "PASSED"
    }
    allowed = run_opa("gasc_verification_separation.rego", "data.gasc.governor.verification.allow_reintegration", input_data)
    assert allowed == False

def test_rego_quarantine_integrity_pass():
    input_data = {
        "parent_status": [
            {"parent_node_id": "parent_1", "exists": True, "quarantined": False}
        ],
        "write_request": {
            "parent_dependency_commitments": [
                {"parent_node_id": "parent_1"}
            ],
            "declared_evidence_boundary": {
                "fixed_at_utc": "2026-08-04T12:00:00Z"
            }
        }
    }
    allowed = run_opa("gasc_quarantine_integrity.rego", "data.gasc.governor.integrity.allow_state_write", input_data)
    assert allowed == True

def test_rego_quarantine_integrity_fail_monotonicity():
    input_data = {
        "quarantine_set_Q_current": ["1", "2"],
        "quarantine_set_Q_proposed": ["1"], # 2 is missing
        "committed_dag_node_ids": ["parent_1"],
        "write_request": {
            "parent_dependency_commitments": [
                {"parent_node_id": "parent_1"}
            ],
            "declared_evidence_boundary": {
                "fixed_at_utc": "2026-08-04T12:00:00Z"
            }
        }
    }
    allowed = run_opa("gasc_quarantine_integrity.rego", "data.gasc.governor.integrity.allow_state_write", input_data)
    assert allowed == False
