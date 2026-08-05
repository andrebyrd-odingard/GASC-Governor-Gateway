import pytest
import json
import tempfile
import os
from src.gasc_audit_engine import GASCAuditEngine

@pytest.fixture
def mock_manifest():
    return {
        "boundary_id": "BOUNDARY-PROD-2026-A",
        "operating_envelope_declaration": "Test Env",
        "admitted_writes": [
            {
                "declared_evidence_boundary": {"boundary_id": "B1"},
                "parent_dependency_commitments": [{"parent_node_id": "N1"}]
            }
        ],
        "quarantine_incidents": [],
        "quarantine_transitions": [],
        "continuity_exposures": [],
        "reconstruction_attempts": [],
        "fault_injection_campaign": {
            "preregistered_suite_run": True,
            "shared_dependency_inventory_published": True,
            "observed_catch_rate": 0.98,
            "preregistered_target_catch_rate": 0.95
        },
        "reintegrations": [],
        "recurrence_monitor": {},
        "disposed_targets": [
            {"disposition": "REDUCIBLE"},
            {"disposition": "IRREDUCIBLE"}
        ],
        "measured_cost_report": {
            "safety": 1.0,
            "availability": 0.99,
            "coverage": 0.9,
            "function_restoration": 0.8,
            "burden": 0.1,
            "recurrence": 0.0
        }
    }

def create_engine(manifest_data):
    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".json") as tmp:
        json.dump(manifest_data, tmp)
        manifest_path = tmp.name

    engine = GASCAuditEngine(manifest_path)
    os.remove(manifest_path)
    # Re-inject the data directly to bypass file missing issues if needed
    engine.manifest = manifest_data 
    return engine

def test_audit_all_pass_with_not_exercised(mock_manifest):
    engine = create_engine(mock_manifest)
    res = engine.run_full_audit()
    assert res["conformance_summary"]["overall_audit_passed"] is True
    assert res["conformance_summary"]["not_exercised_count"] == 6

def test_audit_rule2_self_attestation(mock_manifest):
    mock_manifest["quarantine_incidents"] = [
        {
            "poisoned_root_id": "root",
            "computed_blast_radius_C_p": ["root"]
            # missing independent_snapshot_hash
        }
    ]
    engine = create_engine(mock_manifest)
    res = engine.run_full_audit()
    
    assert res["conformance_summary"]["overall_audit_passed"] is True
    assert res["conformance_summary"]["self_attested_count"] == 1
    
    row2 = next(r for r in res["row_by_row_results"] if r["req_id"] == "GASC-REQ-002")
    assert row2["status"] == "SELF-ATTESTED"

def test_audit_rule3_disclosure_limit(mock_manifest):
    mock_manifest["fault_injection_campaign"]["preregistered_suite_run"] = False
    engine = create_engine(mock_manifest)
    res = engine.run_full_audit()
    
    assert res["conformance_summary"]["rule_3_compliance_breached"] is True
    assert res["conformance_summary"]["overall_audit_passed"] is False

def test_row9_non_vacuity(mock_manifest):
    mock_manifest["disposed_targets"] = [{"disposition": "REDUCIBLE"}] # Missing irreducible
    engine = create_engine(mock_manifest)
    res = engine.run_full_audit()
    
    row9 = next(r for r in res["row_by_row_results"] if r["req_id"] == "GASC-REQ-009")
    assert row9["status"] == "NOT-EXERCISED"
    assert res["conformance_summary"]["not_exercised_count"] == 7
