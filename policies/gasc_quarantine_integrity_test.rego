package gasc.governor.integrity
import future.keywords

test_allow_state_write_success if {
    allow_state_write with input as {
        "quarantine_set_Q_current": ["Q1", "Q2"],
        "quarantine_set_Q_proposed": ["Q1", "Q2", "Q3"],
        "committed_dag_node_ids": ["parent_1", "parent_2"],
        "write_request": {
            "parent_dependency_commitments": [
                {"parent_node_id": "parent_1"}
            ],
            "declared_evidence_boundary": {
                "fixed_at_utc": "2026-08-04T12:00:00Z"
            }
        }
    }
}

test_deny_due_to_monotonicity_breach if {
    not allow_state_write with input as {
        "quarantine_set_Q_current": ["Q1", "Q2"],
        "quarantine_set_Q_proposed": ["Q1"], # Missing Q2
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
}

test_deny_due_to_unresolved_dependency if {
    not allow_state_write with input as {
        "quarantine_set_Q_current": [],
        "quarantine_set_Q_proposed": [],
        "committed_dag_node_ids": ["parent_1"],
        "write_request": {
            "parent_dependency_commitments": [
                {"parent_node_id": "missing_parent"} 
            ],
            "declared_evidence_boundary": {
                "fixed_at_utc": "2026-08-04T12:00:00Z"
            }
        }
    }
}

test_deny_due_to_quarantined_parent if {
    not allow_state_write with input as {
        "quarantine_set_Q_current": ["Q1"],
        "quarantine_set_Q_proposed": ["Q1"],
        "committed_dag_node_ids": ["Q1", "parent_1"],
        "write_request": {
            "parent_dependency_commitments": [
                {"parent_node_id": "Q1"}
            ],
            "declared_evidence_boundary": {
                "fixed_at_utc": "2026-08-04T12:00:00Z"
            }
        }
    }
}
