package gasc.governor.integrity
import future.keywords

test_allow_state_write_success if {
    allow_state_write with input as {
        "parent_status": [
            {"parent_node_id": "parent_1", "exists": true, "quarantined": false}
        ],
        "write_request": {
            "declared_evidence_boundary": {
                "fixed_at_utc": "2026-08-04T12:00:00Z"
            }
        }
    }
}

test_deny_due_to_monotonicity_breach if {
    not monotonicity_preserved with input as {
        "quarantine_set_Q_current": ["Q1", "Q2"],
        "quarantine_set_Q_proposed": ["Q1"], # Missing Q2
    }
}

test_deny_due_to_unresolved_dependency if {
    not allow_state_write with input as {
        "parent_status": [
            {"parent_node_id": "missing_parent", "exists": false, "quarantined": false}
        ],
        "write_request": {
            "declared_evidence_boundary": {
                "fixed_at_utc": "2026-08-04T12:00:00Z"
            }
        }
    }
}

test_deny_due_to_quarantined_parent if {
    not allow_state_write with input as {
        "parent_status": [
            {"parent_node_id": "Q1", "exists": true, "quarantined": true}
        ],
        "write_request": {
            "declared_evidence_boundary": {
                "fixed_at_utc": "2026-08-04T12:00:00Z"
            }
        }
    }
}
