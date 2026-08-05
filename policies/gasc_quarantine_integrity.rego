package gasc.governor.integrity

import future.keywords.in

default allow_state_write = false

# Historical Monotonicity Check (GASC-REQ-003)
# Ensures current quarantine set Q_t is a subset of proposed Q_{t+1}
monotonicity_preserved if {
    every element in input.quarantine_set_Q_current {
        element in input.quarantine_set_Q_proposed
    }
}

# Lineage Resolution Check (GASC-REQ-001)
# Every declared parent dependency must exist in committed DAG state.
declared_dependencies_resolved if {
    every parent in input.write_request.parent_dependency_commitments {
        parent.parent_node_id in input.committed_dag_node_ids
    }
}

# Block Writes Originating from Quarantined Parents
parents_are_clean if {
    not any_parent_quarantined
}

any_parent_quarantined if {
    some parent in input.write_request.parent_dependency_commitments
    parent.parent_node_id in input.quarantine_set_Q_current
}

# Final Write Admission Gate
allow_state_write if {
    monotonicity_preserved
    declared_dependencies_resolved
    parents_are_clean
    input.write_request.declared_evidence_boundary.fixed_at_utc != ""
}
