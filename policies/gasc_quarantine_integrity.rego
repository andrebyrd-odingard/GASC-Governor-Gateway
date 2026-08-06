package gasc.governor.integrity

import future.keywords

default allow_state_write = false

# GASC-REQ-001 — every declared parent resolves to a committed record
declared_dependencies_resolved if {
    every p in input.parent_status {
        p.exists == true
    }
}

# Writes may not build on quarantined roots
parents_are_clean if {
    not any_parent_quarantined
}

any_parent_quarantined if {
    some p in input.parent_status
    p.quarantined == true
}

allow_state_write if {
    declared_dependencies_resolved
    parents_are_clean
    input.write_request.declared_evidence_boundary.fixed_at_utc != ""
}

# Historical Monotonicity Check (GASC-REQ-003)
# Ensures current quarantine set Q_t is a subset of proposed Q_{t+1}
# Moved to transition path instead of write admission path.
monotonicity_preserved if {
    every element in input.quarantine_set_Q_current {
        element in input.quarantine_set_Q_proposed
    }
}
