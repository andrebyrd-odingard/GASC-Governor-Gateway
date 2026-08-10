package gasc.governor.admission

import future.keywords

# Combined admission policy that evaluates both integrity and verification
# in a single call, halving OPA invocation overhead per admission.
#
# Input schema:
#   input.integrity: { write_request, parent_status }
#   input.verification: { candidate_submission, quarantine_set_Q, auth_context,
#                         request_timestamp_epoch, verifier_execution_status }

default allow_state_write = false
default allow_reintegration = false
default is_irreducible = false

# --- Integrity checks (from gasc.governor.integrity) ---

declared_dependencies_resolved if {
    every p in input.integrity.parent_status {
        p.exists == true
    }
}

any_parent_quarantined if {
    some p in input.integrity.parent_status
    p.quarantined == true
}

parents_are_clean if {
    not any_parent_quarantined
}

allow_state_write if {
    declared_dependencies_resolved
    parents_are_clean
    input.integrity.write_request.declared_evidence_boundary.fixed_at_utc != ""
}

# --- Verification checks (from gasc.governor.verification) ---

has_evaluative_planner_output if {
    some key in ["planner_score", "justification", "confidence_rating", "reasoning_tokens"]
    input.verification.candidate_submission[key]
}

fresh_identity_valid if {
    input.verification.candidate_submission.new_candidate_node_id != input.verification.candidate_submission.target_replaced_node_id
}

frontier_contains_quarantined_ancestors if {
    some parent_id in input.verification.candidate_submission.admissible_frontier_parent_ids
    parent_id in input.verification.quarantine_set_Q
}

ephemeral_identity_valid if {
    input.verification.auth_context.is_nhi == true
    input.verification.auth_context.expires_at_epoch > input.verification.request_timestamp_epoch
    input.verification.auth_context.scope == "agent:state:reconstruct"
}

allow_reintegration if {
    not has_evaluative_planner_output
    fresh_identity_valid
    not frontier_contains_quarantined_ancestors
    ephemeral_identity_valid
    input.verification.verifier_execution_status == "PASSED"
}

is_irreducible if {
    frontier_contains_quarantined_ancestors
}

is_irreducible if {
    input.verification.verifier_execution_status == "FAILED_UNRESOLVABLE_DEPENDENCY"
}

# Combined result object — always evaluates to the current state of each rule
result := {
    "allow_state_write": allow_state_write,
    "allow_reintegration": allow_reintegration,
    "is_irreducible": is_irreducible,
}
