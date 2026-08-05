package gasc.governor.verification

import future.keywords

default allow_reintegration = false
default is_irreducible = false

# Rule 1: Verification Separation (GASC-REQ-006)
# Evaluative planner output (scores, reasoning tokens, justifications) is strictly prohibited in input context.
has_evaluative_planner_output if {
    some key in ["planner_score", "justification", "confidence_rating", "reasoning_tokens"]
    input.candidate_submission[key]
}

# Rule 2: Fresh Identity Constraint (GASC-REQ-005)
# Replaced ID must never equal candidate ID.
fresh_identity_valid if {
    input.candidate_submission.new_candidate_node_id != input.candidate_submission.target_replaced_node_id
}

# Rule 3: Provenance Frontier Cleanliness (GASC-REQ-003 & GASC-REQ-005)
# No ancestor in candidate frontier may exist inside the global Quarantine Set Q.
frontier_contains_quarantined_ancestors if {
    some parent_id in input.candidate_submission.admissible_frontier_parent_ids
    parent_id in input.quarantine_set_Q
}

# Rule 4: Ephemeral Credential Validity (GASC-REQ-011)
ephemeral_identity_valid if {
    input.auth_context.is_nhi == true
    input.auth_context.expires_at_epoch > input.request_timestamp_epoch
    input.auth_context.scope == "agent:state:reconstruct"
}

# Master Reintegration Authorization Rule
allow_reintegration if {
    not has_evaluative_planner_output
    fresh_identity_valid
    not frontier_contains_quarantined_ancestors
    ephemeral_identity_valid
    input.verifier_execution_status == "PASSED"
}

# Trigger Irreducibility Escalation (GASC-REQ-009)
is_irreducible if {
    frontier_contains_quarantined_ancestors
}

is_irreducible if {
    input.verifier_execution_status == "FAILED_UNRESOLVABLE_DEPENDENCY"
}
