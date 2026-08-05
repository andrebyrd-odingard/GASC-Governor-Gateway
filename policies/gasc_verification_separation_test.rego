package gasc.governor.verification

# Test Case 1: A valid reintegration request should be allowed.
test_allow_reintegration_success if {
    allow_reintegration with input as {
        "candidate_submission": {
            "new_candidate_node_id": "uuid-new",
            "target_replaced_node_id": "uuid-old",
            "admissible_frontier_parent_ids": ["clean-parent-1"]
        },
        "quarantine_set_Q": ["quarantined-node-A"],
        "auth_context": {
            "is_nhi": true,
            "expires_at_epoch": 2000000000, 
            "scope": "agent:state:reconstruct"
        },
        "request_timestamp_epoch": 1700000000, 
        "verifier_execution_status": "PASSED"
    }
}

# Test Case 2: Deny if planner justification is present (REQ-006 violation).
test_deny_due_to_planner_output if {
    not allow_reintegration with input as {
        "candidate_submission": {
            "new_candidate_node_id": "uuid-new",
            "target_replaced_node_id": "uuid-old",
            "admissible_frontier_parent_ids": ["clean-parent-1"],
            "justification": "The agent thinks this is a good idea." 
        },
        "quarantine_set_Q": ["quarantined-node-A"],
        "auth_context": { "is_nhi": true, "expires_at_epoch": 2000000000, "scope": "agent:state:reconstruct" },
        "request_timestamp_epoch": 1700000000,
        "verifier_execution_status": "PASSED"
    }
}

# Test Case 3: Deny if a parent is in the quarantine set (REQ-003/005 violation).
test_deny_due_to_quarantined_ancestor if {
    not allow_reintegration with input as {
        "candidate_submission": {
            "new_candidate_node_id": "uuid-new",
            "target_replaced_node_id": "uuid-old",
            "admissible_frontier_parent_ids": ["quarantined-node-A"] 
        },
        "quarantine_set_Q": ["quarantined-node-A"], 
        "auth_context": { "is_nhi": true, "expires_at_epoch": 2000000000, "scope": "agent:state:reconstruct" },
        "request_timestamp_epoch": 1700000000,
        "verifier_execution_status": "PASSED"
    }
}

# Test Case 4: Ensure irreducibility is triggered for a quarantined ancestor.
test_is_irreducible_on_tainted_frontier if {
    is_irreducible with input as {
        "candidate_submission": {
            "admissible_frontier_parent_ids": ["quarantined-node-A"]
        },
        "quarantine_set_Q": ["quarantined-node-A"]
    }
}
