import pytest
from fastapi.testclient import TestClient
import json
import hashlib

from src.recovery_adapter import app, public_key_hex

client = TestClient(app)

def test_reconstruct_success_path():
    req = {
        "graph_snapshot": {
            "root": {"parent_dependency_commitments": []},
            "poisoned": {"parent_dependency_commitments": [{"parent_node_id": "root", "edge_class": "CARRIED"}]},
            "clean_sibling": {"parent_dependency_commitments": [{"parent_node_id": "root", "edge_class": "CARRIED"}]},
            "compaction": {"covers": ["root", "poisoned", "clean_sibling"]}
        },
        "quarantine_ledger": ["poisoned"],
        "poisoned_root_id": "poisoned",
        "compaction_covers": ["root", "poisoned", "clean_sibling"],
        "requested_frontier": ["clean_sibling", "root"],
        "method": "llm-v1",
        "checkpoint": {"snapshot_data": {"test": "data"}}
    }
    
    res = client.post("/reconstruct", json=req)
    assert res.status_code == 200
    candidate = res.json()["candidate"]
    
    assert candidate["node_type"] == "COMPACTION"
    assert set(candidate["covers"]) == set(["root", "clean_sibling"])
    assert candidate["ephemeral_nhi"]["identity_id"] == public_key_hex
    assert "mocked generated summary" in candidate["state_content"]["data"]
    
def test_reconstruct_frontier_mismatch():
    req = {
        "graph_snapshot": {
            "root": {"parent_dependency_commitments": []},
            "poisoned": {"parent_dependency_commitments": [{"parent_node_id": "root", "edge_class": "CARRIED"}]},
            "clean_sibling": {"parent_dependency_commitments": [{"parent_node_id": "root", "edge_class": "CARRIED"}]}
        },
        "quarantine_ledger": ["poisoned"],
        "poisoned_root_id": "poisoned",
        "compaction_covers": ["root", "poisoned", "clean_sibling"],
        "requested_frontier": ["root", "poisoned", "clean_sibling"], # Incorrectly requesting poisoned node
        "method": "llm-v1",
        "checkpoint": {"snapshot_data": {"test": "data"}}
    }
    
    res = client.post("/reconstruct", json=req)
    assert res.status_code == 403
    assert res.json()["detail"] == "frontier_mismatch"
