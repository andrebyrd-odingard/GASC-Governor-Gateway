from fastapi import FastAPI, HTTPException, Request
import json
import subprocess
from pathlib import Path
from datetime import datetime, timezone
import uuid

app = FastAPI()

ROOT_DIR = Path(__file__).parent.parent
POLICIES_DIR = ROOT_DIR / "policies"
OPA_BIN = ROOT_DIR / "bin" / "opa"

# In-memory mock database
db = {
    "dag": {"clean-parent-1": {"content": "initial"}}, # committed nodes
    "quarantine_ledger": ["quarantined-node-A"],       # tainted nodes Q_t
    "quarantine_events": []
}

def evaluate_opa_policy(policy_file: str, query: str, input_data: dict) -> bool:
    input_file = ROOT_DIR / "src" / f"temp_opa_input_{uuid.uuid4().hex}.json"
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
        print(f"OPA CLI error: {result.stderr}")
        return False
        
    output = json.loads(result.stdout)
    if not output.get("result"):
        return False
    
    return output["result"][0]["expressions"][0]["value"]

@app.post("/submit-candidate")
async def submit_candidate(request: Request):
    payload = await request.json()
    
    # Simulate auth context extraction (e.g., from JWT token)
    auth_context = {
        "is_nhi": True,
        "expires_at_epoch": int(datetime.now(timezone.utc).timestamp()) + 3600,
        "scope": "agent:state:reconstruct"
    }
    
    # 1. Lineage & Monotonicity Check (Integrity)
    integrity_input = {
        "quarantine_set_Q_current": db["quarantine_ledger"],
        "quarantine_set_Q_proposed": db["quarantine_ledger"],
        "committed_dag_node_ids": list(db["dag"].keys()),
        "write_request": payload
    }
    is_integrity_valid = evaluate_opa_policy(
        "gasc_quarantine_integrity.rego",
        "data.gasc.governor.integrity.allow_state_write",
        integrity_input
    )
    
    if not is_integrity_valid:
        # Check if the failure is due to a tainted parent
        has_tainted_parent = any(
            p["parent_node_id"] in db["quarantine_ledger"] 
            for p in payload.get("parent_dependency_commitments", [])
        )
        if has_tainted_parent:
            # Trigger Quarantine Logic
            poisoned_root = [
                p["parent_node_id"] for p in payload.get("parent_dependency_commitments", [])
                if p["parent_node_id"] in db["quarantine_ledger"]
            ][0]
            
            event = {
                "quarantine_event_id": str(uuid.uuid4()),
                "detected_at_utc": datetime.now(timezone.utc).isoformat() + "Z",
                "poisoned_root_id": poisoned_root,
                "computed_blast_radius_C_p": [poisoned_root, payload.get("payload_id")],
                "independent_snapshot_hash": "a"*64,
                "monotonic_ledger_digest_post_transition": "b"*64
            }
            db["quarantine_events"].append(event)
            db["quarantine_ledger"].append(payload.get("payload_id")) # Add attempt to ledger
            raise HTTPException(status_code=403, detail={"error": "TAINTED_PARENT", "event": event})
            
        raise HTTPException(status_code=400, detail="Lineage or Monotonicity Invalid")

    # 2. Reintegration Check (Verification)
    # Simulate building the candidate submission object internally
    reintegration_input = {
        "candidate_submission": {
            "new_candidate_node_id": payload.get("payload_id"),
            "target_replaced_node_id": "none",
            "admissible_frontier_parent_ids": [p["parent_node_id"] for p in payload.get("parent_dependency_commitments", [])],
        },
        "quarantine_set_Q": db["quarantine_ledger"],
        "auth_context": auth_context,
        "request_timestamp_epoch": int(datetime.now(timezone.utc).timestamp()),
        "verifier_execution_status": "PASSED"
    }
    
    # Inject forbidden output to simulate policy failure if requested by test
    if "justification" in payload:
        reintegration_input["candidate_submission"]["justification"] = payload["justification"]
        
    is_reintegration_valid = evaluate_opa_policy(
        "gasc_verification_separation.rego",
        "data.gasc.governor.verification.allow_reintegration",
        reintegration_input
    )
    
    if not is_reintegration_valid:
        raise HTTPException(status_code=403, detail="Verification Separation Policy Failed")

    # Success: Commit to DAG
    db["dag"][payload["payload_id"]] = payload
    return {"status": "success", "message": "State node committed to DAG."}

@app.get("/db-state")
def get_db_state():
    return db

@app.post("/reset-db")
def reset_db():
    db["dag"] = {"clean-parent-1": {"content": "initial"}}
    db["quarantine_ledger"] = ["quarantined-node-A"]
    db["quarantine_events"] = []
    return {"status": "ok"}
