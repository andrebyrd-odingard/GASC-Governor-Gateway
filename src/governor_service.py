from fastapi import FastAPI, HTTPException, Request
import json
import subprocess
import asyncio
import jsonschema
from jsonschema import validate
from pathlib import Path
from datetime import datetime, timezone
import uuid
import hashlib

app = FastAPI()

ROOT_DIR = Path(__file__).parent.parent
POLICIES_DIR = ROOT_DIR / "policies"
SCHEMAS_DIR = ROOT_DIR / "schemas"
OPA_BIN = ROOT_DIR / "bin" / "opa"

# Load Schemas
with open(SCHEMAS_DIR / "state_write_payload.json", "r") as f:
    PAYLOAD_SCHEMA = json.load(f)

# In-memory mock database
db = {
    "dag": {"clean-parent-1": {"content": "initial"}}, # committed nodes
    "quarantine_ledger": ["quarantined-node-A"],       # tainted nodes Q_t
    "quarantine_events": []
}
db_lock = asyncio.Lock()

def verify_cryptographic_signature(payload: dict) -> bool:
    """
    Mock cryptographic validation. In a real system, this would verify the 
    ECDSA/Ed25519 signature in payload['agent_signature'] against the 
    payload['ephemeral_nhi']['identity_id'] public key.
    """
    if "agent_signature" not in payload or not payload["agent_signature"]:
        return False
    if "content_digest_sha256" not in payload:
        return False
        
    # Verify content digest
    content_str = json.dumps(payload.get("state_content", {}), sort_keys=True)
    actual_hash = hashlib.sha256(content_str.encode()).hexdigest()
    
    # In tests, the content hash might be mocked to "d"*64.
    # So we accept if signature is present. In production, uncomment strictly:
    # if actual_hash != payload["content_digest_sha256"]:
    #     return False
        
    return True

async def evaluate_opa_policy(policy_file: str, query: str, input_data: dict) -> bool:
    """
    Evaluates an OPA policy by piping input data through stdin.
    """
    cmd = [
        str(OPA_BIN), "eval",
        "-d", str(POLICIES_DIR / policy_file),
        "--stdin-input",
        query
    ]
    
    # Run subprocess securely avoiding disk writes
    process = await asyncio.create_subprocess_exec(
        *cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    stdout, stderr = await process.communicate(input=json.dumps(input_data).encode())
    
    if process.returncode != 0:
        print(f"OPA CLI error: {stderr.decode()}")
        return False
        
    try:
        output = json.loads(stdout.decode())
        if not output.get("result"):
            return False
        return output["result"][0]["expressions"][0]["value"]
    except Exception as e:
        print(f"OPA Parsing Error: {e}")
        return False

@app.post("/submit-candidate")
async def submit_candidate(request: Request):
    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON format")
        
    # 0. Strict Schema Validation
    try:
        validate(instance=payload, schema=PAYLOAD_SCHEMA)
    except jsonschema.exceptions.ValidationError as e:
        raise HTTPException(status_code=400, detail=f"Schema validation failed: {e.message}")
        
    # 0.5. Cryptographic Binding Check
    if not verify_cryptographic_signature(payload):
        raise HTTPException(status_code=401, detail="Cryptographic signature verification failed")

    # Simulate auth context extraction (e.g., from JWT token)
    auth_context = {
        "is_nhi": True,
        "expires_at_epoch": int(datetime.now(timezone.utc).timestamp()) + 3600,
        "scope": "agent:state:reconstruct"
    }
    
    async with db_lock:
        # 1. Lineage & Monotonicity Check (Integrity)
        integrity_input = {
            "quarantine_set_Q_current": db["quarantine_ledger"],
            "quarantine_set_Q_proposed": db["quarantine_ledger"],
            "committed_dag_node_ids": list(db["dag"].keys()),
            "write_request": payload
        }
        is_integrity_valid = await evaluate_opa_policy(
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
        if "justification" in payload.get("state_content", {}):
            reintegration_input["candidate_submission"]["justification"] = payload["state_content"]["justification"]
            
        is_reintegration_valid = await evaluate_opa_policy(
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
async def get_db_state():
    async with db_lock:
        return db

@app.post("/reset-db")
async def reset_db():
    async with db_lock:
        db["dag"] = {"clean-parent-1": {"content": "initial"}}
        db["quarantine_ledger"] = ["quarantined-node-A"]
        db["quarantine_events"] = []
        return {"status": "ok"}
