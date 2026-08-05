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
import httpx
import jwt
from ecdsa import VerifyingKey, NIST256p
from pydantic_settings import BaseSettings
from typing import Dict, List, Any
from abc import ABC, abstractmethod
from pydantic import BaseModel
from enum import Enum

# --- Settings ---
class Settings(BaseSettings):
    OPA_URL: str | None = None # e.g. http://localhost:8181
    JWT_PUBLIC_KEY: str
    DEBUG_MODE: bool = False

settings = Settings()

ROOT_DIR = Path(__file__).parent.parent
POLICIES_DIR = ROOT_DIR / "policies"
SCHEMAS_DIR = ROOT_DIR / "schemas"
OPA_BIN = ROOT_DIR / "bin" / "opa"

with open(SCHEMAS_DIR / "state_write_payload.json", "r") as f:
    PAYLOAD_SCHEMA = json.load(f)

# --- Designation Models ---
class DesignationSource(str, Enum):
    HUMAN_REPORT = "human_report"
    EXTERNAL_SENSOR = "external_sensor"
    DOWNSTREAM_CONTRADICTION = "downstream_contradiction"
    AMG_TAMPER_CHECK = "amg_tamper_check"

class DesignationEvent(BaseModel):
    poisoned_node_id: str
    detected_at_utc: str
    source: DesignationSource
    confidence_score: float
    reason: str

# --- State Backend Abstraction ---
class BaseStateBackend(ABC):
    @abstractmethod
    async def get_dag(self) -> Dict[str, Any]: pass
    @abstractmethod
    async def get_quarantine_ledger(self) -> List[str]: pass
    @abstractmethod
    async def get_repair_candidates(self) -> Dict[str, Any]: pass
    @abstractmethod
    async def commit_node(self, payload: dict): pass
    @abstractmethod
    async def log_quarantine_event(self, event: dict): pass
    @abstractmethod
    async def add_to_quarantine_ledger(self, node_id: str): pass
    @abstractmethod
    async def compute_blast_radius(self, poisoned_root_id: str) -> List[str]: pass
    @abstractmethod
    async def reset(self): pass

class MemoryStateBackend(BaseStateBackend):
    def __init__(self):
        self.lock = asyncio.Lock()
        self._reset_sync()
        
    def _reset_sync(self):
        self.dag = {"clean-parent-1": {"payload_id": "clean-parent-1", "parent_dependency_commitments": []}}
        self.quarantine_ledger = ["quarantined-node-A"]
        self.quarantine_events = []
        self.repair_candidates = {}
        
    async def get_dag(self) -> Dict[str, Any]:
        async with self.lock: return self.dag.copy()
        
    async def get_quarantine_ledger(self) -> List[str]:
        async with self.lock: return list(self.quarantine_ledger)
        
    async def get_repair_candidates(self) -> Dict[str, Any]:
        async with self.lock: return dict(self.repair_candidates)
        
    async def commit_node(self, payload: dict):
        async with self.lock: self.dag[payload["payload_id"]] = payload
        
    async def log_quarantine_event(self, event: dict):
        async with self.lock: self.quarantine_events.append(event)
        
    async def add_to_quarantine_ledger(self, node_id: str):
        async with self.lock:
            if node_id not in self.quarantine_ledger:
                self.quarantine_ledger.append(node_id)
        
    async def compute_blast_radius(self, poisoned_root_id: str) -> List[str]:
        # True Graph Traversal (BFS) with COMPACTION/CARRIED edge logic
        async with self.lock:
            visited = set([poisoned_root_id])
            queue = [poisoned_root_id]
            c_p = []
            
            while queue:
                current = queue.pop(0)
                c_p.append(current)
                
                for node_id, node_data in self.dag.items():
                    if node_id in visited: continue
                    
                    parents = []
                    is_carried = False
                    for p in node_data.get("parent_dependency_commitments", []):
                        if p["parent_node_id"] == current:
                            parents.append(current)
                            if p.get("edge_class") == "CARRIED":
                                is_carried = True
                                
                    if current in parents:
                        visited.add(node_id)
                        queue.append(node_id)
                        if is_carried:
                            # Flag as repair candidate, but traversal STILL continues (Fail-closed irreducibility)
                            self.repair_candidates[node_id] = {
                                "disposition": "IRREDUCIBLE",
                                "reason": "no_reconstruction_backend",
                                "escalation_record": "Requires human review"
                            }
            return sorted(c_p)

    async def reset(self):
        async with self.lock: self._reset_sync()

backend = MemoryStateBackend()
app = FastAPI()

# --- Security Checks ---
def verify_nhi_jwt(token: str, payload_identity: str) -> dict:
    try:
        claims = jwt.decode(token, settings.JWT_PUBLIC_KEY, algorithms=["ES256"])
        if claims.get("sub") != payload_identity:
            raise ValueError("JWT subject does not match payload identity")
        return claims
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid Session Token: {str(e)}")

def verify_role_jwt(request: Request, required_role: str) -> dict:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid token")
    token = auth_header.split(" ")[1]
    try:
        claims = jwt.decode(token, settings.JWT_PUBLIC_KEY, algorithms=["ES256"])
        if claims.get("role") != required_role:
            raise ValueError(f"Token must have '{required_role}' role")
        return claims
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Unauthorized: {str(e)}")

def verify_cryptographic_signature(payload: dict) -> bool:
    if "agent_signature" not in payload or not payload["agent_signature"]:
        return False
        
    content_str = json.dumps(payload.get("state_content", {}), sort_keys=True)
    actual_hash = hashlib.sha256(content_str.encode()).hexdigest()
    
    if actual_hash != payload.get("content_digest_sha256"):
        return False
        
    public_key_hex = payload.get("ephemeral_nhi", {}).get("identity_id")
    signature_hex = payload.get("agent_signature")
    
    try:
        vk = VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=NIST256p)
        return vk.verify(bytes.fromhex(signature_hex), actual_hash.encode())
    except Exception as e:
        return False

async def evaluate_opa_policy(policy_package: str, query: str, input_data: dict) -> bool:
    if settings.OPA_URL:
        try:
            async with httpx.AsyncClient() as client:
                res = await client.post(f"{settings.OPA_URL}/v1/data/{policy_package}", json={"input": input_data})
                if res.status_code == 200:
                    result = res.json().get("result", {})
                    if "allow_state_write" in result: return result["allow_state_write"]
                    if "allow_reintegration" in result: return result["allow_reintegration"]
                return False
        except Exception as e:
            print(f"OPA REST Error: {e}")
            return False
            
    # Subprocess fallback
    cmd = [str(OPA_BIN), "eval", "-d", str(POLICIES_DIR), "--stdin-input", query]
    process = await asyncio.create_subprocess_exec(
        *cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    stdout, stderr = await process.communicate(input=json.dumps(input_data).encode())
    if process.returncode != 0: return False
    try:
        output = json.loads(stdout.decode())
        return output.get("result", [{}])[0].get("expressions", [{}])[0].get("value", False)
    except: return False

# --- Routes ---
@app.post("/submit-candidate")
async def submit_candidate(request: Request):
    try:
        payload = await request.json()
    except:
        raise HTTPException(status_code=400, detail="Invalid JSON format")
        
    try:
        validate(instance=payload, schema=PAYLOAD_SCHEMA)
    except jsonschema.exceptions.ValidationError as e:
        raise HTTPException(status_code=400, detail=f"Schema validation failed: {e.message}")
        
    token = payload.get("ephemeral_nhi", {}).get("session_token")
    identity_id = payload.get("ephemeral_nhi", {}).get("identity_id")
    auth_context = verify_nhi_jwt(token, identity_id)
    
    if not verify_cryptographic_signature(payload):
        raise HTTPException(status_code=401, detail="Cryptographic signature verification failed")

    # Topological Coverage Diff (if COMPACTION)
    if payload.get("node_type") == "COMPACTION":
        # Simplified coverage diff computation for PoC.
        # In a full implementation, this finds nodes physically situated between the 
        # earliest and latest covered nodes that were omitted from `covers`.
        payload["covers_diff"] = [] 

    q_ledger = await backend.get_quarantine_ledger()
    dag = await backend.get_dag()
    
    # 1. Lineage & Monotonicity
    integrity_input = {
        "quarantine_set_Q_current": q_ledger,
        "quarantine_set_Q_proposed": q_ledger,
        "committed_dag_node_ids": list(dag.keys()),
        "write_request": payload
    }
    is_integrity_valid = await evaluate_opa_policy(
        "gasc/governor/integrity",
        "data.gasc.governor.integrity.allow_state_write",
        integrity_input
    )
    
    if not is_integrity_valid:
        has_tainted_parent = any(p["parent_node_id"] in q_ledger for p in payload.get("parent_dependency_commitments", []))
        if has_tainted_parent:
            poisoned_root = [p["parent_node_id"] for p in payload.get("parent_dependency_commitments", []) if p["parent_node_id"] in q_ledger][0]
            
            await backend.commit_node(payload) 
            c_p = await backend.compute_blast_radius(poisoned_root)
            
            dag_state = await backend.get_dag()
            independent_snapshot_hash = hashlib.sha256(json.dumps(dag_state, sort_keys=True).encode()).hexdigest()
            updated_ledger = q_ledger + [payload.get("payload_id")]
            monotonic_ledger_digest = hashlib.sha256(json.dumps(updated_ledger, sort_keys=True).encode()).hexdigest()
            
            event = {
                "quarantine_event_id": str(uuid.uuid4()),
                "detected_at_utc": datetime.now(timezone.utc).isoformat() + "Z",
                "poisoned_root_id": poisoned_root,
                "computed_blast_radius_C_p": c_p,
                "independent_snapshot_hash": independent_snapshot_hash,
                "monotonic_ledger_digest_post_transition": monotonic_ledger_digest
            }
            await backend.log_quarantine_event(event)
            await backend.add_to_quarantine_ledger(payload.get("payload_id"))
            raise HTTPException(status_code=403, detail={"error": "TAINTED_PARENT", "event": event})
            
        raise HTTPException(status_code=400, detail="Lineage or Monotonicity Invalid")

    # 2. Reintegration Check
    reintegration_input = {
        "candidate_submission": {
            "new_candidate_node_id": payload.get("payload_id"),
            "target_replaced_node_id": "none",
            "admissible_frontier_parent_ids": [p["parent_node_id"] for p in payload.get("parent_dependency_commitments", [])],
        },
        "quarantine_set_Q": q_ledger,
        "auth_context": auth_context,
        "request_timestamp_epoch": int(datetime.now(timezone.utc).timestamp()),
        "verifier_execution_status": auth_context.get("verifier_execution_status", "PENDING")
    }
    
    if "justification" in payload.get("state_content", {}):
        reintegration_input["candidate_submission"]["justification"] = payload["state_content"]["justification"]
        
    is_reintegration_valid = await evaluate_opa_policy(
        "gasc/governor/verification",
        "data.gasc.governor.verification.allow_reintegration",
        reintegration_input
    )
    
    if not is_reintegration_valid:
        raise HTTPException(status_code=403, detail="Verification Separation Policy Failed")

    await backend.commit_node(payload)
    return {"status": "success", "message": "State node committed to DAG."}

@app.post("/designate")
async def designate_poison(event: DesignationEvent, request: Request):
    claims = verify_role_jwt(request, "designator")
    
    dag = await backend.get_dag()
    if event.poisoned_node_id not in dag:
        raise HTTPException(status_code=404, detail="Node ID not found in DAG")
        
    q_ledger = await backend.get_quarantine_ledger()
    if event.poisoned_node_id in q_ledger:
        return {"status": "ok", "message": "Node already in quarantine ledger"}
        
    c_p = await backend.compute_blast_radius(event.poisoned_node_id)
    
    independent_snapshot_hash = hashlib.sha256(json.dumps(dag, sort_keys=True).encode()).hexdigest()
    
    for node in c_p:
        await backend.add_to_quarantine_ledger(node)
            
    updated_ledger = await backend.get_quarantine_ledger()
    monotonic_ledger_digest = hashlib.sha256(json.dumps(updated_ledger, sort_keys=True).encode()).hexdigest()
    
    q_event = {
        "quarantine_event_id": str(uuid.uuid4()),
        "detected_at_utc": datetime.now(timezone.utc).isoformat() + "Z",
        "poisoned_root_id": event.poisoned_node_id,
        "computed_blast_radius_C_p": c_p,
        "independent_snapshot_hash": independent_snapshot_hash,
        "monotonic_ledger_digest_post_transition": monotonic_ledger_digest,
        "designator_identity": claims.get("sub"),
        "designation_reason": event.reason
    }
    await backend.log_quarantine_event(q_event)
    
    return {"status": "success", "event": q_event}

@app.get("/db-state")
async def get_db_state(request: Request):
    verify_role_jwt(request, "admin")
    if not settings.DEBUG_MODE:
        raise HTTPException(status_code=403, detail="Debug endpoints disabled in production")
    return {
        "dag": await backend.get_dag(),
        "quarantine_ledger": await backend.get_quarantine_ledger(),
        "quarantine_events": backend.quarantine_events,
        "repair_candidates": await backend.get_repair_candidates()
    }

@app.post("/reset-db")
async def reset_db(request: Request):
    verify_role_jwt(request, "admin")
    if not settings.DEBUG_MODE:
        raise HTTPException(status_code=403, detail="Debug endpoints disabled in production")
    await backend.reset()
    return {"status": "ok"}
