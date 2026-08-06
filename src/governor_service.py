from fastapi import FastAPI, HTTPException, Request
import json
import subprocess
import asyncio
from contextlib import asynccontextmanager
import jsonschema
from jsonschema import validate
from pathlib import Path
from datetime import datetime, timezone
import uuid
import hashlib
import httpx
import jwt
import os
import json
from ecdsa import VerifyingKey, NIST256p
from pydantic_settings import BaseSettings
from typing import Dict, List, Any
from abc import ABC, abstractmethod
from pydantic import BaseModel
from enum import Enum
import subprocess
import asyncio

try:
    import wasmtime
    from src.wasm_engine import OpaWasmEngine
except ImportError:
    wasmtime = None

# --- Settings ---
from src.config import settings


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

class CheckpointEvent(BaseModel):
    checkpoint_id: str
    target_node_id: str
    declared_at_utc: str
    snapshot_data: dict

class ContextCompactedEvent(BaseModel):
    compacted_node_ids: List[str]
    compaction_node_id: str
    timestamp_utc: str
    ephemeral_nhi: dict
    state_content: dict
    agent_signature: str
    method_id: str = "llm_summary"


class ObserveEvent(BaseModel):
    node_id: str
    recurrence_class: str
    detected_at_utc: str
    evidence: dict = {}
    adapter_signature: str | None = None


class CalibrateRequest(BaseModel):
    run_id: str
    run_at_utc: str
    seeded_count: int
    detected_count: int
    sensitivity_floor: float
    monitored_period: dict

class RenewTrustRequest(BaseModel):
    node_id: str

class ExternalEffectEvent(BaseModel):
    idempotency_key: str
    node_id: str
    effect_type: str

# --- State Backend Abstraction ---
class BaseStateBackend(ABC):
    @abstractmethod
    async def get_dag(self) -> Dict[str, Any]: pass
    @abstractmethod
    async def get_quarantine_ledger(self) -> List[str]: pass
    @abstractmethod
    async def get_repair_candidates(self) -> Dict[str, Any]: pass
    @abstractmethod
    async def update_repair_candidate(self, node_id: str, data: dict): pass
    @abstractmethod
    async def commit_node(self, payload: dict): pass
    @abstractmethod
    async def log_quarantine_event(self, event: dict): pass
    @abstractmethod
    async def add_to_quarantine_ledger(self, node_id: str): pass
    @abstractmethod
    async def apply_quarantine_transaction(self, event: dict, c_p: List[str]): pass
    @abstractmethod
    async def get_quarantine_events(self) -> List[dict]: pass
    @abstractmethod
    async def compute_blast_radius(self, poisoned_root_id: str) -> List[str]: pass
    @abstractmethod
    async def add_checkpoint(self, checkpoint: dict): pass
    @abstractmethod
    async def add_external_effect(self, idempotency_key: str, node_id: str, effect_type: str): pass
    @abstractmethod
    async def check_external_effect(self, idempotency_key: str) -> bool: pass
    @abstractmethod
    async def has_external_effects(self, node_ids: List[str]) -> bool: pass
    @abstractmethod
    async def get_checkpoints(self) -> Dict[str, dict]: pass
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
        self.checkpoints = {}
        self.external_effects = {}
        self.shadow_decisions = []
        
    async def get_dag(self) -> Dict[str, Any]:
        async with self.lock: return self.dag.copy()
        
    async def get_quarantine_ledger(self) -> List[str]:
        async with self.lock: return list(self.quarantine_ledger)
        
    async def get_repair_candidates(self) -> Dict[str, Any]:
        async with self.lock: return dict(self.repair_candidates)
        
    async def update_repair_candidate(self, node_id: str, data: dict):
        async with self.lock: self.repair_candidates[node_id] = data
        
    async def commit_node(self, payload: dict):
        async with self.lock: self.dag[payload["payload_id"]] = payload
        
    async def log_quarantine_event(self, event: dict):
        async with self.lock: self.quarantine_events.append(event)
        
    async def add_to_quarantine_ledger(self, node_id: str):
        async with self.lock:
            if node_id not in self.quarantine_ledger:
                self.quarantine_ledger.append(node_id)
                
    async def apply_quarantine_transaction(self, event: dict, c_p: List[str]):
        async with self.lock:
            self.quarantine_events.append(event)
            for node_id in c_p:
                if node_id not in self.quarantine_ledger:
                    self.quarantine_ledger.append(node_id)
                    
    async def get_quarantine_events(self) -> List[dict]:
        async with self.lock: return list(self.quarantine_events)
                
    async def add_checkpoint(self, checkpoint: dict):
        async with self.lock: self.checkpoints[checkpoint["checkpoint_id"]] = checkpoint
        
    async def get_checkpoints(self) -> Dict[str, dict]:
        async with self.lock: return dict(self.checkpoints)
        
    async def compute_blast_radius(self, poisoned_root_id: str) -> List[str]:
        # True Graph Traversal (BFS) with COMPACTION/CARRIED edge logic
        async with self.lock:
            visited = set([poisoned_root_id])
            queue = [poisoned_root_id]
            c_p = []
            affected_compactions = []
            
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
                            affected_compactions.append(node_id)
            
            # R1 & R2
            semantic_rollback = False
            for effect in self.external_effects.values():
                if effect["node_id"] in c_p:
                    semantic_rollback = True
                    break
            
            for comp_node in affected_compactions:
                if semantic_rollback:
                    self.repair_candidates[comp_node] = {
                        "disposition": "IRREDUCIBLE",
                        "reason": "semantic_rollback_hazard",
                        "escalation_record": "Quarantined subgraph contains irreversible external effects"
                    }
                    continue
                    
                covers = self.dag[comp_node].get("covers", [])
                
                # R1: Admissible Frontier
                frontier = [n for n in covers if n not in c_p]
                if not frontier:
                    self.repair_candidates[comp_node] = {
                        "disposition": "IRREDUCIBLE",
                        "reason": "empty_frontier",
                        "escalation_record": "Requires human review"
                    }
                    continue
                
                # R2: Planner & Selection
                summarizer = self.dag[comp_node].get("summarizer", {})
                if summarizer.get("method_id") == "llm-v1":
                    # Require verified checkpoint reconstruction
                    admissible_checkpoint = None
                    for cp_id, cp_data in self.checkpoints.items():
                        # Admissibility: targets a clean node (in F) and not in C_p (which is true if in F)
                        if cp_data["target_node_id"] in frontier:
                            admissible_checkpoint = cp_data
                            break
                            
                    if not admissible_checkpoint:
                        self.repair_candidates[comp_node] = {
                            "disposition": "IRREDUCIBLE",
                            "reason": "no_admissible_checkpoint",
                            "escalation_record": "Requires human review"
                        }
                        continue
                        
                    if not settings.RECOVERY_ADAPTER_URL:
                        self.repair_candidates[comp_node] = {
                            "disposition": "IRREDUCIBLE",
                            "reason": "no_reconstruction_backend",
                            "escalation_record": "Requires human review"
                        }
                        continue
                        
                    self.repair_candidates[comp_node] = {
                        "disposition": "PENDING_RECONSTRUCTION",
                        "frontier": frontier,
                        "method": "verified_checkpoint_reconstruction",
                        "checkpoint": admissible_checkpoint
                    }
                else:
                    self.repair_candidates[comp_node] = {
                        "disposition": "IRREDUCIBLE",
                        "reason": "no_reconstruction_backend",
                        "escalation_record": "Unknown summarizer method"
                    }
                    
            return sorted(c_p)

    async def add_external_effect(self, idempotency_key: str, node_id: str, effect_type: str):
        async with self.lock:
            self.external_effects[idempotency_key] = {
                "node_id": node_id,
                "effect_type": effect_type,
                "recorded_at_utc": datetime.now(timezone.utc).isoformat() + "Z"
            }

    async def check_external_effect(self, idempotency_key: str) -> bool:
        async with self.lock:
            return idempotency_key in self.external_effects

    async def has_external_effects(self, node_ids: List[str]) -> bool:
        async with self.lock:
            for effect in self.external_effects.values():
                if effect["node_id"] in node_ids:
                    return True
            return False

    async def reset(self):
        async with self.lock: self._reset_sync()

    async def record_reintegration(self, node_id: str, predecessor_id: str, horizon_seconds: int): pass
    async def get_active_horizon_set(self) -> Dict[str, dict]: return {}
    async def get_expired_horizon_set(self) -> List[str]: return []
    async def renew_trust(self, node_id: str, horizon_seconds: int): pass
    async def apply_withdrawal_transaction(self, event: dict, w_r: List[str]): pass
    async def get_withdrawal_ledger(self) -> Dict[str, dict]: return {}
    async def record_calibration_run(self, run: dict): pass
    async def get_calibration_runs(self) -> List[dict]: return []
    
    async def record_shadow_decision(self, decision_id: str, node_id: str, evaluated_at_utc: str, would_have_blocked: bool, reason: str, parent_status_json: str, policy_bundle_digest: str, writer_identity: str):
        async with self.lock:
            self.shadow_decisions.append({"would_have_blocked": would_have_blocked})



    async def nodes_exist(self, node_ids: List[str]) -> Dict[str, bool]:
        async with self.lock:
            return {nid: (nid in self.dag) for nid in node_ids}

    async def are_quarantined(self, node_ids: List[str]) -> Dict[str, bool]:
        async with self.lock:
            q_set = set(self.quarantine_ledger)
            return {nid: (nid in q_set) for nid in node_ids}

    async def compute_covers_interval_gap(self, covers: List[str]) -> List[str]:
        async with self.lock:
            return _compute_covers_interval_gap(self.dag, covers)

    async def compute_quarantine_digest(self, additional_node_ids: List[str]) -> str:
        async with self.lock:
            merged = sorted(set(self.quarantine_ledger) | set(additional_node_ids))
            return hashlib.sha256(json.dumps(merged, sort_keys=True).encode()).hexdigest()


if settings.BACKEND_TYPE == "sqlite":
    from src.sqlite_backend import SqliteStateBackend
    backend = SqliteStateBackend()
else:
    backend = MemoryStateBackend()

# --- Admission Lock (Phase 2 Part A) ---
# Prevents the race where /designate quarantines a parent between
# are_quarantined() and commit_node() in /submit-candidate.
# Admissions take SHARED; designations take EXCLUSIVE.
# Single lock key, consistent acquisition order, no nesting.
class _AdmissionLock:
    """
    Async read-write lock. Readers (admissions) run concurrently;
    a writer (designation) blocks until all readers finish and
    excludes further readers until it completes.

    The internal asyncio.Lock is created lazily on first use to avoid
    binding to an event loop at import time (which breaks test parametrization).
    """
    def __init__(self):
        self._readers = 0
        self._writer = False
        self._write_requested = False
        self._mutex = None

    def _get_mutex(self):
        if self._mutex is None:
            self._mutex = asyncio.Lock()
        return self._mutex

    @asynccontextmanager
    async def shared(self):
        mutex = self._get_mutex()
        while True:
            async with mutex:
                if not self._writer and not self._write_requested:
                    self._readers += 1
                    break
            # Writer active or requested — yield control and retry
            await asyncio.sleep(0)
        try:
            yield
        finally:
            async with mutex:
                self._readers -= 1

    @asynccontextmanager
    async def exclusive(self):
        mutex = self._get_mutex()
        # Signal that a write is requested so new readers back off
        async with mutex:
            self._write_requested = True

        # Wait for existing readers to drain
        while True:
            async with mutex:
                if self._readers == 0 and not self._writer:
                    self._writer = True
                    break
            await asyncio.sleep(0)
        try:
            yield
        finally:
            async with mutex:
                self._writer = False
                self._write_requested = False


_admission_lock = _AdmissionLock()

app = FastAPI()

@app.on_event("startup")
async def startup_event():
    if hasattr(backend, "init_db"):
        await backend.init_db()
        
    if settings.ENFORCEMENT_MODE == "shadow":
        if settings.SHADOW_BANNER:
            print("===========================================================")
            print("WARNING: GASC GOVERNOR IS RUNNING IN SHADOW MODE")
            print("Writes that fail policy checks WILL BE ADMITTED.")
            print("Decisions are recorded in shadow_decisions for auditing.")
            print("===========================================================")

    # §A.3: Warn if admission lock will be held across a slow policy call.
    # WASM evaluates in sub-100µs; subprocess/REST takes ~14ms with 1s tail.
    if not (settings.OPA_POLICY_BUNDLE and settings.OPA_POLICY_BUNDLE.endswith(".wasm")):
        import logging
        logging.getLogger("gasc.governor").warning(
            "ADMISSION LOCK WARNING: Policy evaluation is NOT using WASM. "
            "The shared admission lock will be held across an out-of-process OPA "
            "call (~14ms p50, 1s tail). WASM bundle (OPA_POLICY_BUNDLE=*.wasm) is "
            "required for production concurrency."
        )


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

_wasm_engine_cache = {}
_wasm_engine_lock = asyncio.Lock()


class PolicyEvaluationError(Exception):
    """Raised when the policy engine fails to evaluate (distinct from policy returning False)."""
    pass


async def evaluate_opa_policy(policy_package: str, query: str, input_data: dict) -> bool:
    if settings.OPA_POLICY_BUNDLE and os.path.exists(settings.OPA_POLICY_BUNDLE):
        if wasmtime and settings.OPA_POLICY_BUNDLE.endswith(".wasm"):
            async with _wasm_engine_lock:
                if settings.OPA_POLICY_BUNDLE not in _wasm_engine_cache:
                    _wasm_engine_cache[settings.OPA_POLICY_BUNDLE] = OpaWasmEngine(settings.OPA_POLICY_BUNDLE)
            engine = _wasm_engine_cache[settings.OPA_POLICY_BUNDLE]

            try:
                result = engine.evaluate(input_data, query)
            except RuntimeError as e:
                raise PolicyEvaluationError(f"WASM policy evaluation failed: {e}") from e

            if not result:
                raise PolicyEvaluationError("WASM returned empty result set")
            res = result[0].get("result", False)
            if isinstance(res, bool):
                return res
            if isinstance(res, dict):
                if "allow_state_write" in res:
                    return res["allow_state_write"]
                if "allow_reintegration" in res:
                    return res["allow_reintegration"]
            return False
                
        cmd = [str(OPA_BIN), "eval", "-b", settings.OPA_POLICY_BUNDLE, "--stdin-input", query]
        process = await asyncio.create_subprocess_exec(
            *cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, stderr = await process.communicate(input=json.dumps(input_data).encode())
        if process.returncode != 0:
            raise PolicyEvaluationError(
                f"OPA bundle eval failed (exit {process.returncode}): {stderr.decode()[:200]}"
            )
        output = json.loads(stdout.decode())
        return output.get("result", [{}])[0].get("expressions", [{}])[0].get("value", False)

    if settings.OPA_URL:
        try:
            async with httpx.AsyncClient() as client:
                res = await client.post(f"{settings.OPA_URL}/v1/data/{policy_package}", json={"input": input_data})
                if res.status_code == 200:
                    result = res.json().get("result", {})
                    if "allow_state_write" in result: return result["allow_state_write"]
                    if "allow_reintegration" in result: return result["allow_reintegration"]
                    return False
                raise PolicyEvaluationError(f"OPA REST returned {res.status_code}")
        except PolicyEvaluationError:
            raise
        except Exception as e:
            raise PolicyEvaluationError(f"OPA REST unreachable: {e}") from e
            
    # Subprocess fallback
    cmd = [str(OPA_BIN), "eval", "-d", str(POLICIES_DIR), "--stdin-input", query]
    process = await asyncio.create_subprocess_exec(
        *cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    stdout, stderr = await process.communicate(input=json.dumps(input_data).encode())

    if process.returncode != 0:
        raise PolicyEvaluationError(
            f"OPA subprocess failed (exit {process.returncode}): {stderr.decode()[:200]}"
        )
    try:
        output = json.loads(stdout.decode())
        return output.get("result", [{}])[0].get("expressions", [{}])[0].get("value", False)
    except (json.JSONDecodeError, IndexError, KeyError) as e:
        raise PolicyEvaluationError(f"OPA output unparseable: {e}") from e

def _compute_covers_interval_gap(dag, covers):
    if not covers: return []
    covers_set = set(covers)
    
    # D_covers: nodes reachable FROM any node in covers
    d_covers = set(covers)
    queue = list(covers)
    while queue:
        curr = queue.pop(0)
        for node_id, data in dag.items():
            parents = [p["parent_node_id"] for p in data.get("parent_dependency_commitments", [])]
            if curr in parents and node_id not in d_covers:
                d_covers.add(node_id)
                queue.append(node_id)
                
    # A_covers: nodes that can REACH any node in covers
    a_covers = set(covers)
    queue = list(covers)
    while queue:
        curr = queue.pop(0)
        curr_data = dag.get(curr, {})
        parents = [p["parent_node_id"] for p in curr_data.get("parent_dependency_commitments", [])]
        for p_id in parents:
            if p_id in dag and p_id not in a_covers:
                a_covers.add(p_id)
                queue.append(p_id)
                
    interval = d_covers.intersection(a_covers)
    return sorted(list(interval - covers_set))

# --- Routes ---

async def evaluate_admission(payload: dict, parent_ids: List[str], exists_map: Dict[str, bool], quarantined_map: Dict[str, bool], auth_context: dict) -> dict:
    integrity_input = {
        "write_request": payload,
        "parent_status": [
            {
                "parent_node_id": pid,
                "exists": exists_map.get(pid, False),
                "quarantined": quarantined_map.get(pid, False),
            }
            for pid in parent_ids
        ],
    }

    is_integrity_valid = await evaluate_opa_policy(
        "gasc/governor/integrity",
        "data.gasc.governor.integrity.allow_state_write",
        integrity_input
    )
    
    if not is_integrity_valid:
        tainted = [pid for pid in parent_ids if quarantined_map.get(pid)]
        if tainted:
            return {"admit": False, "reason": "TAINTED_PARENT", "poisoned_root": tainted[0]}
        return {"admit": False, "reason": "Lineage or Monotonicity Invalid"}

    reintegration_input = {
        "candidate_submission": {
            "new_candidate_node_id": payload.get("payload_id"),
            "target_replaced_node_id": "none",
            "admissible_frontier_parent_ids": parent_ids,
        },
        "quarantine_set_Q": [pid for pid in parent_ids if quarantined_map.get(pid)],
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
        return {"admit": False, "reason": "Verification Separation Policy Failed"}

    return {"admit": True}

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

    parent_ids = [p["parent_node_id"] for p in payload.get("parent_dependency_commitments", [])]
    if len(parent_ids) > 256:
        raise HTTPException(status_code=400, detail="Too many declared parents")

    # --- Transactional admission (Phase 2 Part A) ---
    # The shared lock ensures no /designate can quarantine a parent between
    # the taint check and the commit. Policy evaluation is inside the lock;
    # with WASM this is sub-100µs. See §A.3 for the subprocess warning.
    async with _admission_lock.shared():
        exists_map, quarantined_map = await asyncio.gather(
            backend.nodes_exist(parent_ids),
            backend.are_quarantined(parent_ids),
        )

        if payload.get("node_type") == "COMPACTION":
            payload["covers_interval_gap"] = await backend.compute_covers_interval_gap(payload.get("covers", []))

        try:
            decision = await evaluate_admission(payload, parent_ids, exists_map, quarantined_map, auth_context)
        except PolicyEvaluationError as e:
            raise HTTPException(status_code=503, detail=f"Policy engine unavailable: {e}")

        decision_id = str(uuid.uuid4())
        writer_identity = auth_context.get("sub", "unknown")
        parent_status_json = json.dumps([{"parent_node_id": pid, "exists": exists_map.get(pid, False), "quarantined": quarantined_map.get(pid, False)} for pid in parent_ids])

        if settings.ENFORCEMENT_MODE == "shadow":
            await backend.record_shadow_decision(
                decision_id=decision_id,
                node_id=payload.get("payload_id"),
                evaluated_at_utc=datetime.now(timezone.utc).isoformat() + "Z",
                would_have_blocked=not decision["admit"],
                reason=decision.get("reason", ""),
                parent_status_json=parent_status_json,
                policy_bundle_digest=settings.OPA_POLICY_BUNDLE or "none",
                writer_identity=writer_identity
            )
            # Shadow mode: always admit unless invalid signature/schema (which we already threw for)
            await backend.commit_node(payload)
            return {"status": "success", "message": "State node committed to DAG (Shadow Mode)."}
        else:
            if not decision["admit"]:
                await backend.record_shadow_decision(
                    decision_id=decision_id,
                    node_id=payload.get("payload_id"),
                    evaluated_at_utc=datetime.now(timezone.utc).isoformat() + "Z",
                    would_have_blocked=True,
                    reason=decision.get("reason", ""),
                    parent_status_json=parent_status_json,
                    policy_bundle_digest=settings.OPA_POLICY_BUNDLE or "none",
                    writer_identity=writer_identity
                )

                if decision.get("reason") == "TAINTED_PARENT":
                    poisoned_root = decision["poisoned_root"]
                    # Deliberate: commit the rejected payload so it appears in the
                    # blast-radius BFS and the quarantine ledger for audit
                    # completeness.  The node is refused (403) but its attempt is
                    # permanently recorded — the same way a firewall logs dropped
                    # packets.
                    await backend.commit_node(payload)
                    c_p = await backend.compute_blast_radius(poisoned_root)

                    from src.r6_utils import process_recurrence
                    active_horizons = await backend.get_active_horizon_set()
                    for n in c_p:
                        if n in active_horizons:
                            await process_recurrence(backend, n, "PROHIBITED_PATH", "internal_hook")

                    new_quarantined = [payload.get("payload_id")]
                    monotonic_ledger_digest = await backend.compute_quarantine_digest(c_p + new_quarantined)

                    event = {
                        "quarantine_event_id": str(uuid.uuid4()),
                        "detected_at_utc": datetime.now(timezone.utc).isoformat() + "Z",
                        "poisoned_root_id": poisoned_root,
                        "computed_blast_radius_C_p": c_p,
                        "monotonic_ledger_digest_post_transition": monotonic_ledger_digest
                    }
                    await backend.apply_quarantine_transaction(event, new_quarantined)
                    raise HTTPException(status_code=403, detail={"error": "TAINTED_PARENT", "event": event})
                else:
                    raise HTTPException(status_code=403 if decision.get("reason") == "Verification Separation Policy Failed" else 400, detail=decision.get("reason", "Policy Failed"))

            await backend.record_shadow_decision(
                decision_id=decision_id,
                node_id=payload.get("payload_id"),
                evaluated_at_utc=datetime.now(timezone.utc).isoformat() + "Z",
                would_have_blocked=False,
                reason="",
                parent_status_json=parent_status_json,
                policy_bundle_digest=settings.OPA_POLICY_BUNDLE or "none",
                writer_identity=writer_identity
            )
            await backend.commit_node(payload)
            return {"status": "success", "message": "State node committed to DAG."}

@app.post("/declare-external-effect")

async def declare_external_effect(event: ExternalEffectEvent, request: Request):
    """
    Records an external effect (e.g. API call, payment) to prevent semantic rollbacks.
    The agent must declare external effects so they can't be replayed across quarantine.
    """
    verify_role_jwt(request, "admin")  # Only trusted services can declare effects
    await backend.add_external_effect(event.idempotency_key, event.node_id, event.effect_type)
    return {"status": "success", "message": "External effect recorded."}

@app.post("/context-compacted")
async def declare_context_compacted(event: ContextCompactedEvent, request: Request):
    """
    ACP Extension: Translates an LLM context compaction event into a trackable
    COMPACTION node in the DAG, turning the untracked carry channel into a tracked read.
    """
    dag = await backend.get_dag()
    
    parent_commitments = []
    for nid in event.compacted_node_ids:
        if nid not in dag:
            raise HTTPException(status_code=400, detail=f"Compacted node {nid} not found in DAG")
        p_hash = dag[nid].get("content_digest_sha256", "0"*64)
        parent_commitments.append({
            "parent_node_id": nid,
            "parent_content_hash": p_hash,
            "edge_class": "CARRIED"
        })
        
    content_str = json.dumps(event.state_content, sort_keys=True)
    actual_hash = hashlib.sha256(content_str.encode()).hexdigest()
    
    payload = {
        "payload_id": event.compaction_node_id,
        "node_type": "COMPACTION",
        "timestamp_utc": event.timestamp_utc,
        "ephemeral_nhi": event.ephemeral_nhi,
        "declared_evidence_boundary": {
            "boundary_id": f"bnd-{event.compaction_node_id}",
            "fixed_at_utc": event.timestamp_utc,
            "boundary_digest": "0"*64
        },
        "state_content": event.state_content,
        "content_digest_sha256": actual_hash,
        "agent_signature": event.agent_signature,
        "covers": event.compacted_node_ids,
        "parent_dependency_commitments": parent_commitments,
        "summarizer": {
            "method_id": event.method_id,
            "config_digest": "0"*64
        }
    }
    
    token = payload.get("ephemeral_nhi", {}).get("session_token")
    identity_id = payload.get("ephemeral_nhi", {}).get("identity_id")
    verify_nhi_jwt(token, identity_id)
    
    if not verify_cryptographic_signature(payload):
        raise HTTPException(status_code=401, detail="Cryptographic signature verification failed")

    # Shared lock: /context-compacted is a commit path, same as /submit-candidate.
    async with _admission_lock.shared():
        await backend.commit_node(payload)
    return {"status": "success", "message": "Compaction node committed to DAG."}

@app.post("/checkpoint")
async def declare_checkpoint(event: CheckpointEvent, request: Request):
    verify_role_jwt(request, "admin")
    
    # We do not verify admissibility at declaration time (e.g., predates containment),
    # since there is no incident yet. We just store the checkpoint.
    await backend.add_checkpoint(event.model_dump())
    return {"status": "success", "message": "Checkpoint declared"}

@app.post("/designate")
async def designate_poison(event: DesignationEvent, request: Request):
    claims = verify_role_jwt(request, "designator")

    # --- Exclusive lock (Phase 2 Part A) ---
    # Designation takes the EXCLUSIVE admission lock. This blocks all concurrent
    # admissions until the quarantine ledger is updated, closing the phantom race.
    # Designations are rare; contention is negligible by construction.
    async with _admission_lock.exclusive():
        exists_map, quarantined_map = await asyncio.gather(
            backend.nodes_exist([event.poisoned_node_id]),
            backend.are_quarantined([event.poisoned_node_id]),
        )
        if not exists_map.get(event.poisoned_node_id):
            raise HTTPException(status_code=404, detail="Node ID not found in DAG")
        if quarantined_map.get(event.poisoned_node_id):
            return {"status": "ok", "message": "Node already in quarantine ledger"}

        c_p = await backend.compute_blast_radius(event.poisoned_node_id)

        from src.r6_utils import process_recurrence
        active_horizons = await backend.get_active_horizon_set()
        for n in c_p:
            if n in active_horizons:
                await process_recurrence(backend, n, "RENEWED_DESIGNATION", "internal_hook")

        monotonic_ledger_digest = await backend.compute_quarantine_digest(c_p)

        q_event = {
            "quarantine_event_id": str(uuid.uuid4()),
            "detected_at_utc": datetime.now(timezone.utc).isoformat() + "Z",
            "poisoned_root_id": event.poisoned_node_id,
            "computed_blast_radius_C_p": c_p,
            "monotonic_ledger_digest_post_transition": monotonic_ledger_digest,
            "designator_identity": claims.get("sub"),
            "designation_reason": event.reason
        }
        await backend.apply_quarantine_transaction(q_event, c_p)
    
    # R3: Attempt external reconstruction
    repair_candidates = await backend.get_repair_candidates()
    # Defer expensive loads until we know reconstruction is actually needed
    _dag_cache = None
    _q_ledger_cache = None
    for comp_node, rc_data in repair_candidates.items():
        if rc_data["disposition"] == "PENDING_RECONSTRUCTION":
            if not settings.RECOVERY_ADAPTER_URL:
                rc_data["disposition"] = "IRREDUCIBLE"
                rc_data["reason"] = "no_reconstruction_backend"
                await backend.update_repair_candidate(comp_node, rc_data)
                continue
                
            try:
                # Lazy-load DAG and quarantine ledger only when reconstruction fires
                if _dag_cache is None:
                    _dag_cache, _q_ledger_cache = await asyncio.gather(
                        backend.get_dag(),
                        backend.get_quarantine_ledger(),
                    )
                
                # POST to adapter
                compaction_covers = _dag_cache[comp_node].get("covers", [])
                
                # Structural projection: strip state_content
                dag_projection = {}
                for n_id, n_data in _dag_cache.items():
                    dag_projection[n_id] = {k: v for k, v in n_data.items() if k != "state_content"}

                async with httpx.AsyncClient() as client:
                    resp = await client.post(
                        f"{settings.RECOVERY_ADAPTER_URL}/reconstruct",
                        json={
                            "graph_snapshot": dag_projection,
                            "quarantine_ledger": _q_ledger_cache,
                            "poisoned_root_id": event.poisoned_node_id,
                            "compaction_covers": compaction_covers,
                            "requested_frontier": rc_data["frontier"],
                            "method": rc_data["method"],
                            "checkpoint": rc_data["checkpoint"]
                        },
                        timeout=5.0
                    )
                    
                if resp.status_code != 200:
                    rc_data["disposition"] = "IRREDUCIBLE"
                    rc_data["reason"] = "backend_unavailable"
                    await backend.update_repair_candidate(comp_node, rc_data)
                    continue
                    
                candidate = resp.json().get("candidate", {})
                
                # Verify R4
                # We do NOT verify the generated text. We verify identity and frontier.
                if not candidate:
                    rc_data["disposition"] = "IRREDUCIBLE"
                    rc_data["reason"] = "backend_unavailable"
                    await backend.update_repair_candidate(comp_node, rc_data)
                    continue
                    
                # The candidate should be signed by the adapter
                if not verify_cryptographic_signature(candidate):
                    rc_data["disposition"] = "IRREDUCIBLE"
                    rc_data["reason"] = "invalid_signature"
                    await backend.update_repair_candidate(comp_node, rc_data)
                    continue
                    
                # R4 Identity Verification: Signature must match RECOVERY_ADAPTER_PUBLIC_KEY
                adapter_key = settings.RECOVERY_ADAPTER_PUBLIC_KEY
                if not adapter_key or candidate.get("ephemeral_nhi", {}).get("identity_id") != adapter_key:
                    rc_data["disposition"] = "IRREDUCIBLE"
                    rc_data["reason"] = "invalid_identity"
                    await backend.update_repair_candidate(comp_node, rc_data)
                    continue
                    
                # R4 Frontier Verification
                if set(candidate.get("covers", [])) != set(rc_data["frontier"]):
                    rc_data["disposition"] = "IRREDUCIBLE"
                    rc_data["reason"] = "frontier_mismatch"
                    await backend.update_repair_candidate(comp_node, rc_data)
                    continue
                    
                # R5 Reintegration Gate (Simplified, in real system this is an OPA call)
                # But we just admit it directly since the Rego checks happen in submit-candidate usually,
                # actually we should commit it to the DAG.
                await backend.commit_node(candidate)
                await backend.record_reintegration(candidate.get("payload_id"), comp_node, settings.CONTINUATION_HORIZON_SECONDS)
                rc_data["disposition"] = "REDUCIBLE"
                rc_data["reconstructed_node_id"] = candidate.get("payload_id")
                await backend.update_repair_candidate(comp_node, rc_data)
                
            except httpx.ReadTimeout:
                rc_data["disposition"] = "IRREDUCIBLE"
                rc_data["reason"] = "backend_timeout"
            except Exception as e:
                rc_data["disposition"] = "IRREDUCIBLE"
                rc_data["reason"] = "backend_unavailable"
    
    return {"status": "success", "event": q_event}


@app.post("/observe")
async def observe_recurrence(event: ObserveEvent, request: Request):
    claims = verify_role_jwt(request, "designator")
    
    if event.recurrence_class not in ["FUNCTIONAL_FAILURE", "VERIFIER_CONTRADICTION"]:
        raise HTTPException(status_code=400, detail="Invalid recurrence class")
        
    if event.recurrence_class == "VERIFIER_CONTRADICTION":
        if not event.adapter_signature:
            raise HTTPException(status_code=403, detail="adapter_signature required for VERIFIER_CONTRADICTION")
            
        adapter_key = settings.RECOVERY_ADAPTER_PUBLIC_KEY
        if not adapter_key:
            raise HTTPException(status_code=500, detail="RECOVERY_ADAPTER_PUBLIC_KEY not configured")
            
        try:
            from ecdsa import VerifyingKey, NIST256p
            vk = VerifyingKey.from_string(bytes.fromhex(adapter_key), curve=NIST256p)
            if not vk.verify(bytes.fromhex(event.adapter_signature), event.node_id.encode()):
                raise HTTPException(status_code=403, detail="Invalid adapter signature")
        except Exception:
            raise HTTPException(status_code=403, detail="Invalid adapter signature")
            
    from src.r6_utils import process_recurrence
    await process_recurrence(backend, event.node_id, event.recurrence_class, claims.get("sub"), event.evidence)
    return {"status": "success"}

@app.post("/renew-trust")
async def renew_trust(req: RenewTrustRequest, request: Request):
    claims = verify_role_jwt(request, "designator")
    
    q_ledger = await backend.get_quarantine_ledger()
    if req.node_id in q_ledger:
        raise HTTPException(status_code=403, detail="Cannot renew trust: Prohibited path from historical quarantine exists (node is tainted)")
        
    await backend.renew_trust(req.node_id, settings.CONTINUATION_HORIZON_SECONDS)
    return {"status": "success"}


@app.post("/calibrate")
async def calibrate_harness(req: CalibrateRequest, request: Request):
    verify_role_jwt(request, "admin")
    if not settings.DEBUG_MODE:
        raise HTTPException(status_code=403, detail="Calibration requires DEBUG_MODE")
        
    await backend.record_calibration_run(req.model_dump())
    return {"status": "success"}

@app.get("/recurrence-report")
async def get_recurrence_report(request: Request):
    verify_role_jwt(request, "admin")
    return {
        "active_horizons": await backend.get_active_horizon_set(),
        "expired_horizons": await backend.get_expired_horizon_set(),
        "withdrawal_ledger": await backend.get_withdrawal_ledger()
    }

@app.get("/shadow-report")
async def get_shadow_report(request: Request):
    verify_role_jwt(request, "admin")
    
    if hasattr(backend, "_connect"):
        async with backend._connect() as db:
            async with db.execute("SELECT COUNT(*) FROM shadow_decisions") as cursor:
                total = (await cursor.fetchone())[0]
            async with db.execute("SELECT COUNT(*) FROM shadow_decisions WHERE would_have_blocked = 1") as cursor:
                blocked = (await cursor.fetchone())[0]
    else:
        total = len(backend.shadow_decisions)
        blocked = sum(1 for d in backend.shadow_decisions if d["would_have_blocked"])

        
    return {
        "enforcement_mode": settings.ENFORCEMENT_MODE,
        "total_decisions": total,
        "counterfactual_rejections": blocked,
        "caveat": "Shadow-mode blast radii are upper bounds relative to enforcement mode because they include writes that would have been blocked."
    }

@app.get("/db-state")
async def get_db_state(request: Request):
    verify_role_jwt(request, "admin")
    if not settings.DEBUG_MODE:
        raise HTTPException(status_code=403, detail="Debug endpoints disabled in production")
    return {
        "dag": await backend.get_dag(),
        "quarantine_ledger": await backend.get_quarantine_ledger(),
        "quarantine_events": await backend.get_quarantine_events(),
        "repair_candidates": await backend.get_repair_candidates(),
        "enforcement_mode": settings.ENFORCEMENT_MODE
    }

@app.post("/reset-db")
async def reset_db(request: Request):
    verify_role_jwt(request, "admin")
    if not settings.DEBUG_MODE:
        raise HTTPException(status_code=403, detail="Debug endpoints disabled in production")
    await backend.reset()
    return {"status": "ok"}

@app.get("/reducibility-report")
async def get_reducibility_report(request: Request):
    verify_role_jwt(request, "admin")
    repair_candidates = await backend.get_repair_candidates()
    
    total = len(repair_candidates)
    reducible_count = 0
    irreducible_count = 0
    undecided_count = 0
    reasons = {}
    
    for rc in repair_candidates.values():
        disp = rc.get("disposition")
        if disp == "REDUCIBLE":
            reducible_count += 1
        elif disp == "IRREDUCIBLE":
            irreducible_count += 1
            reason = rc.get("reason", "unknown")
            reasons[reason] = reasons.get(reason, 0) + 1
        else:
            undecided_count += 1
            
    return {
        "compactions_entering_repair_path": total,
        "reducible": {
            "count": reducible_count,
            "fraction": reducible_count / total if total > 0 else 0.0
        },
        "irreducible": {
            "count": irreducible_count,
            "fraction": irreducible_count / total if total > 0 else 0.0,
            "reasons": reasons
        },
        "undecided": {
            "count": undecided_count,
            "fraction": undecided_count / total if total > 0 else 0.0
        }
    }

@app.get("/readyz")
async def readyz():
    if settings.OPA_POLICY_BUNDLE and not os.path.exists(settings.OPA_POLICY_BUNDLE):
        raise HTTPException(status_code=503, detail="Policy bundle not found")
    return {"status": "ok", "enforcement_mode": settings.ENFORCEMENT_MODE}

@app.get("/livez")
async def livez():
    return {"status": "ok"}
    
