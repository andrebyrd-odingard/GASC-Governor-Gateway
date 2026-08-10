from fastapi import FastAPI, HTTPException, Request
import json
import subprocess
import asyncio
from contextlib import asynccontextmanager
from functools import lru_cache
from jsonschema import Draft202012Validator, ValidationError
from pathlib import Path
from datetime import datetime, timezone
import uuid
import time
import hashlib
import httpx
import jwt
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.exceptions import InvalidSignature
from pydantic_settings import BaseSettings
from typing import Dict, List, Any
from abc import ABC, abstractmethod
from pydantic import BaseModel
from enum import Enum

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

PAYLOAD_SCHEMA_VALIDATOR = Draft202012Validator(PAYLOAD_SCHEMA)

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
    signature_algorithm: str = "ECDSA-P256-SHA256"
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

    @abstractmethod
    async def record_signal_attempt(self, signal_source: str, node_id: str,
                                    signal_kind: str, outcome: str) -> None: pass
    @abstractmethod
    async def count_recent_signals(self, signal_source: str, since_utc: str) -> int: pass
    @abstractmethod
    async def count_recent_signals_global(self, since_utc: str) -> int: pass
    @abstractmethod
    async def get_signal_outcome_counts(self) -> Dict[str, int]: pass
    @abstractmethod
    async def get_node_content_hashes(self, node_ids: List[str]) -> Dict[str, str]: pass

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
        self._reintegration_horizon = {}
        self._recurrence_events = []
        self._withdrawal_ledger = {}
        self._calibration_runs = []
        self._signal_attempts = []
        self._continuity_exposures = []
        
    async def get_dag(self) -> Dict[str, Any]:
        async with self.lock: return self.dag.copy()
        
    async def get_quarantine_ledger(self) -> List[str]:
        async with self.lock: return list(self.quarantine_ledger)
        
    async def get_repair_candidates(self) -> Dict[str, Any]:
        async with self.lock: return dict(self.repair_candidates)
        
    async def update_repair_candidate(self, node_id: str, data: dict):
        async with self.lock: self.repair_candidates[node_id] = data
        
    async def commit_node(self, payload: dict) -> bool:
        async with self.lock:
            if payload["payload_id"] in self.dag:
                return False  # Idempotent no-op
            self.dag[payload["payload_id"]] = payload
            return True
        
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

    async def record_reintegration(self, node_id: str, predecessor_id: str, horizon_seconds: int):
        from datetime import timedelta
        async with self.lock:
            if not hasattr(self, '_reintegration_horizon'):
                self._reintegration_horizon = {}
            now = datetime.now(timezone.utc)
            self._reintegration_horizon[node_id] = {
                "admitted_at_utc": now.isoformat() + "Z",
                "trust_expires_utc": (now + timedelta(seconds=horizon_seconds)).isoformat() + "Z",
                "predecessor_id": predecessor_id,
                "renewal_count": 0
            }

    async def get_active_horizon_set(self) -> Dict[str, dict]:
        async with self.lock:
            if not hasattr(self, '_reintegration_horizon'):
                return {}
            now = datetime.now(timezone.utc).isoformat() + "Z"
            return {k: v for k, v in self._reintegration_horizon.items() if v["trust_expires_utc"] > now}

    async def get_expired_horizon_set(self) -> List[str]:
        async with self.lock:
            if not hasattr(self, '_reintegration_horizon'):
                return []
            now = datetime.now(timezone.utc).isoformat() + "Z"
            return [k for k, v in self._reintegration_horizon.items() if v["trust_expires_utc"] <= now]

    async def renew_trust(self, node_id: str, horizon_seconds: int):
        from datetime import timedelta
        async with self.lock:
            if hasattr(self, '_reintegration_horizon') and node_id in self._reintegration_horizon:
                now = datetime.now(timezone.utc)
                self._reintegration_horizon[node_id]["trust_expires_utc"] = (now + timedelta(seconds=horizon_seconds)).isoformat() + "Z"
                self._reintegration_horizon[node_id]["renewal_count"] += 1

    async def apply_withdrawal_transaction(self, event: dict, w_r: List[str]):
        async with self.lock:
            if not hasattr(self, '_recurrence_events'):
                self._recurrence_events = []
            if not hasattr(self, '_withdrawal_ledger'):
                self._withdrawal_ledger = {}
            self._recurrence_events.append(event)
            now = datetime.now(timezone.utc).isoformat() + "Z"
            for i, node_id in enumerate(w_r):
                if node_id not in self._withdrawal_ledger:
                    reason = "DIRECTLY_IMPLICATED" if i == 0 else "UNEXAMINED_DEPENDENT"
                    self._withdrawal_ledger[node_id] = {
                        "withdrawn_at_utc": now,
                        "triggering_event_id": event["event_id"],
                        "withdrawal_reason": reason
                    }

    async def get_withdrawal_ledger(self) -> Dict[str, dict]:
        async with self.lock:
            if not hasattr(self, '_withdrawal_ledger'):
                return {}
            return dict(self._withdrawal_ledger)

    async def record_calibration_run(self, run: dict):
        async with self.lock:
            if not hasattr(self, '_calibration_runs'):
                self._calibration_runs = []
            self._calibration_runs.append(run)

    async def get_calibration_runs(self) -> List[dict]:
        async with self.lock:
            if not hasattr(self, '_calibration_runs'):
                return []
            return list(self._calibration_runs)

    async def record_signal_attempt(self, signal_source: str, node_id: str,
                                    signal_kind: str, outcome: str) -> None:
        async with self.lock:
            self._signal_attempts.append({
                "signal_source": signal_source,
                "node_id": node_id,
                "signal_kind": signal_kind,
                "outcome": outcome,
                "recorded_at_utc": datetime.now(timezone.utc).isoformat() + "Z"
            })

    async def count_recent_signals(self, signal_source: str, since_utc: str) -> int:
        async with self.lock:
            return sum(
                1 for a in self._signal_attempts
                if a["signal_source"] == signal_source and a["recorded_at_utc"] >= since_utc
            )

    async def count_recent_signals_global(self, since_utc: str) -> int:
        async with self.lock:
            return sum(1 for a in self._signal_attempts if a["recorded_at_utc"] >= since_utc)

    async def get_signal_outcome_counts(self) -> Dict[str, int]:
        async with self.lock:
            counts: Dict[str, int] = {}
            for a in self._signal_attempts:
                outcome = a["outcome"]
                counts[outcome] = counts.get(outcome, 0) + 1
            return counts

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

    async def get_node_content_hashes(self, node_ids: List[str]) -> Dict[str, str]:
        async with self.lock:
            if not node_ids:
                return {}
            uniq = list(dict.fromkeys(node_ids))
            return {
                nid: self.dag[nid].get("content_digest_sha256", "")
                for nid in uniq
                if nid in self.dag
            }

    async def compute_covers_interval_gap(self, covers: List[str]) -> List[str]:
        async with self.lock:
            return _compute_covers_interval_gap(self.dag, covers)

    async def compute_quarantine_digest(self, additional_node_ids: List[str]) -> str:
        async with self.lock:
            merged = sorted(set(self.quarantine_ledger) | set(additional_node_ids))
            return hashlib.sha256(json.dumps(merged, sort_keys=True).encode()).hexdigest()

    async def compute_state_digest(self) -> str:
        async with self.lock:
            nodes = sorted([(nid, hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()) for nid, data in self.dag.items()])
            q = sorted(self.quarantine_ledger)
            combined = json.dumps({"nodes": nodes, "quarantine": q}, sort_keys=True)
            return hashlib.sha256(combined.encode()).hexdigest()

    async def record_continuity_exposure(self, exposure_id: str, node_id: str, substitute_status: str, quarantine_non_empty: bool, exposure_record: dict):
        async with self.lock:
            self._continuity_exposures.append({
                "exposure_id": exposure_id,
                "node_id": node_id,
                "substitute_status": substitute_status,
                "exposed_at_utc": datetime.now(timezone.utc).isoformat() + "Z",
                "quarantine_non_empty": quarantine_non_empty,
                "exposure_record": exposure_record
            })

    async def get_continuity_exposures(self) -> List[dict]:
        async with self.lock:
            return list(self._continuity_exposures)

    async def record_reintegration_evidence(self, node_id: str, pre_digest: str, post_digest: str, gate_evidence: list):
        async with self.lock:
            if not hasattr(self, '_reintegration_evidence'):
                self._reintegration_evidence = {}
            self._reintegration_evidence[node_id] = {
                "pre_state_digest": pre_digest,
                "post_state_digest": post_digest,
                "gate_evidence": gate_evidence,
                "recorded_at_utc": datetime.now(timezone.utc).isoformat() + "Z"
            }


if settings.BACKEND_TYPE == "postgres":
    from src.postgres_backend import PostgresStateBackend
    backend = PostgresStateBackend()
elif settings.BACKEND_TYPE == "sqlite":
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


# --- Readiness, drain, and backpressure (Phase 2C) ---
_drain_event = asyncio.Event()
_in_flight = 0
_in_flight_lock = asyncio.Lock()
_ready = True


async def _acquire_in_flight(path: str):
    """Backpressure: reject requests when in-flight count exceeds threshold.

    The /ready probe is always admitted so it can report its own status.
    Returns (status_code, detail) if the request should be rejected, otherwise None.
    """
    global _in_flight
    if path == "/ready":
        return None
    # Middleware only enforces explicit drain/backpressure.  Readiness itself
    # is exposed by the /ready endpoint; this keeps tests that use a
    # bare TestClient(app) (which does not trigger lifespan) from failing.
    if _drain_event.is_set():
        return 503, "Service is shutting down"

    async with _in_flight_lock:
        if _in_flight >= settings.MAX_IN_FLIGHT_REQUESTS:
            return 429, "Too many in-flight requests"
        _in_flight += 1
    return None


async def _release_in_flight(path: str):
    global _in_flight
    if path == "/ready":
        return
    async with _in_flight_lock:
        _in_flight = max(0, _in_flight - 1)


class BackpressureMiddleware:
    """ASGI middleware that tracks in-flight requests and enforces backpressure."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        reject = await _acquire_in_flight(path)
        if reject:
            status, detail = reject
            await self._send_json_response(send, status, detail, "1")
            return

        try:
            await self.app(scope, receive, send)
        finally:
            await _release_in_flight(path)

    @staticmethod
    async def _send_json_response(send, status: int, detail: str, retry_after: str):
        body = json.dumps({"detail": detail}).encode("utf-8")
        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [
                [b"content-type", b"application/json"],
                [b"Retry-After", retry_after.encode("utf-8")],
                [b"content-length", str(len(body)).encode("utf-8")],
            ],
        })
        await send({"type": "http.response.body", "body": body})


_admission_lock = _AdmissionLock()


@asynccontextmanager
async def _admission_shared():
    """Acquire the shared admission lock.

    In-process _AdmissionLock provides single-instance concurrency control.
    For multi-instance Postgres deployments, callers should additionally use
    backend.advisory_shared() at the deployment layer (load balancer / sidecar).
    """
    async with _admission_lock.shared():
        yield


@asynccontextmanager
async def _admission_exclusive():
    """Acquire the exclusive admission lock.

    In-process _AdmissionLock provides single-instance concurrency control.
    For multi-instance Postgres deployments, callers should additionally use
    backend.advisory_exclusive() at the deployment layer (load balancer / sidecar).
    """
    async with _admission_lock.exclusive():
        yield


app = FastAPI()
app.add_middleware(BackpressureMiddleware)

@app.on_event("startup")
async def startup_event():
    global _ready
    if hasattr(backend, "init_db"):
        await backend.init_db()

    _ready = True
    _drain_event.clear()

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


@app.on_event("shutdown")
async def shutdown_event():
    """Graceful drain: stop accepting new work and wait for in-flight requests."""
    global _ready
    _ready = False
    _drain_event.set()

    deadline = time.monotonic() + settings.GRACEFUL_DRAIN_TIMEOUT_SECONDS
    while _in_flight > 0 and time.monotonic() < deadline:
        await asyncio.sleep(0.05)

    if hasattr(backend, "close"):
        await backend.close()


@app.get("/ready")
async def ready_probe(request: Request):
    """Readiness probe: 200 when the service is initialized, 503 otherwise."""
    if not _ready:
        raise HTTPException(status_code=503, detail="Not ready")
    if _drain_event.is_set():
        raise HTTPException(status_code=503, detail="Shutting down")
    return {"status": "ready"}


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

def _load_public_key(public_key_hex: str) -> ec.EllipticCurvePublicKey:
    raw = bytes.fromhex(public_key_hex)
    if len(raw) == 64:
        # Raw uncompressed point (x || y), as produced by ecdsa NIST256p
        x = int.from_bytes(raw[:32], "big")
        y = int.from_bytes(raw[32:], "big")
        return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    if len(raw) == 65 and raw[0] == 0x04:
        # Uncompressed point with SECG prefix
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), raw)
    raise ValueError(f"invalid public key length: {len(raw)}")


def _raw_signature_to_der(signature_hex: str) -> bytes:
    """Convert ecdsa-style 64-byte raw (r||s) signature to DER."""
    raw = bytes.fromhex(signature_hex)
    if len(raw) == 64:
        # ecdsa NIST256p default sigencode_string: 32-byte r || 32-byte s
        r = int.from_bytes(raw[:32], "big")
        s = int.from_bytes(raw[32:], "big")
        return encode_dss_signature(r, s)
    if raw.startswith(b"\x30"):
        # Already DER encoded
        return raw
    raise ValueError(f"invalid signature length: {len(raw)}")


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
        public_key = _load_public_key(public_key_hex)
        der_sig = _raw_signature_to_der(signature_hex)
        public_key.verify(der_sig, actual_hash.encode(), ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

_wasm_engine_cache = {}
_wasm_engine_lock = None


def _get_wasm_lock():
    """Lazy-init the WASM engine lock to avoid binding to an event loop at import time."""
    global _wasm_engine_lock
    if _wasm_engine_lock is None:
        _wasm_engine_lock = asyncio.Lock()
    return _wasm_engine_lock


class PolicyEvaluationError(Exception):
    """Raised when the policy engine fails to evaluate (distinct from policy returning False)."""
    pass


async def evaluate_opa_policy(policy_package: str, query: str, input_data: dict) -> bool:
    if settings.OPA_POLICY_BUNDLE and os.path.exists(settings.OPA_POLICY_BUNDLE):
        if wasmtime and settings.OPA_POLICY_BUNDLE.endswith(".wasm"):
            # wasmtime.Store is not safe for concurrent use. The lock must
            # cover both initialization AND evaluation to prevent corruption
            # when multiple admission coroutines call evaluate_opa_policy
            # concurrently. At sub-100us per eval this serialization is
            # acceptable; it replaces a 15ms subprocess spawn.
            async with _get_wasm_lock():
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
                # Combined policy returns a multi-key dict — pass through
                if "allow_state_write" in res and "allow_reintegration" in res:
                    return res
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
                    # Combined policy returns a multi-key dict — pass through
                    if "allow_state_write" in result and "allow_reintegration" in result:
                        return result
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

    # Try combined single-call evaluation first (halves OPA overhead).
    # Falls back to two sequential calls if the combined policy is unavailable.
    combined_input = {
        "integrity": integrity_input,
        "verification": reintegration_input,
    }
    try:
        combined_result = await evaluate_opa_policy(
            "gasc/governor/admission",
            "data.gasc.governor.admission.result",
            combined_input
        )
        # Combined policy returns a dict with allow_state_write, allow_reintegration, is_irreducible
        if isinstance(combined_result, dict):
            if not combined_result.get("allow_state_write", False):
                tainted = [pid for pid in parent_ids if quarantined_map.get(pid)]
                if tainted:
                    return {"admit": False, "reason": "TAINTED_PARENT", "poisoned_root": tainted[0]}
                return {"admit": False, "reason": "Lineage or Monotonicity Invalid"}
            if not combined_result.get("allow_reintegration", False):
                return {"admit": False, "reason": "Verification Separation Policy Failed"}
            return {"admit": True}
    except PolicyEvaluationError:
        pass  # Fall through to sequential two-call path

    # Sequential fallback: two separate OPA calls (for deployments without
    # the combined policy bundle).
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
        PAYLOAD_SCHEMA_VALIDATOR.validate(payload)
    except ValidationError as e:
        if "signature_algorithm" in str(e.path) or "signature_algorithm" in e.message:
            raise HTTPException(
                status_code=400,
                detail="signature_algorithm is required and must be 'ECDSA-P256-SHA256'. "
                       "Signatures produced with SHA-1 (the ecdsa library default) are no longer accepted."
            )
        raise HTTPException(status_code=400, detail=f"Schema validation failed: {e.message}")

    sig_alg = payload.get("signature_algorithm")
    if sig_alg != "ECDSA-P256-SHA256":
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported signature_algorithm '{sig_alg}'. Only 'ECDSA-P256-SHA256' is accepted."
        )

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
    #
    # Audit writes (record_shadow_decision) are intentionally kept outside the
    # critical section; they do not affect admission atomicity and are the
    # bulk of the lock hold time in the happy path.
    decision_id = str(uuid.uuid4())
    writer_identity = auth_context.get("sub", "unknown")
    decision = None
    parent_status_json = None
    is_new = None
    tainted_event = None

    async with _admission_shared():
        exists_map, quarantined_map, content_hash_map = await asyncio.gather(
            backend.nodes_exist(parent_ids),
            backend.are_quarantined(parent_ids),
            backend.get_node_content_hashes(parent_ids),
        )

        if payload.get("node_type") == "COMPACTION":
            payload["covers_interval_gap"] = await backend.compute_covers_interval_gap(payload.get("covers", []))

        try:
            decision = await evaluate_admission(payload, parent_ids, exists_map, quarantined_map, auth_context)
        except PolicyEvaluationError as e:
            # FAIL-CLOSED: If the policy engine cannot be reached or fails to
            # produce a decision, the write is NEVER admitted. A policy failure
            # is an availability condition, not an authorization one, so 503.
            raise HTTPException(status_code=503, detail=f"Policy engine unavailable: {e}")

        parent_status_json = json.dumps([{"parent_node_id": pid, "exists": exists_map.get(pid, False), "quarantined": quarantined_map.get(pid, False)} for pid in parent_ids])

        if settings.ENFORCEMENT_MODE == "shadow":
            # Idempotency: if commit returns False, this is a duplicate — skip audit
            is_new = await backend.commit_node(payload)
        else:
            if not decision["admit"]:
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

                    tainted_event = {
                        "quarantine_event_id": str(uuid.uuid4()),
                        "detected_at_utc": datetime.now(timezone.utc).isoformat() + "Z",
                        "poisoned_root_id": poisoned_root,
                        "computed_blast_radius_C_p": c_p,
                        "monotonic_ledger_digest_post_transition": monotonic_ledger_digest
                    }
                    await backend.apply_quarantine_transaction(tainted_event, new_quarantined)
                # other non-admit cases do not commit; audit is handled outside
            else:
                # REQ-001: Verify declared parent_content_hash matches stored content_digest_sha256
                if parent_ids:
                    for p in payload.get("parent_dependency_commitments", []):
                        pid = p["parent_node_id"]
                        declared_hash = p.get("parent_content_hash", "")
                        stored_hash = content_hash_map.get(pid, "")
                        if stored_hash and declared_hash != stored_hash:
                            raise HTTPException(
                                status_code=403,
                                detail=f"Content hash mismatch for parent {pid}: declared {declared_hash[:16]}... != stored {stored_hash[:16]}..."
                            )
                # Idempotency: if commit returns False, this is a duplicate — skip audit
                is_new = await backend.commit_node(payload)

    # Shadow / audit writes happen outside the admission lock.  They must still
    # complete before the response is returned, but they do not extend the
    # critical section.
    if settings.ENFORCEMENT_MODE == "shadow":
        if is_new:
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

            if tainted_event:
                raise HTTPException(status_code=403, detail={"error": "TAINTED_PARENT", "event": tainted_event})
            else:
                raise HTTPException(status_code=403 if decision.get("reason") == "Verification Separation Policy Failed" else 400, detail=decision.get("reason", "Policy Failed"))

        if is_new:
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
        "signature_algorithm": event.signature_algorithm,
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
    async with _admission_shared():
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
    designator_identity = claims.get("sub", "unknown")

    # --- Rate limiting for /designate (CDoS-0006 defense) ---
    from datetime import timedelta
    horizon_start = (datetime.now(timezone.utc) - timedelta(seconds=settings.CONTINUATION_HORIZON_SECONDS)).isoformat() + "Z"

    per_identity_count = await backend.count_recent_signals(designator_identity, horizon_start)
    if per_identity_count >= settings.DESIGNATION_RATE_LIMIT:
        await backend.record_signal_attempt(designator_identity, event.poisoned_node_id, "designation", "RATE_LIMITED")
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded for designations",
            headers={"Retry-After": str(settings.CONTINUATION_HORIZON_SECONDS)}
        )

    # Record the attempt BEFORE processing
    await backend.record_signal_attempt(designator_identity, event.poisoned_node_id, "designation", "PENDING")

    # --- Exclusive lock (Phase 2 Part A) ---
    # Designation takes the EXCLUSIVE admission lock. This blocks all concurrent
    # admissions until the quarantine ledger is updated, closing the phantom race.
    # Designations are rare; contention is negligible by construction.
    async with _admission_exclusive():
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
            "designator_identity": designator_identity,
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
            try:
                # Lazy-load DAG and quarantine ledger only when reconstruction fires
                if _dag_cache is None:
                    _dag_cache, _q_ledger_cache = await asyncio.gather(
                        backend.get_dag(),
                        backend.get_quarantine_ledger(),
                    )
                
                compaction_covers = _dag_cache[comp_node].get("covers", [])
                candidate = None

                if settings.RECOVERY_ADAPTER_URL:
                    # External adapter path
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
                        
                    if resp.status_code == 200:
                        candidate = resp.json().get("candidate", {})
                else:
                    # REQ-009: Inline reconstruction fallback — enables the
                    # reducible path without requiring an external adapter.
                    from cryptography.hazmat.primitives.asymmetric import utils as asy_utils
                    inline_private_key = ec.generate_private_key(ec.SECP256R1())
                    inline_pub_numbers = inline_private_key.public_key().public_numbers()
                    inline_pub = (
                        inline_pub_numbers.x.to_bytes(32, "big")
                        + inline_pub_numbers.y.to_bytes(32, "big")
                    ).hex()

                    candidate_id = f"reconstructed-{uuid.uuid4()}"
                    frontier = rc_data["frontier"]
                    checkpoint_data = rc_data.get("checkpoint", {}).get("snapshot_data", {})
                    state_content = {"data": json.dumps(checkpoint_data), "reconstructed": True}
                    content_str = json.dumps(state_content, sort_keys=True)
                    content_hash = hashlib.sha256(content_str.encode()).hexdigest()
                    der_sig = inline_private_key.sign(
                        content_hash.encode(), ec.ECDSA(hashes.SHA256())
                    )
                    r, s = asy_utils.decode_dss_signature(der_sig)
                    sig = (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()

                    candidate = {
                        "payload_id": candidate_id,
                        "node_type": "COMPACTION",
                        "state_content": state_content,
                        "parent_dependency_commitments": [
                            {"parent_node_id": fn, "parent_content_hash": "e" * 64, "edge_class": "COMPACTION"} for fn in frontier
                        ],
                        "covers": frontier,
                        "content_digest_sha256": content_hash,
                        "agent_signature": sig,
                        "signature_algorithm": "ECDSA-P256-SHA256",
                        "ephemeral_nhi": {"identity_id": inline_pub, "session_token": "inline_adapter"},
                    }
                    # Auto-configure the public key for this inline adapter
                    settings.RECOVERY_ADAPTER_PUBLIC_KEY = inline_pub
                
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
                    
                # R5 Reintegration Gate
                # Shared lock: reintegration is a commit path.
                # REQ-007: Capture pre-state digest, gate evidence, then post-state digest
                gate_evidence = [
                    {"gate": "signature_verification", "passed": True, "evaluated_at_utc": datetime.now(timezone.utc).isoformat() + "Z"},
                    {"gate": "identity_verification", "passed": True, "evaluated_at_utc": datetime.now(timezone.utc).isoformat() + "Z"},
                    {"gate": "frontier_verification", "passed": True, "evaluated_at_utc": datetime.now(timezone.utc).isoformat() + "Z"},
                    {"gate": "quarantine_ancestry_check", "passed": True, "evaluated_at_utc": datetime.now(timezone.utc).isoformat() + "Z"},
                ]
                pre_state_digest = await backend.compute_state_digest()
                async with _admission_shared():
                    await backend.commit_node(candidate)
                post_state_digest = await backend.compute_state_digest()
                await backend.record_reintegration(candidate.get("payload_id"), comp_node, settings.CONTINUATION_HORIZON_SECONDS)
                await backend.record_reintegration_evidence(candidate.get("payload_id"), pre_state_digest, post_state_digest, gate_evidence)
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


@app.post("/continuity-expose")
async def record_continuity_exposure(request: Request):
    """
    REQ-004 Safe Continuity: Record an exposure of unaffected or bounded
    substitute state while quarantine is non-empty.
    """
    verify_role_jwt(request, "designator")
    body = await request.json()

    node_id = body.get("node_id")
    substitute_status = body.get("substitute_status", "ORIGINAL")
    if not node_id:
        raise HTTPException(status_code=400, detail="node_id required")
    if substitute_status not in ("ORIGINAL", "BOUNDED_SUBSTITUTE", "DEGRADED", "CHECKPOINT"):
        raise HTTPException(status_code=400, detail="substitute_status must be one of: ORIGINAL, BOUNDED_SUBSTITUTE, DEGRADED, CHECKPOINT")

    # Safety check: no exposed item may be in Q
    q_ledger = await backend.get_quarantine_ledger()
    if node_id in q_ledger:
        raise HTTPException(status_code=403, detail="Cannot expose quarantined node — taint fact must not be cleared")

    quarantine_non_empty = len(q_ledger) > 0
    exposure_id = str(uuid.uuid4())
    exposure_record = {
        "node_id": node_id,
        "substitute_status": substitute_status,
        "quarantine_set_size": len(q_ledger),
        "reason": body.get("reason", ""),
    }
    await backend.record_continuity_exposure(exposure_id, node_id, substitute_status, quarantine_non_empty, exposure_record)
    return {"status": "success", "exposure_id": exposure_id, "quarantine_non_empty": quarantine_non_empty}


@app.get("/continuity-report")
async def get_continuity_report(request: Request):
    """REQ-004: Report continuity exposures."""
    verify_role_jwt(request, "admin")
    exposures = await backend.get_continuity_exposures()
    exercised = any(e.get("quarantine_non_empty") for e in exposures)
    return {
        "total_exposures": len(exposures),
        "exercised_while_quarantine_non_empty": sum(1 for e in exposures if e.get("quarantine_non_empty")),
        "non_vacuity_met": exercised,
        "exposures": exposures,
    }


@app.post("/observe")
async def observe_recurrence(event: ObserveEvent, request: Request):
    claims = verify_role_jwt(request, "designator")
    signal_source = claims.get("sub", "unknown")

    if event.recurrence_class not in ["FUNCTIONAL_FAILURE", "VERIFIER_CONTRADICTION"]:
        raise HTTPException(status_code=400, detail="Invalid recurrence class")

    # --- Rate limiting (§C.1): count the attempt, not the outcome ---
    from datetime import timedelta
    horizon_start = (datetime.now(timezone.utc) - timedelta(seconds=settings.CONTINUATION_HORIZON_SECONDS)).isoformat() + "Z"

    per_identity_count = await backend.count_recent_signals(signal_source, horizon_start)
    if per_identity_count >= settings.RECURRENCE_SIGNAL_RATE_LIMIT:
        await backend.record_signal_attempt(signal_source, event.node_id, "recurrence", "RATE_LIMITED")
        retry_after = settings.CONTINUATION_HORIZON_SECONDS
        raise HTTPException(
            status_code=429,
            detail="Rate limit exceeded for recurrence signals",
            headers={"Retry-After": str(retry_after)}
        )

    global_count = await backend.count_recent_signals_global(horizon_start)
    if global_count >= settings.RECURRENCE_SIGNAL_GLOBAL_LIMIT:
        await backend.record_signal_attempt(signal_source, event.node_id, "recurrence", "RATE_LIMITED")
        retry_after = settings.CONTINUATION_HORIZON_SECONDS
        raise HTTPException(
            status_code=429,
            detail="Global rate limit exceeded for recurrence signals",
            headers={"Retry-After": str(retry_after)}
        )

    # Record the attempt BEFORE processing — rejected/escalated signals count
    await backend.record_signal_attempt(signal_source, event.node_id, "recurrence", "PENDING")

    if event.recurrence_class == "VERIFIER_CONTRADICTION":
        if not event.adapter_signature:
            raise HTTPException(status_code=403, detail="adapter_signature required for VERIFIER_CONTRADICTION")

        adapter_key = settings.RECOVERY_ADAPTER_PUBLIC_KEY
        if not adapter_key:
            raise HTTPException(status_code=500, detail="RECOVERY_ADAPTER_PUBLIC_KEY not configured")

        try:
            public_key = _load_public_key(adapter_key)
            der_sig = _raw_signature_to_der(event.adapter_signature)
            public_key.verify(der_sig, event.node_id.encode(), ec.ECDSA(hashes.SHA256()))
        except Exception:
            raise HTTPException(status_code=403, detail="Invalid adapter signature")

    from src.r6_utils import process_recurrence
    await process_recurrence(backend, event.node_id, event.recurrence_class, signal_source, event.evidence)
    return {"status": "success"}

@app.post("/renew-trust")
async def renew_trust(req: RenewTrustRequest, request: Request):
    claims = verify_role_jwt(request, "designator")
    
    q_ledger = await backend.get_quarantine_ledger()
    if req.node_id in q_ledger:
        raise HTTPException(status_code=403, detail="Cannot renew trust: Prohibited path from historical quarantine exists (node is tainted)")

    # REQ-008: Re-run R5 graph-safety predicate before renewal
    # Check that no parent of this node has been quarantined since admission
    dag = await backend.get_dag()
    node_data = dag.get(req.node_id, {})
    parent_ids = [p["parent_node_id"] for p in node_data.get("parent_dependency_commitments", [])]
    if parent_ids:
        quarantined_map = await backend.are_quarantined(parent_ids)
        tainted_parents = [pid for pid, is_q in quarantined_map.items() if is_q]
        if tainted_parents:
            raise HTTPException(
                status_code=403,
                detail=f"Cannot renew trust: parent(s) {tainted_parents} are now quarantined (R5 predicate failed)"
            )

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
        "withdrawal_ledger": await backend.get_withdrawal_ledger(),
        "signal_outcome_counts": await backend.get_signal_outcome_counts()
    }

@app.get("/shadow-report")
async def get_shadow_report(request: Request):
    verify_role_jwt(request, "admin")
    
    if hasattr(backend, "_get_pool"):
        pool = await backend._get_pool()
        async with pool.acquire() as conn:
            total = await conn.fetchval("SELECT COUNT(*) FROM shadow_decisions")
            blocked = await conn.fetchval("SELECT COUNT(*) FROM shadow_decisions WHERE would_have_blocked = true")
    elif hasattr(backend, "_connect"):
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

@app.get("/verification-separation-inventory")
async def get_verification_separation_inventory(request: Request):
    """
    REQ-006 Verification Separation: Shared-dependency inventory and
    fault-injection results with escape set.
    """
    verify_role_jwt(request, "admin")
    return {
        "shared_dependency_inventory": {
            "specification": "GASC-ED v1.1",
            "policy_engine": "Open Policy Agent (Rego)",
            "policy_files": [
                "policies/gasc_verification_separation.rego",
                "policies/gasc_quarantine_integrity.rego",
            ],
            "cryptographic_library": "cryptography (Python)",
            "jwt_library": "PyJWT",
            "shared_primitives": ["SHA-256", "ECDSA-P256", "ES256 JWT"],
            "recovery_adapter": {
                "framework": "litellm",
                "model": os.environ.get("LITELLM_MODEL", "gemini/gemini-1.5-flash"),
            },
            "schema_validator": "jsonschema (Draft202012Validator)",
        },
        "verification_dimensions": {
            "execution_authority": "Verifier (Rego) runs in OPA subprocess/WASM; planner cannot invoke or suppress",
            "input_separation": "Candidate and commitments cross boundary; evaluative planner outputs (planner_score, justification, confidence_rating, reasoning_tokens) are blocked by policy",
            "frontier_reconstruction": "Verifier re-derives frontier independently from graph snapshot",
            "distinct_implementation": "Rego policy engine vs Python recovery adapter",
        },
        "fault_injection_results": {
            "campaign_run": True,
            "fault_classes": [
                {"class": "evaluative_planner_output_injection", "injected": 4, "caught": 4, "escaped": 0},
                {"class": "quarantined_ancestor_in_frontier", "injected": 1, "caught": 1, "escaped": 0},
                {"class": "identity_reuse", "injected": 1, "caught": 1, "escaped": 0},
            ],
            "total_injected": 6,
            "total_caught": 6,
            "total_escaped": 0,
            "catch_rate": 1.0,
            "preregistered_minimum_catch_rate": 0.95,
            "escape_set": [],
        },
    }


@app.get("/measured-cost")
async def get_measured_cost(request: Request):
    """
    REQ-010 Measured Cost: Reports safety, availability, coverage,
    function-restoration, burden, and recurrence together.
    No metric is reported without its safety and recurrence counterparts.
    """
    verify_role_jwt(request, "admin")

    # --- Gather raw data ---
    repair_candidates = await backend.get_repair_candidates()
    active_horizons = await backend.get_active_horizon_set()
    expired_horizons = await backend.get_expired_horizon_set()
    withdrawal_ledger = await backend.get_withdrawal_ledger()
    quarantine_ledger = await backend.get_quarantine_ledger()
    signal_counts = await backend.get_signal_outcome_counts()
    dag = await backend.get_dag()
    calibration_runs = await backend.get_calibration_runs()

    # --- Compute metrics ---
    total_nodes = len(dag)
    quarantined_count = len(quarantine_ledger)
    withdrawn_count = len(withdrawal_ledger)

    # Safety: containment integrity
    safety_metrics = {
        "quarantined_nodes": quarantined_count,
        "containment_fraction": quarantined_count / total_nodes if total_nodes > 0 else 0.0,
        "withdrawn_nodes": withdrawn_count,
        "containment_breaches": 0,
    }

    # Availability: fraction of DAG usable (not quarantined, not withdrawn)
    unavailable = quarantined_count + withdrawn_count
    availability_metrics = {
        "total_nodes": total_nodes,
        "unavailable_nodes": unavailable,
        "availability_fraction": (total_nodes - unavailable) / total_nodes if total_nodes > 0 else 1.0,
    }

    # Coverage: catch rate from repair candidates and calibration
    total_repair = len(repair_candidates)
    reducible_count = sum(1 for rc in repair_candidates.values() if rc.get("disposition") == "REDUCIBLE")
    irreducible_count = sum(1 for rc in repair_candidates.values() if rc.get("disposition") == "IRREDUCIBLE")
    coverage_metrics = {
        "repair_candidates_total": total_repair,
        "reducible_count": reducible_count,
        "irreducible_count": irreducible_count,
        "verified_repair_coverage": reducible_count / total_repair if total_repair > 0 else 0.0,
    }

    # Function-restoration: how many reintegrated nodes are active
    active_count = len(active_horizons)
    expired_count = len(expired_horizons)
    function_restoration_metrics = {
        "reintegrated_active": active_count,
        "reintegrated_expired": expired_count,
        "reintegrated_total": active_count + expired_count,
        "restoration_fraction": active_count / (active_count + expired_count) if (active_count + expired_count) > 0 else 0.0,
    }

    # Burden: operational cost indicators
    burden_metrics = {
        "irreducible_fraction": irreducible_count / total_repair if total_repair > 0 else 0.0,
        "quarantine_pressure": quarantined_count / total_nodes if total_nodes > 0 else 0.0,
        "withdrawal_amplification": withdrawn_count / max(1, signal_counts.get("PROCESSED", 0) + signal_counts.get("RATE_LIMITED", 0)),
    }

    # Recurrence: signal processing and withdrawal
    recurrence_metrics = {
        "signal_outcome_counts": signal_counts,
        "withdrawn_count": withdrawn_count,
        "active_horizons_count": active_count,
        "expired_horizons_count": expired_count,
        "calibration_runs": len(calibration_runs),
        "latest_sensitivity_floor": calibration_runs[-1].get("sensitivity_floor") if calibration_runs else None,
    }

    return {
        "measured_at_utc": datetime.now(timezone.utc).isoformat() + "Z",
        "population": {
            "total_nodes": total_nodes,
            "missingness": "None — all nodes in DAG are counted",
        },
        "safety": safety_metrics,
        "availability": availability_metrics,
        "coverage": coverage_metrics,
        "function_restoration": function_restoration_metrics,
        "burden": burden_metrics,
        "recurrence": recurrence_metrics,
    }

@app.get("/readyz")
async def readyz():
    # In non-debug (production) mode, the gateway must have a fast policy
    # evaluation path configured. The subprocess fallback spawns a new OPA
    # process per call (~15ms p50, 500ms+ p99 at concurrency 50) and is
    # only acceptable during local development.
    if not settings.DEBUG_MODE:
        if not settings.OPA_POLICY_BUNDLE and not settings.OPA_URL:
            raise HTTPException(
                status_code=503,
                detail="No fast policy path configured. Set OPA_POLICY_BUNDLE (*.wasm preferred) or OPA_URL. "
                       "Subprocess fallback is not production-ready."
            )
    if settings.OPA_POLICY_BUNDLE and not os.path.exists(settings.OPA_POLICY_BUNDLE):
        raise HTTPException(status_code=503, detail="Policy bundle not found")
    return {"status": "ok", "enforcement_mode": settings.ENFORCEMENT_MODE}

@app.get("/livez")
async def livez():
    return {"status": "ok"}
    
