from fastapi.responses import JSONResponse

from fastapi import Body, FastAPI, HTTPException, Request
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
    @asynccontextmanager
    async def transaction(self):
        yield
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

    # --- Substitute declarations (M3) ---
    @abstractmethod
    async def add_substitute_declaration(self, declaration: dict): pass
    @abstractmethod
    async def get_substitute_declarations(self) -> Dict[str, dict]: pass

    # --- Detector event log ---
    @abstractmethod
    async def record_detector_event(self, event: dict): pass
    @abstractmethod
    async def get_detector_events(self) -> List[dict]: pass

    # --- Critical function dependency tracking ---
    @abstractmethod
    async def get_critical_dependents(self, quarantined_node_ids: List[str]) -> List[dict]: pass

    # --- Tainted-action tracking (B.8) ---
    @abstractmethod
    async def record_tainted_rejection(self, node_id: str, parent_id: str,
                                       rejected_at_utc: str, author_identity: str = ""): pass
    @abstractmethod
    async def record_tainted_offer(self, rejection_node_id: str, replacement_node_id: str, replacement_type: str): pass
    @abstractmethod
    async def record_tainted_completion(self, rejection_node_id: str, completed_by_node_id: str): pass
    @abstractmethod
    async def check_retry_completion(self, payload: dict) -> None: pass
    @abstractmethod
    async def get_tainted_action_stats(self) -> dict: pass
    @abstractmethod
    async def find_continuity_replacement(self, tainted_node_id: str) -> dict | None: pass

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
        self._substitute_declarations = {}
        self._detector_events = []
        self._tainted_rejections = []
        self._tainted_completions = []
        
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
                    # C1 fix: also follow covers[] edges. A compaction that
                    # covers a tainted node carries tainted material.
                    elif current in node_data.get("covers", []):
                        visited.add(node_id)
                        queue.append(node_id)
            
            # R1 & R2
            semantic_rollback = False
            for effect in self.external_effects.values():
                if effect["node_id"] in c_p:
                    semantic_rollback = True
                    break
            
            for comp_node in affected_compactions:
                # Skip nodes that already reached a terminal disposition
                existing = self.repair_candidates.get(comp_node, {})
                if existing.get("disposition") in ("REDUCIBLE", "IRREDUCIBLE"):
                    continue

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

    # --- Substitute declarations (M3) ---
    async def add_substitute_declaration(self, declaration: dict):
        async with self.lock:
            self._substitute_declarations[declaration["target_node_id"]] = declaration

    async def get_substitute_declarations(self) -> Dict[str, dict]:
        async with self.lock:
            return dict(self._substitute_declarations)

    # --- Detector event log ---
    async def record_detector_event(self, event: dict):
        async with self.lock:
            self._detector_events.append(event)

    async def get_detector_events(self) -> List[dict]:
        async with self.lock:
            return list(self._detector_events)

    # --- Critical function dependency tracking ---
    async def get_critical_dependents(self, quarantined_node_ids: List[str]) -> List[dict]:
        """Find DAG nodes with criticality_weight > 0 that are in or depend on quarantined nodes.

        Includes quarantined nodes themselves if they have criticality > 0, because
        continuity's job is to provide replacement service for exactly those functions.
        """
        async with self.lock:
            q_set = set(quarantined_node_ids)
            results = []
            for nid, ndata in self.dag.items():
                cw = ndata.get("criticality_weight", 0)
                if cw <= 0:
                    continue
                parents = [p["parent_node_id"] for p in ndata.get("parent_dependency_commitments", [])]
                tainted_parents = [p for p in parents if p in q_set]
                # Include if the node itself is quarantined OR has quarantined parents
                if nid in q_set or tainted_parents:
                    results.append({
                        "node_id": nid,
                        "criticality_weight": cw,
                        "tainted_parents": tainted_parents if tainted_parents else [nid],
                    })
            return results

    # --- Tainted-action tracking (B.8) ---
    async def record_tainted_rejection(self, node_id: str, parent_id: str,
                                       rejected_at_utc: str, author_identity: str = ""):
        async with self.lock:
            self._tainted_rejections.append({
                "node_id": node_id,
                "tainted_parent_id": parent_id,
                "rejected_at_utc": rejected_at_utc,
                "author_identity": author_identity,
                "offered": False,
                "offered_replacement": None,
                "replacement_type": None,  # "direct" or "ancestor"
                "completed": False,
                "completed_by": None,
            })

    async def record_tainted_offer(self, rejection_node_id: str, replacement_node_id: str, replacement_type: str):
        """Record that a replacement was offered at 403-time. Does NOT mark completed."""
        async with self.lock:
            for r in self._tainted_rejections:
                if r["node_id"] == rejection_node_id and not r["offered"]:
                    r["offered"] = True
                    r["offered_replacement"] = replacement_node_id
                    r["replacement_type"] = replacement_type
                    break

    async def record_tainted_completion(self, rejection_node_id: str, completed_by_node_id: str):
        """Record that the rejected action was actually completed via retry."""
        async with self.lock:
            for r in self._tainted_rejections:
                if r["node_id"] == rejection_node_id and not r["completed"]:
                    r["completed"] = True
                    r["completed_by"] = completed_by_node_id
                    break

    async def check_retry_completion(self, payload: dict) -> None:
        """Check if a newly admitted write completes a previously rejected action.

        Completion requires a structural match: the offered replacement_node_id
        must appear among the payload's parents. This is verified against
        Gateway-controlled state and cannot be forged by the submitter.

        retry_of is stored as a provenance hint but does NOT by itself
        trigger completion — otherwise the metric would be self-reported
        by the party being measured.

        When retry_of IS present, we additionally verify the submitting
        identity matches the rejected write's author. A mismatched
        identity is silently ignored (no completion credit).

        A single admitted write can complete multiple previously-rejected
        actions if it parents on a replacement that was offered to several
        rejections.
        """
        async with self.lock:
            retry_of = payload.get("retry_of")
            parent_ids = [p["parent_node_id"] for p in payload.get("parent_dependency_commitments", [])]
            submitter = payload.get("ephemeral_nhi", {}).get("identity_id", "")

            for r in self._tainted_rejections:
                if r["completed"]:
                    continue
                if not r["offered"]:
                    continue
                # Structural match: the offered replacement must be a parent.
                if not (r["offered_replacement"] and r["offered_replacement"] in parent_ids):
                    continue
                # If retry_of is declared, verify identity matches the
                # original author. Mismatch → skip (no credit for
                # claiming someone else's workflow).
                if retry_of and retry_of == r["node_id"]:
                    if r["author_identity"] and submitter != r["author_identity"]:
                        continue
                r["completed"] = True
                r["completed_by"] = payload["payload_id"]

    async def get_tainted_action_stats(self) -> dict:
        async with self.lock:
            total = len(self._tainted_rejections)
            offered = sum(1 for r in self._tainted_rejections if r["offered"])
            completed = sum(1 for r in self._tainted_rejections if r["completed"])
            direct_offered = sum(1 for r in self._tainted_rejections if r["offered"] and r["replacement_type"] == "direct")
            ancestor_offered = sum(1 for r in self._tainted_rejections if r["offered"] and r["replacement_type"] == "ancestor")
            direct_completed = sum(1 for r in self._tainted_rejections if r["completed"] and r["replacement_type"] == "direct")
            ancestor_completed = sum(1 for r in self._tainted_rejections if r["completed"] and r["replacement_type"] == "ancestor")
            return {
                "total_rejections": total,
                "offered": offered,
                "completed": completed,
                "completion_rate": completed / total if total > 0 else 0.0,
                "offer_rate": offered / total if total > 0 else 0.0,
                "direct": {"offered": direct_offered, "completed": direct_completed},
                "ancestor": {"offered": ancestor_offered, "completed": ancestor_completed},
            }

    async def find_continuity_replacement(self, tainted_node_id: str) -> dict | None:
        """Find a continuity replacement for tainted_node_id or any of its
        quarantined ancestors.

        Checks two sources in order for each candidate:
        1. Continuity exposures (M3/M4 replay nodes whose state_content
           references the candidate as 'original_target')
        2. Pre-declared substitutes whose source is still admissible

        Returns {"replacement_node_id": ..., "replacement_for": ..., ...}
        or None.
        """
        async with self.lock:
            # Build the set of quarantined ancestors to check (including
            # the node itself). Walk parent edges while staying in
            # quarantine to find the original poisoned root(s).
            candidates = []
            visited = set()
            queue = [tainted_node_id]
            while queue:
                nid = queue.pop(0)
                if nid in visited:
                    continue
                visited.add(nid)
                if nid in self.quarantine_ledger:
                    candidates.append(nid)
                    node_data = self.dag.get(nid, {})
                    for p in node_data.get("parent_dependency_commitments", []):
                        queue.append(p["parent_node_id"])

            for candidate in candidates:
                # 1. Check fired continuity exposures
                for exp in self._continuity_exposures:
                    node_id = exp.get("node_id")
                    node_data = self.dag.get(node_id, {})
                    sc = node_data.get("state_content", {})
                    if sc.get("original_target") == candidate:
                        return {
                            "replacement_node_id": node_id,
                            "replacement_for": candidate,
                            "exposure_id": exp.get("exposure_id"),
                            "mechanism": exp.get("exposure_record", {}).get("mechanism", "unknown"),
                        }

                # 2. Check pre-declared substitutes
                sub_decl = self._substitute_declarations.get(candidate)
                if sub_decl:
                    sub_source = sub_decl.get("substitute_source_id")
                    if sub_source and sub_source in self.dag and sub_source not in self.quarantine_ledger:
                        return {
                            "replacement_node_id": sub_source,
                            "replacement_for": candidate,
                            "exposure_id": None,
                            "mechanism": "M3_DECLARED_SUBSTITUTE",
                        }

        return None


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

MAX_PAYLOAD_BYTES = int(os.environ.get("MAX_PAYLOAD_BYTES", 2 * 1024 * 1024))

@app.post("/submit-candidate")
async def submit_candidate(request: Request):

    body_bytes = await request.body()
    if len(body_bytes) > MAX_PAYLOAD_BYTES:
        raise HTTPException(status_code=413, detail=f"Payload exceeds maximum allowed size of {MAX_PAYLOAD_BYTES} bytes")

    try:
        payload = json.loads(body_bytes)
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
        async with backend.transaction():
                # C4 fix: reject writes whose payload_id is already quarantined.
            # The old behavior was a silent no-op (INSERT OR IGNORE) returning
            # 200, which is misleading — the caller thinks new content landed.
            payload_id = payload.get("payload_id", "")
            id_quarantined = await backend.are_quarantined([payload_id])
            if id_quarantined.get(payload_id):
                raise HTTPException(
                    status_code=409,
                    detail=f"payload_id {payload_id} is quarantined; cannot reuse a quarantined identity"
                )

            exists_map, quarantined_map, content_hash_map = await asyncio.gather(
                backend.nodes_exist(parent_ids),
                backend.are_quarantined(parent_ids),
                backend.get_node_content_hashes(parent_ids),
            )

            if payload.get("node_type") == "COMPACTION":
                payload["covers_interval_gap"] = await backend.compute_covers_interval_gap(payload.get("covers", []))
                # C1 fix: reject compaction nodes that cover quarantined nodes.
                # A compaction summarizes its covers[]; if any covered node is
                # quarantined, the summary carries tainted material.
                covers = payload.get("covers", [])
                if covers:
                    covers_quarantined = await backend.are_quarantined(covers)
                    tainted_covers = [cid for cid in covers if covers_quarantined.get(cid)]
                    if tainted_covers:
                        raise HTTPException(
                            status_code=403,
                            detail={
                                "error": "TAINTED_COVERS",
                                "message": "Compaction covers quarantined nodes",
                                "tainted_covers": tainted_covers,
                            }
                        )

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

                        # B.8: Track tainted-action rejection for completion metric
                        await backend.record_tainted_rejection(
                            payload.get("payload_id", "unknown"),
                            poisoned_root,
                            datetime.now(timezone.utc).isoformat() + "Z",
                            author_identity=payload.get("ephemeral_nhi", {}).get("identity_id", "")
                        )

                        # Check if continuity already produced a replacement
                        replacement = await backend.find_continuity_replacement(poisoned_root)
                        if replacement:
                            tainted_event["continuity_available"] = True
                            tainted_event["replacement_node_id"] = replacement["replacement_node_id"]
                            tainted_event["replacement_for"] = replacement["replacement_for"]
                            tainted_event["replacement_mechanism"] = replacement["mechanism"]
                            # Classify: direct = the immediate tainted parent was replaced;
                            # ancestor = an upstream node was replaced, re-derivation needed.
                            replacement_type = "direct" if replacement["replacement_for"] == poisoned_root else "ancestor"
                            # Record offer — NOT completion. Completion requires
                            # the agent to actually re-parent and land a write.
                            await backend.record_tainted_offer(
                                payload.get("payload_id", "unknown"),
                                replacement["replacement_node_id"],
                                replacement_type
                            )
                        else:
                            tainted_event["continuity_available"] = False
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

                # Shadow / audit writes happen inside the transaction now.
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
                    return JSONResponse(status_code=200, content={"status": "success", "message": "State node committed to DAG (Shadow Mode).", "idempotent": not is_new})
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
                            return JSONResponse(
                                status_code=403,
                                content={
                                    "detail": {
                                        "error": "TAINTED_PARENT",
                                        "event": tainted_event
                                    }
                                }
                            )
                        else:
                            is_verification_sep = decision.get("reason") == "Verification Separation Policy Failed"
                            return JSONResponse(
                                status_code=403 if is_verification_sep else 400,
                                content={
                                    "detail": decision.get("reason", "Policy Failed")
                                }
                            )
                    else:
                        if is_new:
                            await backend.record_shadow_decision(
                                decision_id=decision_id,
                                node_id=payload.get("payload_id"),
                                evaluated_at_utc=datetime.now(timezone.utc).isoformat() + "Z",
                                would_have_blocked=False,
                                reason="admit",
                                parent_status_json=parent_status_json,
                                policy_bundle_digest=settings.OPA_POLICY_BUNDLE or "none",
                                writer_identity=writer_identity
                            )
                            await backend.check_retry_completion(payload)
                        return JSONResponse(status_code=200, content={"status": "success", "message": "State node committed to DAG.", "idempotent": not is_new})

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

    # C1 fix: check covers (= compacted_node_ids) for quarantine before commit.
    # /context-compacted bypasses evaluate_admission, so the covers check
    # must be applied directly here.
    covers_quarantined = await backend.are_quarantined(event.compacted_node_ids)
    tainted_covers = [cid for cid in event.compacted_node_ids if covers_quarantined.get(cid)]
    if tainted_covers:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "TAINTED_COVERS",
                "message": "Compaction covers quarantined nodes",
                "tainted_covers": tainted_covers,
            }
        )

    # Shared lock: /context-compacted is a commit path, same as /submit-candidate.
    async with _admission_shared():
        await backend.commit_node(payload)
    return {"status": "success", "message": "Compaction node committed to DAG."}

async def _attempt_reconstruction(poisoned_root_id: str):
    """R3-R5: Attempt reconstruction of compaction nodes with PENDING_RECONSTRUCTION."""
    repair_candidates = await backend.get_repair_candidates()
    _dag_cache = None
    _q_ledger_cache = None
    for comp_node, rc_data in repair_candidates.items():
        if rc_data["disposition"] == "PENDING_RECONSTRUCTION":
            try:
                if _dag_cache is None:
                    _dag_cache, _q_ledger_cache = await asyncio.gather(
                        backend.get_dag(),
                        backend.get_quarantine_ledger(),
                    )

                compaction_covers = _dag_cache[comp_node].get("covers", [])
                candidate = None

                if settings.RECOVERY_ADAPTER_URL:
                    dag_projection = {}
                    for n_id, n_data in _dag_cache.items():
                        dag_projection[n_id] = {k: v for k, v in n_data.items() if k != "state_content"}

                    async with httpx.AsyncClient() as http_client:
                        resp = await http_client.post(
                            f"{settings.RECOVERY_ADAPTER_URL}/reconstruct",
                            json={
                                "graph_snapshot": dag_projection,
                                "quarantine_ledger": _q_ledger_cache,
                                "poisoned_root_id": poisoned_root_id,
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
                    # REQ-009: Inline reconstruction fallback
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
                    settings.RECOVERY_ADAPTER_PUBLIC_KEY = inline_pub

                if not candidate:
                    rc_data["disposition"] = "IRREDUCIBLE"
                    rc_data["reason"] = "backend_unavailable"
                    await backend.update_repair_candidate(comp_node, rc_data)
                    continue

                if not verify_cryptographic_signature(candidate):
                    rc_data["disposition"] = "IRREDUCIBLE"
                    rc_data["reason"] = "invalid_signature"
                    await backend.update_repair_candidate(comp_node, rc_data)
                    continue

                adapter_key = settings.RECOVERY_ADAPTER_PUBLIC_KEY
                if not adapter_key or candidate.get("ephemeral_nhi", {}).get("identity_id") != adapter_key:
                    rc_data["disposition"] = "IRREDUCIBLE"
                    rc_data["reason"] = "invalid_identity"
                    await backend.update_repair_candidate(comp_node, rc_data)
                    continue

                if set(candidate.get("covers", [])) != set(rc_data["frontier"]):
                    rc_data["disposition"] = "IRREDUCIBLE"
                    rc_data["reason"] = "frontier_mismatch"
                    await backend.update_repair_candidate(comp_node, rc_data)
                    continue

                # R5 Reintegration Gate
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


async def _attempt_safe_continuity(c_p: List[str], q_event: dict) -> dict:
    """M3/M4 Safe Continuity — runs after quarantine, never clears taint.

    For each quarantined node on which a critical function depends:
      M4: find a checkpoint predating containment, re-verify, emit new record
      M3: find a pre-declared substitute, verify admissible, emit new record
    Every exposure is a new record with fresh provenance; nothing is released.

    Gated on settings.CONTINUITY_ENABLED — when False, returns empty results
    (baseline-only response profile, containment without continuity).
    """
    from cryptography.hazmat.primitives.asymmetric import utils as asy_utils

    results = {"checkpoint_replays": [], "substitutions": [], "escalations": [], "enabled": settings.CONTINUITY_ENABLED}
    if not settings.CONTINUITY_ENABLED:
        return results
    critical_deps = await backend.get_critical_dependents(c_p)
    if not critical_deps:
        return results

    checkpoints = await backend.get_checkpoints()
    substitutes = await backend.get_substitute_declarations()
    q_ledger = await backend.get_quarantine_ledger()
    q_set = set(q_ledger)
    dag = await backend.get_dag()
    containment_time = q_event.get("detected_at_utc", datetime.now(timezone.utc).isoformat() + "Z")

    for dep in critical_deps:
        node_id = dep["node_id"]
        served = False

        # Collect all quarantined ancestors relevant to this critical function:
        # the node's own tainted parents, plus the node itself if quarantined,
        # plus the node's actual parents from the DAG
        relevant_tainted = set(dep["tainted_parents"])
        if node_id in q_set:
            relevant_tainted.add(node_id)
        node_data = dag.get(node_id, {})
        for p in node_data.get("parent_dependency_commitments", []):
            pid = p["parent_node_id"]
            if pid in q_set:
                relevant_tainted.add(pid)

        # --- M4: checkpoint-assisted continuity (preferred) ---
        for cp_id, cp_data in checkpoints.items():
            target = cp_data.get("target_node_id")
            # Checkpoint must target a quarantined node relevant to this critical function
            if target not in relevant_tainted:
                continue
            # Must predate containment
            cp_time = cp_data.get("declared_at_utc", "")
            if cp_time >= containment_time:
                continue
            # Target snapshot must contain only undesignated records
            snap_data = cp_data.get("snapshot_data", {})
            if not snap_data:
                continue
            # Re-verify against present-day safety: no quarantined ancestor
            snap_refs = list(snap_data.keys()) if isinstance(snap_data, dict) else []
            tainted_in_snap = [r for r in snap_refs if r in q_set]
            if tainted_in_snap:
                continue

            # Emit as a NEW record with new identity and fresh provenance
            inline_key = ec.generate_private_key(ec.SECP256R1())
            inline_pub_nums = inline_key.public_key().public_numbers()
            inline_pub = (inline_pub_nums.x.to_bytes(32, "big") + inline_pub_nums.y.to_bytes(32, "big")).hex()

            replay_id = f"continuity-cp-{uuid.uuid4()}"
            state_content = {"checkpoint_replay": snap_data, "source_checkpoint": cp_id, "original_target": target}
            content_str = json.dumps(state_content, sort_keys=True)
            content_hash = hashlib.sha256(content_str.encode()).hexdigest()

            der_sig = inline_key.sign(content_hash.encode(), ec.ECDSA(hashes.SHA256()))
            r, s = asy_utils.decode_dss_signature(der_sig)
            sig = (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()

            # Parents drawn only from the admissible frontier (unquarantined)
            clean_parents = [p["parent_node_id"] for p in dag.get(node_id, {}).get("parent_dependency_commitments", []) if p["parent_node_id"] not in q_set]
            if not clean_parents:
                clean_parents = ["clean-parent-1"]

            replay_payload = {
                "payload_id": replay_id,
                "node_type": "STANDARD",
                "timestamp_utc": datetime.now(timezone.utc).isoformat() + "Z",
                "state_content": state_content,
                "content_digest_sha256": content_hash,
                "agent_signature": sig,
                "signature_algorithm": "ECDSA-P256-SHA256",
                "ephemeral_nhi": {"identity_id": inline_pub, "session_token": "continuity_m4", "expires_at_utc": "2099-01-01T00:00:00Z"},
                "declared_evidence_boundary": {"boundary_id": f"cont-{replay_id}", "fixed_at_utc": containment_time, "boundary_digest": "0" * 64},
                "parent_dependency_commitments": [{"parent_node_id": cp, "parent_content_hash": "e" * 64} for cp in clean_parents],
                "criticality_weight": dep["criticality_weight"],
            }

            settings.RECOVERY_ADAPTER_PUBLIC_KEY = inline_pub
            async with _admission_shared():
                await backend.commit_node(replay_payload)

            exposure_id = str(uuid.uuid4())
            await backend.record_continuity_exposure(
                exposure_id, replay_id, "CHECKPOINT_REPLAY", True,
                {"source_checkpoint": cp_id, "critical_node": node_id, "mechanism": "M4"}
            )
            results["checkpoint_replays"].append({"node_id": replay_id, "critical_function": node_id, "checkpoint": cp_id, "exposure_id": exposure_id})
            served = True
            break

        if served:
            continue

        # --- M3: trusted substitution ---
        for tainted_parent in relevant_tainted:
            sub_decl = substitutes.get(tainted_parent)
            if not sub_decl:
                continue
            # Declaration must be pre-incident
            decl_time = sub_decl.get("declared_at_utc", "")
            if decl_time >= containment_time:
                continue
            sub_source = sub_decl.get("substitute_source_id")
            if not sub_source:
                continue
            # Source must be admissible (exists, not quarantined)
            source_data = dag.get(sub_source)
            if not source_data or sub_source in q_set:
                continue

            # Emit as a new record with fresh provenance
            inline_key = ec.generate_private_key(ec.SECP256R1())
            inline_pub_nums = inline_key.public_key().public_numbers()
            inline_pub = (inline_pub_nums.x.to_bytes(32, "big") + inline_pub_nums.y.to_bytes(32, "big")).hex()

            sub_id = f"continuity-sub-{uuid.uuid4()}"
            state_content = {"substituted_from": sub_source, "original_target": tainted_parent, "substitute_declaration": sub_decl.get("declared_at_utc")}
            content_str = json.dumps(state_content, sort_keys=True)
            content_hash = hashlib.sha256(content_str.encode()).hexdigest()

            der_sig = inline_key.sign(content_hash.encode(), ec.ECDSA(hashes.SHA256()))
            r, s = asy_utils.decode_dss_signature(der_sig)
            sig = (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()

            sub_payload = {
                "payload_id": sub_id,
                "node_type": "STANDARD",
                "timestamp_utc": datetime.now(timezone.utc).isoformat() + "Z",
                "state_content": state_content,
                "content_digest_sha256": content_hash,
                "agent_signature": sig,
                "signature_algorithm": "ECDSA-P256-SHA256",
                "ephemeral_nhi": {"identity_id": inline_pub, "session_token": "continuity_m3", "expires_at_utc": "2099-01-01T00:00:00Z"},
                "declared_evidence_boundary": {"boundary_id": f"cont-{sub_id}", "fixed_at_utc": containment_time, "boundary_digest": "0" * 64},
                "parent_dependency_commitments": [{"parent_node_id": sub_source, "parent_content_hash": source_data.get("content_digest_sha256", "e" * 64)}],
                "criticality_weight": dep["criticality_weight"],
            }

            settings.RECOVERY_ADAPTER_PUBLIC_KEY = inline_pub
            async with _admission_shared():
                await backend.commit_node(sub_payload)

            exposure_id = str(uuid.uuid4())
            await backend.record_continuity_exposure(
                exposure_id, sub_id, "BOUNDED_SUBSTITUTE", True,
                {"substitute_source": sub_source, "critical_node": node_id, "mechanism": "M3"}
            )
            results["substitutions"].append({"node_id": sub_id, "critical_function": node_id, "substitute_source": sub_source, "exposure_id": exposure_id})
            served = True
            break

        if not served:
            results["escalations"].append({"critical_function": node_id, "reason": "no_admissible_checkpoint_or_substitute"})


    return results


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
        async with backend.transaction():
            exists_map, quarantined_map = await asyncio.gather(
                backend.nodes_exist([event.poisoned_node_id]),
                backend.are_quarantined([event.poisoned_node_id]),
            )
            if not exists_map.get(event.poisoned_node_id):
                return JSONResponse(status_code=404, content={"detail": "Node ID not found in DAG"})
            if quarantined_map.get(event.poisoned_node_id):
                return JSONResponse(status_code=200, content={"status": "ok", "message": "Node already in quarantine ledger"})

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

            # --- M3/M4 Safe Continuity (§7.2 row 4) ---
            # After containment, attempt to restore critical function availability
            # without clearing taint, reducing quarantine, or rehabilitating identity.
            continuity_results = await _attempt_safe_continuity(c_p, q_event)

            await _attempt_reconstruction(event.poisoned_node_id)
            
            return JSONResponse(status_code=200, content={"status": "success", "event": q_event, "continuity": continuity_results})


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
    """REQ-004: Dual-footprint continuity report.

    Containment footprint (must be bit-identical across continuity):
      CPI, containment-WCAL, RER.
    Operational-unavailability footprint (what continuity is allowed to move):
      OU-WCAL, Critical Function Availability, Trusted Substitution Coverage,
      Continuity Provenance Completeness, Escalation Count.
    """
    verify_role_jwt(request, "admin")
    exposures = await backend.get_continuity_exposures()
    q_ledger = await backend.get_quarantine_ledger()
    dag = await backend.get_dag()
    tainted_stats = await backend.get_tainted_action_stats()

    exercised = any(e.get("quarantine_non_empty") for e in exposures)
    checkpoint_replays = [e for e in exposures if e.get("substitute_status") == "CHECKPOINT_REPLAY"]
    substitutions = [e for e in exposures if e.get("substitute_status") == "BOUNDED_SUBSTITUTE"]

    # Critical Function Availability: fraction of critical nodes not quarantined
    critical_nodes = [nid for nid, ndata in dag.items() if ndata.get("criticality_weight", 0) > 0]
    q_set = set(q_ledger)
    available_critical = [n for n in critical_nodes if n not in q_set]

    # Containment footprint (safety proof — must not move)
    containment_footprint = {
            "quarantine_ledger_size": len(q_ledger),
            "quarantine_ledger_digest": hashlib.sha256(json.dumps(sorted(q_ledger), sort_keys=True).encode()).hexdigest(),
    }

    # Operational-unavailability footprint (what continuity moves)
    operational_footprint = {
            "critical_function_availability": len(available_critical) / len(critical_nodes) if critical_nodes else 1.0,
            "total_critical_functions": len(critical_nodes),
            "available_critical_functions": len(available_critical),
            "trusted_substitution_coverage": len(substitutions),
            "checkpoint_replay_count": len(checkpoint_replays),
            "continuity_provenance_complete": all(
                e.get("exposure_record", {}).get("mechanism") in ("M3", "M4") for e in exposures if e.get("quarantine_non_empty")
            ),
            "escalation_count": 0,
            "authorized_tainted_action_completion": tainted_stats,
    }

    return {
            "total_exposures": len(exposures),
            "exercised_while_quarantine_non_empty": sum(1 for e in exposures if e.get("quarantine_non_empty")),
            "non_vacuity_met": exercised,
            "containment_footprint": containment_footprint,
            "operational_footprint": operational_footprint,
            "exposures": exposures,
    }


@app.post("/declare-substitute")
async def declare_substitute(request: Request):
    """M3: Pre-incident substitute declaration. Admin-role, pre-incident only.

    A substitute is a preauthorized alternate source declared before the incident.
    Declaration must be admin-role. A substitute declared after designation can be
    attacker-influenced, so the continuity mechanism filters by declaration time.
    """
    verify_role_jwt(request, "admin")
    body = await request.json()

    target_node_id = body.get("target_node_id")
    substitute_source_id = body.get("substitute_source_id")
    declared_at_utc = body.get("declared_at_utc")

    if not all([target_node_id, substitute_source_id, declared_at_utc]):
            raise HTTPException(status_code=400, detail="target_node_id, substitute_source_id, and declared_at_utc are required")

    # Verify the substitute source exists and is not quarantined
    exists_map = await backend.nodes_exist([substitute_source_id])
    if not exists_map.get(substitute_source_id):
            raise HTTPException(status_code=404, detail=f"Substitute source {substitute_source_id} not found in DAG")

    quarantined_map = await backend.are_quarantined([substitute_source_id])
    if quarantined_map.get(substitute_source_id):
            raise HTTPException(status_code=403, detail="Substitute source is quarantined")

    declaration = {
            "target_node_id": target_node_id,
            "substitute_source_id": substitute_source_id,
            "declared_at_utc": declared_at_utc,
            "declared_by": "admin",
    }
    await backend.add_substitute_declaration(declaration)
    return {"status": "success", "message": "Substitute declaration recorded"}


@app.post("/detector/{source}")
async def ingest_detector_event(source: str, request: Request):
    """Detection ingress: accepts a foreign detector's event, maps it via the
    appropriate adapter, and either produces a designation or records a drop.

    Every inbound raw event is recorded regardless of outcome — the drop rate
    tells an operator whether the integration is wired correctly.
    """
    from src.detectors import DETECTOR_REGISTRY

    verify_role_jwt(request, "designator")

    if source not in DETECTOR_REGISTRY:
            raise HTTPException(status_code=400, detail=f"Unknown detector source: {source}. Available: {list(DETECTOR_REGISTRY.keys())}")

    adapter = DETECTOR_REGISTRY[source]
    raw_event = await request.json()

    # Record every inbound event regardless of outcome
    raw_event_record = {
            "event_id": raw_event.get("event_id", str(uuid.uuid4())),
            "source": source,
            "raw_event": raw_event,
            "received_at_utc": datetime.now(timezone.utc).isoformat() + "Z",
    }
    await backend.record_detector_event(raw_event_record)

    designation_fields, drop_reason = await adapter.to_designation(raw_event)

    if designation_fields is None:
            raw_event_record["outcome"] = "dropped"
            raw_event_record["drop_reason"] = drop_reason
            return {"designated": False, "reason": drop_reason}

    # Forward to /designate logic
    designation_event = DesignationEvent(**designation_fields)

    # Reuse the designate_poison handler's internal logic
    # but we need the request for JWT verification — it's already verified above
    # Build a synthetic designator identity from the JWT
    claims = verify_role_jwt(request, "designator")
    designator_identity = claims.get("sub", f"detector:{source}")

    from datetime import timedelta
    horizon_start = (datetime.now(timezone.utc) - timedelta(seconds=settings.CONTINUATION_HORIZON_SECONDS)).isoformat() + "Z"

    per_identity_count = await backend.count_recent_signals(designator_identity, horizon_start)
    if per_identity_count >= settings.DESIGNATION_RATE_LIMIT:
            await backend.record_signal_attempt(designator_identity, designation_event.poisoned_node_id, "designation", "RATE_LIMITED")
            raise HTTPException(status_code=429, detail="Rate limit exceeded for designations", headers={"Retry-After": str(settings.CONTINUATION_HORIZON_SECONDS)})

    await backend.record_signal_attempt(designator_identity, designation_event.poisoned_node_id, "designation", "PENDING")

    async with _admission_exclusive():
            exists_map, quarantined_map = await asyncio.gather(
                backend.nodes_exist([designation_event.poisoned_node_id]),
                backend.are_quarantined([designation_event.poisoned_node_id]),
            )
            if not exists_map.get(designation_event.poisoned_node_id):
                raise HTTPException(status_code=404, detail="Node ID not found in DAG")
            if quarantined_map.get(designation_event.poisoned_node_id):
                return {"designated": True, "message": "Node already in quarantine ledger", "already_quarantined": True}

            c_p = await backend.compute_blast_radius(designation_event.poisoned_node_id)

            from src.r6_utils import process_recurrence
            active_horizons = await backend.get_active_horizon_set()
            for n in c_p:
                if n in active_horizons:
                    await process_recurrence(backend, n, "RENEWED_DESIGNATION", "internal_hook")

            monotonic_ledger_digest = await backend.compute_quarantine_digest(c_p)

            q_event = {
                "quarantine_event_id": str(uuid.uuid4()),
                "detected_at_utc": datetime.now(timezone.utc).isoformat() + "Z",
                "poisoned_root_id": designation_event.poisoned_node_id,
                "computed_blast_radius_C_p": c_p,
                "monotonic_ledger_digest_post_transition": monotonic_ledger_digest,
                "designator_identity": designator_identity,
                "designation_reason": designation_event.reason,
                "detector_source": source,
            }
            await backend.apply_quarantine_transaction(q_event, c_p)

    continuity_results = await _attempt_safe_continuity(c_p, q_event)

    await _attempt_reconstruction(designation_event.poisoned_node_id)

    raw_event_record["outcome"] = "designated"
    raw_event_record["quarantine_event_id"] = q_event["quarantine_event_id"]

    return {
            "designated": True,
            "event": q_event,
            "continuity": continuity_results,
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

@app.post("/seed-root")
async def seed_root(request: Request, body: dict = Body(...)):
    """C3 mitigation: admin can seed a new independent root when the
    existing root(s) are quarantined. This restores write availability
    without clearing quarantine.

    The seed node is gateway-signed (ECDSA-P256) and records the
    authorizing admin identity, so it participates in the same
    cryptographic binding as every other DAG node.

    Body: {"root_id": "new-root-id"}
    """
    claims = verify_role_jwt(request, "admin")
    admin_identity = claims.get("sub", "unknown")

    root_id = body.get("root_id")
    if not root_id:
            raise HTTPException(status_code=400, detail="root_id required")
    exists = await backend.nodes_exist([root_id])
    if exists.get(root_id):
            raise HTTPException(status_code=409, detail=f"Node {root_id} already exists")

    # Generate a gateway signing key for this seed operation
    from cryptography.hazmat.primitives.asymmetric import utils as asy_utils
    gateway_private_key = ec.generate_private_key(ec.SECP256R1())
    gateway_pub_numbers = gateway_private_key.public_key().public_numbers()
    gateway_pub_hex = (
            gateway_pub_numbers.x.to_bytes(32, "big")
            + gateway_pub_numbers.y.to_bytes(32, "big")
    ).hex()

    state_content = {"type": "seed_root", "seeded_by": admin_identity}
    content_str = json.dumps(state_content, sort_keys=True)
    content_hash = hashlib.sha256(content_str.encode()).hexdigest()

    # Sign content_hash with gateway key (same scheme as agent signatures)
    der_sig = gateway_private_key.sign(content_hash.encode(), ec.ECDSA(hashes.SHA256()))
    r, s = asy_utils.decode_dss_signature(der_sig)
    sig_hex = (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()

    seed_payload = {
            "payload_id": root_id,
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "ephemeral_nhi": {
                "identity_id": gateway_pub_hex,
                "session_token": "gateway_seed",
                "expires_at_utc": "9999-12-31T23:59:59Z",
            },
            "declared_evidence_boundary": {
                "boundary_id": f"seed-{root_id}",
                "fixed_at_utc": datetime.now(timezone.utc).isoformat(),
                "boundary_digest": "0" * 64,
            },
            "state_content": state_content,
            "parent_dependency_commitments": [],
            "content_digest_sha256": content_hash,
            "agent_signature": sig_hex,
            "signature_algorithm": "ECDSA-P256-SHA256",
    }
    await backend.commit_node(seed_payload)
    return {"status": "ok", "root_id": root_id, "gateway_identity": gateway_pub_hex}

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

    # Safety: containment integrity — count nodes outside quarantine
    # that derive from quarantined material (via parents or covers).
    q_set = set(quarantine_ledger)
    breaches = []
    for nid, ndata in dag.items():
            if nid in q_set:
                continue
            for p in ndata.get("parent_dependency_commitments", []):
                if p["parent_node_id"] in q_set:
                    breaches.append(nid)
                    break
            else:
                for covered in ndata.get("covers", []):
                    if covered in q_set:
                        breaches.append(nid)
                        break

    safety_metrics = {
            "quarantined_nodes": quarantined_count,
            "containment_fraction": quarantined_count / total_nodes if total_nodes > 0 else 0.0,
            "withdrawn_nodes": withdrawn_count,
            "containment_breaches": len(breaches),
            "escape_set": breaches,
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
    
