import asyncio
import hashlib
from typing import Dict, Any, List
from abc import ABC, abstractmethod

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
    async def apply_quarantine_transaction(self, event: dict, c_p: List[str]): pass
    @abstractmethod
    async def compute_blast_radius(self, poisoned_root_id: str) -> List[str]: pass
    @abstractmethod
    async def add_checkpoint(self, checkpoint: dict): pass
    @abstractmethod
    async def get_checkpoints(self) -> Dict[str, dict]: pass
    @abstractmethod
    async def reset(self): pass
    @abstractmethod
    async def record_reintegration(self, node_id: str, predecessor_id: str, horizon_seconds: int): pass
    @abstractmethod
    async def get_active_horizon_set(self) -> Dict[str, dict]: pass
    @abstractmethod
    async def get_expired_horizon_set(self) -> List[str]: pass
    @abstractmethod
    async def renew_trust(self, node_id: str, horizon_seconds: int): pass
    @abstractmethod
    async def apply_withdrawal_transaction(self, event: dict, w_r: List[str]): pass
    @abstractmethod
    async def get_withdrawal_ledger(self) -> Dict[str, dict]: pass
    @abstractmethod
    async def record_calibration_run(self, run: dict): pass
    @abstractmethod
    async def get_calibration_runs(self) -> List[dict]: pass
    

    @abstractmethod
    async def record_shadow_decision(self, decision_id: str, node_id: str, evaluated_at_utc: str, would_have_blocked: bool, reason: str, parent_status_json: str, policy_bundle_digest: str, writer_identity: str):
        pass

    @abstractmethod
    async def nodes_exist(self, node_ids: List[str]) -> Dict[str, bool]: pass
    @abstractmethod
    async def are_quarantined(self, node_ids: List[str]) -> Dict[str, bool]: pass
    @abstractmethod
    async def compute_covers_interval_gap(self, covers: List[str]) -> List[str]: pass
    @abstractmethod
    async def compute_quarantine_digest(self, additional_node_ids: List[str]) -> str:
        """Compute SHA-256 of sorted(current_ledger + additional_node_ids) without returning the full ledger."""
        pass
