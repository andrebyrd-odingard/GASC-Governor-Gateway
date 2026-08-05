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

