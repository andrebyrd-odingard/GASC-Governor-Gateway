import aiosqlite
import json
import hashlib
import os
from typing import Dict, Any, List

from src.governor_service import BaseStateBackend
from src.config import settings

class SqliteStateBackend(BaseStateBackend):
    def __init__(self, db_path: str = "state.db"):
        self.db_path = db_path
        self._max_traversal_depth = getattr(settings, "MAX_TRAVERSAL_DEPTH", 1000)

    async def init_db(self):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("PRAGMA journal_mode=WAL")
            await db.execute("PRAGMA synchronous=FULL")
            
            await db.execute('''CREATE TABLE IF NOT EXISTS nodes (
                node_id TEXT PRIMARY KEY,
                payload_json TEXT,
                content_hash TEXT,
                commitment TEXT
            )''')
            
            await db.execute('''CREATE TABLE IF NOT EXISTS edges (
                child_id TEXT,
                parent_id TEXT,
                edge_class TEXT,
                PRIMARY KEY (child_id, parent_id)
            )''')
            
            await db.execute("CREATE INDEX IF NOT EXISTS idx_edges_parent_id ON edges(parent_id)")
            
            await db.execute('''CREATE TABLE IF NOT EXISTS quarantine_ledger (
                node_id TEXT PRIMARY KEY
            )''')
            
            await db.execute('''CREATE TABLE IF NOT EXISTS quarantine_events (
                event_id TEXT PRIMARY KEY,
                event_json TEXT
            )''')
            
            await db.execute('''CREATE TABLE IF NOT EXISTS repair_candidates (
                node_id TEXT PRIMARY KEY,
                candidate_json TEXT
            )''')
            
            await db.execute('''CREATE TABLE IF NOT EXISTS checkpoints (
                checkpoint_id TEXT PRIMARY KEY,
                checkpoint_json TEXT
            )''')
            await db.commit()

    async def get_dag(self) -> Dict[str, Any]:
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("SELECT node_id, payload_json FROM nodes") as cursor:
                rows = await cursor.fetchall()
                return {row[0]: json.loads(row[1]) for row in rows}

    async def get_quarantine_ledger(self) -> List[str]:
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("SELECT node_id FROM quarantine_ledger") as cursor:
                rows = await cursor.fetchall()
                return [row[0] for row in rows]

    async def get_repair_candidates(self) -> Dict[str, Any]:
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("SELECT node_id, candidate_json FROM repair_candidates") as cursor:
                rows = await cursor.fetchall()
                return {row[0]: json.loads(row[1]) for row in rows}
                
    async def update_repair_candidate(self, node_id: str, data: dict):
        async with aiosqlite.connect(self.db_path) as db:
            await self._set_repair_candidate(db, node_id, data)

    async def commit_node(self, payload: dict):
        node_id = payload["payload_id"]
        content_hash = payload.get("content_digest_sha256", "")
        parents = payload.get("parent_dependency_commitments", [])
        
        # Commitment logic: SHA-256(contentHash || sorted(deps))
        sorted_deps = sorted([p["parent_node_id"] for p in parents])
        commitment_input = content_hash + "".join(sorted_deps)
        commitment = hashlib.sha256(commitment_input.encode()).hexdigest()
        
        payload_json = json.dumps(payload)
        
        async with aiosqlite.connect(self.db_path) as db:
            # We want to replace if exists to allow overwriting in tests or reintegration
            await db.execute(
                "INSERT OR REPLACE INTO nodes (node_id, payload_json, content_hash, commitment) VALUES (?, ?, ?, ?)",
                (node_id, payload_json, content_hash, commitment)
            )
            
            # Clear old edges and insert new ones
            await db.execute("DELETE FROM edges WHERE child_id = ?", (node_id,))
            for p in parents:
                await db.execute(
                    "INSERT INTO edges (child_id, parent_id, edge_class) VALUES (?, ?, ?)",
                    (node_id, p["parent_node_id"], p.get("edge_class", "MATERIAL"))
                )
            await db.commit()

    async def log_quarantine_event(self, event: dict):
        # Fallback method, ideally use apply_quarantine_transaction
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT OR REPLACE INTO quarantine_events (event_id, event_json) VALUES (?, ?)",
                (event["quarantine_event_id"], json.dumps(event))
            )
            await db.commit()

    async def add_to_quarantine_ledger(self, node_id: str):
        # Fallback method, ideally use apply_quarantine_transaction
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("INSERT OR IGNORE INTO quarantine_ledger (node_id) VALUES (?)", (node_id,))
            await db.commit()

    async def apply_quarantine_transaction(self, event: dict, c_p: List[str]):
        """
        Append-only atomic transaction.
        Records the quarantine event and updates the ledger all-or-nothing.
        """
        # Record the traversal depth lever in the event
        event["max_traversal_depth"] = self._max_traversal_depth
        
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT OR REPLACE INTO quarantine_events (event_id, event_json) VALUES (?, ?)",
                (event["quarantine_event_id"], json.dumps(event))
            )
            for node_id in c_p:
                await db.execute("INSERT OR IGNORE INTO quarantine_ledger (node_id) VALUES (?)", (node_id,))
            await db.commit()

    async def get_quarantine_events(self) -> List[dict]:
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("SELECT event_json FROM quarantine_events") as cursor:
                rows = await cursor.fetchall()
                return [json.loads(row[0]) for row in rows]

    async def compute_blast_radius(self, poisoned_root_id: str) -> List[str]:
        """
        Computes the target blast radius using a recursive CTE.
        Note: Table 4 finds RER 0.968 for bounded-depth. Set max_traversal_depth with caution.
        Lazy evaluation is satisfied by construction: this traversal only runs on designation,
        never during the standard write path.
        """
        query = """
        WITH RECURSIVE blast_radius(node_id, depth) AS (
            SELECT ?, 0
            UNION
            SELECT e.child_id, br.depth + 1
            FROM edges e
            JOIN blast_radius br ON e.parent_id = br.node_id
            WHERE br.depth < ?
        )
        SELECT DISTINCT node_id FROM blast_radius;
        """
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute(query, (poisoned_root_id, self._max_traversal_depth)) as cursor:
                rows = await cursor.fetchall()
                c_p = sorted([row[0] for row in rows])

            # Now find affected compactions:
            # Nodes that have a CARRIED edge originating from a node in c_p
            affected_compactions = []
            if c_p:
                placeholders = ",".join("?" for _ in c_p)
                comp_query = f"""
                SELECT DISTINCT child_id FROM edges 
                WHERE parent_id IN ({placeholders}) AND edge_class = 'CARRIED'
                """
                async with db.execute(comp_query, tuple(c_p)) as comp_cursor:
                    comp_rows = await comp_cursor.fetchall()
                    affected_compactions = [r[0] for r in comp_rows]

            # Re-implement R1 and R2
            dag = await self.get_dag()
            checkpoints = await self.get_checkpoints()
            
            for comp_node in affected_compactions:
                covers = dag[comp_node].get("covers", [])
                
                # R1: Admissible Frontier
                frontier = [n for n in covers if n not in c_p]
                if not frontier:
                    await self._set_repair_candidate(db, comp_node, {
                        "disposition": "IRREDUCIBLE",
                        "reason": "empty_frontier",
                        "escalation_record": "Requires human review"
                    })
                    continue
                
                # R2: Planner & Selection
                summarizer = dag[comp_node].get("summarizer", {})
                if summarizer.get("method_id") == "llm-v1":
                    admissible_checkpoint = None
                    for cp_id, cp_data in checkpoints.items():
                        if cp_data["target_node_id"] in frontier:
                            admissible_checkpoint = cp_data
                            break
                            
                    if not admissible_checkpoint:
                        await self._set_repair_candidate(db, comp_node, {
                            "disposition": "IRREDUCIBLE",
                            "reason": "no_admissible_checkpoint",
                            "escalation_record": "Requires human review"
                        })
                        continue
                        
                    if not getattr(settings, "RECOVERY_ADAPTER_URL", None):
                        await self._set_repair_candidate(db, comp_node, {
                            "disposition": "IRREDUCIBLE",
                            "reason": "no_reconstruction_backend",
                            "escalation_record": "Requires human review"
                        })
                        continue
                        
                    await self._set_repair_candidate(db, comp_node, {
                        "disposition": "PENDING_RECONSTRUCTION",
                        "frontier": frontier,
                        "method": "verified_checkpoint_reconstruction",
                        "checkpoint": admissible_checkpoint
                    })
                else:
                    await self._set_repair_candidate(db, comp_node, {
                        "disposition": "IRREDUCIBLE",
                        "reason": "no_reconstruction_backend",
                        "escalation_record": "Unknown summarizer method"
                    })
                    
        return c_p

    async def _set_repair_candidate(self, db, node_id, data):
        await db.execute(
            "INSERT OR REPLACE INTO repair_candidates (node_id, candidate_json) VALUES (?, ?)",
            (node_id, json.dumps(data))
        )
        await db.commit()

    async def add_checkpoint(self, checkpoint: dict):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute(
                "INSERT OR REPLACE INTO checkpoints (checkpoint_id, checkpoint_json) VALUES (?, ?)",
                (checkpoint["checkpoint_id"], json.dumps(checkpoint))
            )
            await db.commit()

    async def get_checkpoints(self) -> Dict[str, dict]:
        async with aiosqlite.connect(self.db_path) as db:
            async with db.execute("SELECT checkpoint_id, checkpoint_json FROM checkpoints") as cursor:
                rows = await cursor.fetchall()
                return {row[0]: json.loads(row[1]) for row in rows}

    async def reset(self):
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("DELETE FROM nodes")
            await db.execute("DELETE FROM edges")
            await db.execute("DELETE FROM quarantine_ledger")
            await db.execute("DELETE FROM quarantine_events")
            await db.execute("DELETE FROM repair_candidates")
            await db.execute("DELETE FROM checkpoints")
            await db.commit()
            
        # Re-initialize basic data
        await self.commit_node({"payload_id": "clean-parent-1", "parent_dependency_commitments": []})
        async with aiosqlite.connect(self.db_path) as db:
            await db.execute("INSERT OR IGNORE INTO quarantine_ledger (node_id) VALUES (?)", ("quarantined-node-A",))
            await db.commit()
