import aiosqlite
import json
import hashlib
import os
from typing import Dict, Any, List
from contextlib import asynccontextmanager

from src.governor_service import BaseStateBackend
from src.config import settings

class SqliteStateBackend(BaseStateBackend):
    def __init__(self, db_path: str = "state.db"):
        self.db_path = db_path
        self._db = None
        self._max_traversal_depth = getattr(settings, "MAX_TRAVERSAL_DEPTH", 1000)

    @asynccontextmanager
    async def _connect(self):
        if self._db is None:
            self._db = await aiosqlite.connect(self.db_path)
            await self._db.execute("PRAGMA journal_mode=WAL")
            await self._db.execute("PRAGMA synchronous=FULL")
        yield self._db

    async def init_db(self):
        async with self._connect() as db:
            
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
            
            # Partial index: only CARRIED edges are needed for compaction repair.
            await db.execute("CREATE INDEX IF NOT EXISTS idx_edges_carried_parent ON edges(parent_id) WHERE edge_class = 'CARRIED'")
            
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
            
            await db.execute('''CREATE TABLE IF NOT EXISTS external_effects (
                idempotency_key TEXT PRIMARY KEY,
                node_id TEXT,
                effect_type TEXT,
                recorded_at_utc TEXT
            )''')
            
            await db.execute('''CREATE TABLE IF NOT EXISTS reintegration_horizon (
                node_id TEXT PRIMARY KEY,
                admitted_at_utc TEXT NOT NULL,
                trust_expires_utc TEXT NOT NULL,
                predecessor_id TEXT NOT NULL,
                renewal_count INTEGER DEFAULT 0
            )''')
            
            await db.execute("CREATE INDEX IF NOT EXISTS idx_horizon_expiry ON reintegration_horizon(trust_expires_utc)")
            
            await db.execute('''CREATE TABLE IF NOT EXISTS recurrence_events (
                event_id TEXT PRIMARY KEY,
                node_id TEXT NOT NULL,
                recurrence_class TEXT NOT NULL,
                detected_at_utc TEXT NOT NULL,
                signal_source TEXT NOT NULL,
                outcome TEXT NOT NULL DEFAULT 'PROCESSED',
                event_json TEXT NOT NULL
            )''')

            await db.execute('''CREATE TABLE IF NOT EXISTS signal_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                signal_source TEXT NOT NULL,
                node_id TEXT NOT NULL,
                signal_kind TEXT NOT NULL,
                outcome TEXT NOT NULL,
                recorded_at_utc TEXT NOT NULL
            )''')
            await db.execute("CREATE INDEX IF NOT EXISTS idx_signal_attempts_source ON signal_attempts(signal_source, recorded_at_utc)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_signal_attempts_time ON signal_attempts(recorded_at_utc)")
            
            await db.execute('''CREATE TABLE IF NOT EXISTS withdrawal_ledger (
                node_id TEXT PRIMARY KEY,
                withdrawn_at_utc TEXT NOT NULL,
                triggering_event_id TEXT NOT NULL,
                withdrawal_reason TEXT NOT NULL
            )''')
            
            await db.execute('''CREATE TABLE IF NOT EXISTS calibration_runs (
                run_id TEXT PRIMARY KEY,
                run_at_utc TEXT NOT NULL,
                seeded_count INTEGER NOT NULL,
                detected_count INTEGER NOT NULL,
                sensitivity_floor REAL NOT NULL,
                monitored_period_json TEXT NOT NULL
            )''')
            
            await db.execute('''CREATE TABLE IF NOT EXISTS shadow_decisions (
                decision_id       TEXT PRIMARY KEY,
                node_id           TEXT NOT NULL,
                evaluated_at_utc  TEXT NOT NULL,
                would_have_blocked INTEGER NOT NULL,
                reason            TEXT,
                parent_status_json TEXT NOT NULL,
                policy_bundle_digest TEXT NOT NULL,
                writer_identity   TEXT
            )''')
            
            await db.execute("CREATE INDEX IF NOT EXISTS idx_shadow_evaluated ON shadow_decisions(evaluated_at_utc)")
            await db.execute("CREATE INDEX IF NOT EXISTS idx_shadow_blocked ON shadow_decisions(would_have_blocked)")
            
            await db.commit()

    async def get_dag(self) -> Dict[str, Any]:
        async with self._connect() as db:
            async with db.execute("SELECT node_id, payload_json FROM nodes") as cursor:
                rows = await cursor.fetchall()
                return {row[0]: json.loads(row[1]) for row in rows}

    async def get_quarantine_ledger(self) -> List[str]:
        async with self._connect() as db:
            async with db.execute("SELECT node_id FROM quarantine_ledger") as cursor:
                rows = await cursor.fetchall()
                return [row[0] for row in rows]

    async def get_repair_candidates(self) -> Dict[str, Any]:
        async with self._connect() as db:
            async with db.execute("SELECT node_id, candidate_json FROM repair_candidates") as cursor:
                rows = await cursor.fetchall()
                return {row[0]: json.loads(row[1]) for row in rows}
                
    async def update_repair_candidate(self, node_id: str, data: dict):
        async with self._connect() as db:
            await self._set_repair_candidate(db, node_id, data)

    async def commit_node(self, payload: dict) -> bool:
        """
        Commit a node to the DAG. Returns True if the node was newly inserted,
        False if it already existed (idempotent duplicate).
        
        Uses INSERT OR IGNORE for idempotency: a duplicate payload_id is a no-op.
        A retry that lands the same node twice must not produce a second audit
        record, shadow decision, or quarantine event.
        """
        node_id = payload["payload_id"]
        content_hash = payload.get("content_digest_sha256", "")
        parents = payload.get("parent_dependency_commitments", [])
        
        # Commitment logic: SHA-256(contentHash || sorted(deps))
        sorted_deps = sorted([p["parent_node_id"] for p in parents])
        commitment_input = content_hash + "".join(sorted_deps)
        commitment = hashlib.sha256(commitment_input.encode()).hexdigest()
        
        payload_json = json.dumps(payload)
        
        async with self._connect() as db:
            cursor = await db.execute(
                "INSERT OR IGNORE INTO nodes (node_id, payload_json, content_hash, commitment) VALUES (?, ?, ?, ?)",
                (node_id, payload_json, content_hash, commitment)
            )
            if cursor.rowcount == 0:
                # Node already exists — idempotent no-op
                return False
            
            for p in parents:
                await db.execute(
                    "INSERT OR IGNORE INTO edges (child_id, parent_id, edge_class) VALUES (?, ?, ?)",
                    (node_id, p["parent_node_id"], p.get("edge_class", "MATERIAL"))
                )
            await db.commit()
            return True

    async def log_quarantine_event(self, event: dict):
        # Fallback method, ideally use apply_quarantine_transaction
        async with self._connect() as db:
            await db.execute(
                "INSERT OR REPLACE INTO quarantine_events (event_id, event_json) VALUES (?, ?)",
                (event["quarantine_event_id"], json.dumps(event))
            )
            await db.commit()

    async def add_to_quarantine_ledger(self, node_id: str):
        # Fallback method, ideally use apply_quarantine_transaction
        async with self._connect() as db:
            await db.execute("INSERT OR IGNORE INTO quarantine_ledger (node_id) VALUES (?)", (node_id,))
            await db.commit()

    async def apply_quarantine_transaction(self, event: dict, c_p: List[str]):
        """
        Append-only atomic transaction.
        Records the quarantine event and updates the ledger all-or-nothing.
        """
        # Record the traversal depth lever in the event
        event["max_traversal_depth"] = self._max_traversal_depth
        
        async with self._connect() as db:
            await db.execute(
                "INSERT OR REPLACE INTO quarantine_events (event_id, event_json) VALUES (?, ?)",
                (event["quarantine_event_id"], json.dumps(event))
            )
            for node_id in c_p:
                await db.execute("INSERT OR IGNORE INTO quarantine_ledger (node_id) VALUES (?)", (node_id,))
            await db.commit()

    async def get_quarantine_events(self) -> List[dict]:
        async with self._connect() as db:
            async with db.execute("SELECT event_json FROM quarantine_events") as cursor:
                rows = await cursor.fetchall()
                return [json.loads(row[0]) for row in rows]

    async def compute_blast_radius(self, poisoned_root_id: str) -> List[str]:
        """
        Computes the target blast radius using a bounded BFS over the edge table.

        The original recursive CTE was O(paths) and could blow up on dense DAGs
        (the 0001b no-clear scope creates O(n^2) edges).  We now choose between
        two strategies based on edge count:

        - Sparse graphs (<= 10_000 edges): load the full edge table once and
          BFS in Python; a single table scan is cheap and avoids per-level
          round-trips.
        - Dense graphs (> 10_000 edges): walk level-by-level using indexed SQL
          queries and stop early once every node in the DAG has been reached.
          This is sub-millisecond for the no-clear benchmark.

        Depth is still bounded by max_traversal_depth.
        """
        c_p: List[str] = []
        async with self._connect() as db:
            # Edge count helps us choose the right traversal strategy.
            async with db.execute("SELECT COUNT(*) FROM edges") as count_cursor:
                edge_count = (await count_cursor.fetchone())[0]

            visited: set = {poisoned_root_id}

            if edge_count <= 10_000:
                # Sparse: one table scan is faster than many per-level queries.
                async with db.execute("SELECT parent_id, child_id FROM edges") as cursor:
                    rows = await cursor.fetchall()

                adjacency: Dict[str, List[str]] = {}
                for parent_id, child_id in rows:
                    adjacency.setdefault(parent_id, []).append(child_id)

                current_level = [(poisoned_root_id, 0)]
                while current_level:
                    next_level = []
                    for node_id, depth in current_level:
                        if depth >= self._max_traversal_depth:
                            continue
                        for child_id in adjacency.get(node_id, []):
                            if child_id in visited:
                                continue
                            visited.add(child_id)
                            next_level.append((child_id, depth + 1))
                    current_level = next_level
            else:
                # Dense: level-by-level with an early-exit once the whole DAG
                # is covered.  This avoids scanning O(n^2) paths.
                async with db.execute("SELECT COUNT(*) FROM nodes") as nodes_cursor:
                    nodes_count = (await nodes_cursor.fetchone())[0]
                async with db.execute(
                    "SELECT 1 FROM nodes WHERE node_id = ?", (poisoned_root_id,)
                ) as root_cursor:
                    root_in_nodes = (await root_cursor.fetchone()) is not None

                # If the root is not in the nodes table (some repro benchmarks
                # seed the edges but not the root node record), account for it.
                total_expected = nodes_count + (0 if root_in_nodes else 1)

                current: List[str] = [poisoned_root_id]
                depth = 0
                while current and depth < self._max_traversal_depth:
                    placeholders = ",".join("?" for _ in current)
                    query = f"""
                        SELECT DISTINCT child_id
                        FROM edges
                        WHERE parent_id IN ({placeholders})
                    """
                    async with db.execute(query, tuple(current)) as cursor:
                        rows = await cursor.fetchall()

                    next_current = []
                    for (child_id,) in rows:
                        if child_id in visited:
                            continue
                        visited.add(child_id)
                        next_current.append(child_id)

                    if not next_current:
                        break

                    current = next_current
                    depth += 1

                    if len(visited) == total_expected:
                        break

            c_p = sorted(visited)

            # Now find affected compactions:
            # Nodes that have a CARRIED edge originating from a node in c_p
            affected_compactions: List[str] = []
            if c_p:
                # Use a temp table so SQLite can join instead of a huge IN list.
                await db.execute("CREATE TEMP TABLE IF NOT EXISTS _blast_radius_tmp (node_id TEXT PRIMARY KEY)")
                await db.execute("DELETE FROM _blast_radius_tmp")
                await db.executemany(
                    "INSERT INTO _blast_radius_tmp (node_id) VALUES (?)",
                    [(n,) for n in c_p]
                )
                async with db.execute(
                    """
                    SELECT DISTINCT e.child_id
                    FROM edges e
                    JOIN _blast_radius_tmp t ON e.parent_id = t.node_id
                    WHERE e.edge_class = 'CARRIED'
                    """
                ) as comp_cursor:
                    affected_compactions = [r[0] for r in await comp_cursor.fetchall()]

            # R1 and R2 only matter when there are compactions to repair.
            if affected_compactions:
                dag = await self.get_dag()
                checkpoints = await self.get_checkpoints()
                semantic_rollback = await self.has_external_effects(c_p)

                for comp_node in affected_compactions:
                    if semantic_rollback:
                        await self._set_repair_candidate(db, comp_node, {
                            "disposition": "IRREDUCIBLE",
                            "reason": "semantic_rollback_hazard",
                            "escalation_record": "Quarantined subgraph contains irreversible external effects"
                        })
                        continue

                    if comp_node not in dag:
                        continue

                    covers = dag[comp_node].get("covers", [])

                    # R1: Admissible Frontier
                    frontier = [n for n in covers if n not in visited]
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
        async with self._connect() as db:
            await db.execute(
                "INSERT OR REPLACE INTO checkpoints (checkpoint_id, checkpoint_json) VALUES (?, ?)",
                (checkpoint["checkpoint_id"], json.dumps(checkpoint))
            )
            await db.commit()

    async def get_checkpoints(self) -> Dict[str, dict]:
        async with self._connect() as db:
            async with db.execute("SELECT checkpoint_id, checkpoint_json FROM checkpoints") as cursor:
                rows = await cursor.fetchall()
                return {row[0]: json.loads(row[1]) for row in rows}

    async def add_external_effect(self, idempotency_key: str, node_id: str, effect_type: str):
        from datetime import datetime, timezone
        async with self._connect() as db:
            await db.execute(
                "INSERT OR REPLACE INTO external_effects (idempotency_key, node_id, effect_type, recorded_at_utc) VALUES (?, ?, ?, ?)",
                (idempotency_key, node_id, effect_type, datetime.now(timezone.utc).isoformat() + "Z")
            )
            await db.commit()

    async def check_external_effect(self, idempotency_key: str) -> bool:
        async with self._connect() as db:
            async with db.execute("SELECT 1 FROM external_effects WHERE idempotency_key = ?", (idempotency_key,)) as cursor:
                row = await cursor.fetchone()
                return row is not None

    async def has_external_effects(self, node_ids: List[str]) -> bool:
        if not node_ids:
            return False
        placeholders = ",".join(["?"] * len(node_ids))
        async with self._connect() as db:
            async with db.execute(f"SELECT 1 FROM external_effects WHERE node_id IN ({placeholders}) LIMIT 1", tuple(node_ids)) as cursor:
                row = await cursor.fetchone()
                return row is not None

    async def reset(self):
        async with self._connect() as db:
            await db.execute("DELETE FROM nodes")
            await db.execute("DELETE FROM edges")
            await db.execute("DELETE FROM quarantine_ledger")
            await db.execute("DELETE FROM quarantine_events")
            await db.execute("DELETE FROM repair_candidates")
            await db.execute("DELETE FROM checkpoints")
            await db.execute("DELETE FROM external_effects")
            await db.execute("DELETE FROM reintegration_horizon")
            await db.execute("DELETE FROM recurrence_events")
            await db.execute("DELETE FROM withdrawal_ledger")
            await db.execute("DELETE FROM calibration_runs")
            await db.execute("DELETE FROM signal_attempts")
            await db.commit()
            
        # Re-initialize basic data
        await self.commit_node({"payload_id": "clean-parent-1", "parent_dependency_commitments": []})
        async with self._connect() as db:
            await db.execute("INSERT OR IGNORE INTO quarantine_ledger (node_id) VALUES (?)", ("quarantined-node-A",))
            await db.commit()

    async def record_reintegration(self, node_id: str, predecessor_id: str, horizon_seconds: int):
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=horizon_seconds)
        async with self._connect() as db:
            await db.execute(
                "INSERT OR REPLACE INTO reintegration_horizon (node_id, admitted_at_utc, trust_expires_utc, predecessor_id) VALUES (?, ?, ?, ?)",
                (node_id, now.isoformat() + "Z", expires.isoformat() + "Z", predecessor_id)
            )
            await db.commit()

    async def get_active_horizon_set(self) -> Dict[str, dict]:
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat() + "Z"
        async with self._connect() as db:
            async with db.execute("SELECT node_id, trust_expires_utc, predecessor_id, renewal_count FROM reintegration_horizon WHERE trust_expires_utc > ?", (now,)) as cursor:
                rows = await cursor.fetchall()
                return {r[0]: {"trust_expires_utc": r[1], "predecessor_id": r[2], "renewal_count": r[3]} for r in rows}

    async def get_expired_horizon_set(self) -> List[str]:
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat() + "Z"
        async with self._connect() as db:
            async with db.execute("SELECT node_id FROM reintegration_horizon WHERE trust_expires_utc <= ?", (now,)) as cursor:
                rows = await cursor.fetchall()
                return [r[0] for r in rows]

    async def renew_trust(self, node_id: str, horizon_seconds: int):
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=horizon_seconds)
        async with self._connect() as db:
            await db.execute(
                "UPDATE reintegration_horizon SET trust_expires_utc = ?, renewal_count = renewal_count + 1 WHERE node_id = ?",
                (expires.isoformat() + "Z", node_id)
            )
            await db.commit()

    async def apply_withdrawal_transaction(self, event: dict, w_r: List[str]):
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat() + "Z"
        async with self._connect() as db:
            await db.execute(
                "INSERT OR REPLACE INTO recurrence_events (event_id, node_id, recurrence_class, detected_at_utc, signal_source, event_json) VALUES (?, ?, ?, ?, ?, ?)",
                (event["event_id"], event["node_id"], event["recurrence_class"], event["detected_at_utc"], event["signal_source"], json.dumps(event))
            )
            for i, node_id in enumerate(w_r):
                reason = "DIRECTLY_IMPLICATED" if i == 0 else "UNEXAMINED_DEPENDENT"
                await db.execute(
                    "INSERT OR IGNORE INTO withdrawal_ledger (node_id, withdrawn_at_utc, triggering_event_id, withdrawal_reason) VALUES (?, ?, ?, ?)",
                    (node_id, now, event["event_id"], reason)
                )
            await db.commit()

    async def get_withdrawal_ledger(self) -> Dict[str, dict]:
        async with self._connect() as db:
            async with db.execute("SELECT node_id, withdrawn_at_utc, triggering_event_id, withdrawal_reason FROM withdrawal_ledger") as cursor:
                rows = await cursor.fetchall()
                return {r[0]: {"withdrawn_at_utc": r[1], "triggering_event_id": r[2], "withdrawal_reason": r[3]} for r in rows}

    async def record_calibration_run(self, run: dict):
        async with self._connect() as db:
            await db.execute(
                "INSERT OR REPLACE INTO calibration_runs (run_id, run_at_utc, seeded_count, detected_count, sensitivity_floor, monitored_period_json) VALUES (?, ?, ?, ?, ?, ?)",
                (run["run_id"], run["run_at_utc"], run["seeded_count"], run["detected_count"], run["sensitivity_floor"], json.dumps(run["monitored_period"]))
            )
            await db.commit()

    async def get_calibration_runs(self) -> List[dict]:
        async with self._connect() as db:
            async with db.execute("SELECT run_id, run_at_utc, seeded_count, detected_count, sensitivity_floor, monitored_period_json FROM calibration_runs") as cursor:
                rows = await cursor.fetchall()
                return [{"run_id": r[0], "run_at_utc": r[1], "seeded_count": r[2], "detected_count": r[3], "sensitivity_floor": r[4], "monitored_period": json.loads(r[5])} for r in rows]

    async def record_signal_attempt(self, signal_source: str, node_id: str,
                                    signal_kind: str, outcome: str) -> None:
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc).isoformat() + "Z"
        async with self._connect() as db:
            await db.execute(
                "INSERT INTO signal_attempts (signal_source, node_id, signal_kind, outcome, recorded_at_utc) VALUES (?, ?, ?, ?, ?)",
                (signal_source, node_id, signal_kind, outcome, now)
            )
            await db.commit()

    async def count_recent_signals(self, signal_source: str, since_utc: str) -> int:
        async with self._connect() as db:
            async with db.execute(
                "SELECT COUNT(*) FROM signal_attempts WHERE signal_source = ? AND recorded_at_utc > ?",
                (signal_source, since_utc)
            ) as cursor:
                row = await cursor.fetchone()
                return row[0]

    async def count_recent_signals_global(self, since_utc: str) -> int:
        async with self._connect() as db:
            async with db.execute(
                "SELECT COUNT(*) FROM signal_attempts WHERE recorded_at_utc > ?",
                (since_utc,)
            ) as cursor:
                row = await cursor.fetchone()
                return row[0]

    async def get_signal_outcome_counts(self) -> Dict[str, int]:
        async with self._connect() as db:
            async with db.execute(
                "SELECT outcome, COUNT(*) FROM signal_attempts GROUP BY outcome"
            ) as cursor:
                rows = await cursor.fetchall()
                return {r[0]: r[1] for r in rows}

    async def record_shadow_decision(self, decision_id: str, node_id: str, evaluated_at_utc: str, would_have_blocked: bool, reason: str, parent_status_json: str, policy_bundle_digest: str, writer_identity: str):
        async with self._connect() as db:
            await db.execute(
                "INSERT INTO shadow_decisions (decision_id, node_id, evaluated_at_utc, would_have_blocked, reason, parent_status_json, policy_bundle_digest, writer_identity) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (decision_id, node_id, evaluated_at_utc, 1 if would_have_blocked else 0, reason, parent_status_json, policy_bundle_digest, writer_identity)
            )
            await db.commit()

    async def nodes_exist(self, node_ids: List[str]) -> Dict[str, bool]:
        if not node_ids:
            return {}
        uniq = list(dict.fromkeys(node_ids))
        q = f"SELECT node_id FROM nodes WHERE node_id IN ({','.join('?' * len(uniq))})"
        import aiosqlite
        async with self._connect() as db:
            async with db.execute(q, uniq) as cur:
                found = {r[0] for r in await cur.fetchall()}
        return {nid: (nid in found) for nid in uniq}

    async def are_quarantined(self, node_ids: List[str]) -> Dict[str, bool]:
        if not node_ids:
            return {}
        uniq = list(dict.fromkeys(node_ids))
        q = f"SELECT node_id FROM quarantine_ledger WHERE node_id IN ({','.join('?' * len(uniq))})"
        import aiosqlite
        async with self._connect() as db:
            async with db.execute(q, uniq) as cur:
                found = {r[0] for r in await cur.fetchall()}
        return {nid: (nid in found) for nid in uniq}

    async def compute_quarantine_digest(self, additional_node_ids: List[str]) -> str:
        async with self._connect() as db:
            async with db.execute("SELECT node_id FROM quarantine_ledger") as cursor:
                rows = await cursor.fetchall()
                existing = {row[0] for row in rows}
            merged = sorted(existing | set(additional_node_ids))
            return hashlib.sha256(json.dumps(merged, sort_keys=True).encode()).hexdigest()

    async def compute_covers_interval_gap(self, covers: List[str]) -> List[str]:
        if not covers: return []
        uniq = list(dict.fromkeys(covers))
        placeholders = ",".join(["?"] * len(uniq))
        query = f"""
            WITH RECURSIVE
            descendants(node_id) AS (
                SELECT node_id FROM nodes WHERE node_id IN ({placeholders})
                UNION
                SELECT e.child_id FROM edges e
                INNER JOIN descendants d ON e.parent_id = d.node_id
            ),
            ancestors(node_id) AS (
                SELECT node_id FROM nodes WHERE node_id IN ({placeholders})
                UNION
                SELECT e.parent_id FROM edges e
                INNER JOIN ancestors a ON e.child_id = a.node_id
            )
            SELECT node_id FROM descendants
            INTERSECT
            SELECT node_id FROM ancestors
            EXCEPT
            SELECT node_id FROM nodes WHERE node_id IN ({placeholders})
        """
        params = tuple(uniq) * 3
        import aiosqlite
        async with self._connect() as db:
            async with db.execute(query, params) as cursor:
                rows = await cursor.fetchall()
                return sorted([r[0] for r in rows])
