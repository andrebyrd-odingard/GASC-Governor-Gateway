import asyncio
import asyncpg
import json
import hashlib
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List

from src.governor_service import BaseStateBackend
from src.config import settings

# Stable namespace hash for advisory locks.
# All admission/designation paths share one lock key.
_ADVISORY_LOCK_KEY = int.from_bytes(
    hashlib.sha256(b"gasc-governor-admission").digest()[:8],
    byteorder="big", signed=True
)


def _parse_utc(ts: str) -> datetime:
    """Parse a UTC timestamp string into a timezone-aware datetime.

    Handles: '...Z', '...+00:00', '...+00:00Z' (double-marked).
    """
    # Strip redundant trailing Z after an existing offset
    if ts.endswith("+00:00Z"):
        ts = ts[:-1]
    elif ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    dt = datetime.fromisoformat(ts)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


class PostgresStateBackend(BaseStateBackend):
    def __init__(self, dsn: str = ""):
        self.dsn = dsn or getattr(settings, "POSTGRES_DSN", "")
        self._pool: asyncpg.Pool | None = None
        self._pool_loop: asyncio.AbstractEventLoop | None = None
        self._max_traversal_depth = getattr(settings, "MAX_TRAVERSAL_DEPTH", 1000)

    @staticmethod
    async def _setup_connection(conn):
        """Register JSON codec so JSONB columns auto-deserialize."""
        await conn.set_type_codec(
            'jsonb', encoder=json.dumps, decoder=json.loads,
            schema='pg_catalog', format='text'
        )
        await conn.set_type_codec(
            'json', encoder=json.dumps, decoder=json.loads,
            schema='pg_catalog', format='text'
        )

    async def _get_pool(self) -> asyncpg.Pool:
        current_loop = asyncio.get_running_loop()
        if self._pool is not None and self._pool_loop is not current_loop:
            # Pool was created on a different event loop (e.g. test teardown/setup).
            # Discard it; create_pool will bind to the current loop.
            try:
                self._pool.terminate()
            except Exception:
                pass
            self._pool = None
        if self._pool is None:
            self._pool = await asyncpg.create_pool(
                self.dsn, min_size=1, max_size=10,
                init=self._setup_connection
            )
            self._pool_loop = current_loop
        return self._pool

    async def close(self):
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    @asynccontextmanager
    async def advisory_shared(self):
        """Acquire a shared advisory lock (admission paths).

        Multiple shared holders run concurrently; an exclusive holder
        (designation) waits for all shared holders to release.
        Uses session-level locks so inner operations can use separate connections.
        """
        pool = await self._get_pool()
        conn = await pool.acquire()
        try:
            await conn.execute(
                "SELECT pg_advisory_lock_shared($1)", _ADVISORY_LOCK_KEY
            )
            try:
                yield
            finally:
                await conn.execute(
                    "SELECT pg_advisory_unlock_shared($1)", _ADVISORY_LOCK_KEY
                )
        finally:
            await pool.release(conn)

    @asynccontextmanager
    async def advisory_exclusive(self):
        """Acquire an exclusive advisory lock (designation paths).

        Blocks until all shared holders release. Only one exclusive
        holder at a time. Uses session-level locks so inner operations
        can use separate connections.
        """
        pool = await self._get_pool()
        conn = await pool.acquire()
        try:
            await conn.execute(
                "SELECT pg_advisory_lock($1)", _ADVISORY_LOCK_KEY
            )
            try:
                yield
            finally:
                await conn.execute(
                    "SELECT pg_advisory_unlock($1)", _ADVISORY_LOCK_KEY
                )
        finally:
            await pool.release(conn)

    async def init_db(self):
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute('''CREATE TABLE IF NOT EXISTS nodes (
                node_id TEXT PRIMARY KEY,
                payload_json JSONB NOT NULL,
                content_hash TEXT,
                commitment TEXT
            )''')

            await conn.execute('''CREATE TABLE IF NOT EXISTS edges (
                child_id TEXT NOT NULL,
                parent_id TEXT NOT NULL,
                edge_class TEXT,
                PRIMARY KEY (child_id, parent_id)
            )''')

            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_edges_parent_id ON edges(parent_id)")

            await conn.execute('''CREATE TABLE IF NOT EXISTS quarantine_ledger (
                node_id TEXT PRIMARY KEY
            )''')

            await conn.execute('''CREATE TABLE IF NOT EXISTS quarantine_events (
                event_id TEXT PRIMARY KEY,
                event_json JSONB NOT NULL
            )''')

            await conn.execute('''CREATE TABLE IF NOT EXISTS repair_candidates (
                node_id TEXT PRIMARY KEY,
                candidate_json JSONB NOT NULL
            )''')

            await conn.execute('''CREATE TABLE IF NOT EXISTS checkpoints (
                checkpoint_id TEXT PRIMARY KEY,
                checkpoint_json JSONB NOT NULL
            )''')

            await conn.execute('''CREATE TABLE IF NOT EXISTS external_effects (
                idempotency_key TEXT PRIMARY KEY,
                node_id TEXT NOT NULL,
                effect_type TEXT NOT NULL,
                recorded_at_utc TIMESTAMPTZ NOT NULL
            )''')

            await conn.execute('''CREATE TABLE IF NOT EXISTS reintegration_horizon (
                node_id TEXT PRIMARY KEY,
                admitted_at_utc TIMESTAMPTZ NOT NULL,
                trust_expires_utc TIMESTAMPTZ NOT NULL,
                predecessor_id TEXT NOT NULL,
                renewal_count INTEGER DEFAULT 0
            )''')

            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_horizon_expiry ON reintegration_horizon(trust_expires_utc)")

            await conn.execute('''CREATE TABLE IF NOT EXISTS recurrence_events (
                event_id TEXT PRIMARY KEY,
                node_id TEXT NOT NULL,
                recurrence_class TEXT NOT NULL,
                detected_at_utc TIMESTAMPTZ NOT NULL,
                signal_source TEXT NOT NULL,
                outcome TEXT NOT NULL DEFAULT 'PROCESSED',
                event_json JSONB NOT NULL
            )''')

            await conn.execute('''CREATE TABLE IF NOT EXISTS signal_attempts (
                id SERIAL PRIMARY KEY,
                signal_source TEXT NOT NULL,
                node_id TEXT NOT NULL,
                signal_kind TEXT NOT NULL,
                outcome TEXT NOT NULL,
                recorded_at_utc TIMESTAMPTZ NOT NULL
            )''')
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_signal_attempts_source ON signal_attempts(signal_source, recorded_at_utc)")
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_signal_attempts_time ON signal_attempts(recorded_at_utc)")

            await conn.execute('''CREATE TABLE IF NOT EXISTS withdrawal_ledger (
                node_id TEXT PRIMARY KEY,
                withdrawn_at_utc TIMESTAMPTZ NOT NULL,
                triggering_event_id TEXT NOT NULL,
                withdrawal_reason TEXT NOT NULL
            )''')

            await conn.execute('''CREATE TABLE IF NOT EXISTS calibration_runs (
                run_id TEXT PRIMARY KEY,
                run_at_utc TIMESTAMPTZ NOT NULL,
                seeded_count INTEGER NOT NULL,
                detected_count INTEGER NOT NULL,
                sensitivity_floor REAL NOT NULL,
                monitored_period_json JSONB NOT NULL
            )''')

            await conn.execute('''CREATE TABLE IF NOT EXISTS shadow_decisions (
                decision_id TEXT PRIMARY KEY,
                node_id TEXT NOT NULL,
                evaluated_at_utc TIMESTAMPTZ NOT NULL,
                would_have_blocked BOOLEAN NOT NULL,
                reason TEXT,
                parent_status_json JSONB NOT NULL,
                policy_bundle_digest TEXT NOT NULL,
                writer_identity TEXT
            )''')

            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_shadow_evaluated ON shadow_decisions(evaluated_at_utc)")
            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_shadow_blocked ON shadow_decisions(would_have_blocked)")

            await conn.execute('''CREATE TABLE IF NOT EXISTS reintegration_evidence (
                node_id TEXT PRIMARY KEY,
                pre_state_digest TEXT NOT NULL,
                post_state_digest TEXT NOT NULL,
                gate_evidence_json JSONB NOT NULL,
                recorded_at_utc TIMESTAMPTZ NOT NULL
            )''')

            await conn.execute('''CREATE TABLE IF NOT EXISTS continuity_exposures (
                exposure_id TEXT PRIMARY KEY,
                node_id TEXT NOT NULL,
                substitute_status TEXT NOT NULL,
                exposed_at_utc TIMESTAMPTZ NOT NULL,
                quarantine_non_empty BOOLEAN NOT NULL DEFAULT FALSE,
                exposure_record_json JSONB NOT NULL
            )''')

            await conn.execute('''CREATE TABLE IF NOT EXISTS substitute_declarations (
                target_node_id TEXT PRIMARY KEY,
                declaration_json JSONB NOT NULL
            )''')

            await conn.execute('''CREATE TABLE IF NOT EXISTS detector_events (
                event_id TEXT PRIMARY KEY,
                event_json JSONB NOT NULL,
                received_at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )''')

            await conn.execute('''CREATE TABLE IF NOT EXISTS tainted_rejections (
                node_id TEXT NOT NULL,
                tainted_parent_id TEXT NOT NULL,
                rejected_at_utc TIMESTAMPTZ NOT NULL,
                served BOOLEAN DEFAULT FALSE,
                served_by_exposure_id TEXT,
                offered BOOLEAN DEFAULT FALSE,
                offered_replacement TEXT,
                replacement_type TEXT,
                completed BOOLEAN DEFAULT FALSE,
                completed_by TEXT
            )''')

            await conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_tainted_rejections_node_served ON tainted_rejections(node_id, served)")

    # ---- DAG ----

    async def get_dag(self) -> Dict[str, Any]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("SELECT node_id, payload_json FROM nodes")
            return {r["node_id"]: r["payload_json"] for r in rows}

    async def commit_node(self, payload: dict) -> bool:
        node_id = payload["payload_id"]
        content_hash = payload.get("content_digest_sha256", "")
        parents = payload.get("parent_dependency_commitments", [])

        sorted_deps = sorted([p["parent_node_id"] + ":" + p.get("parent_content_hash", "") for p in parents])
        commitment_input = content_hash + "".join(sorted_deps)
        commitment = hashlib.sha256(commitment_input.encode()).hexdigest()

        pool = await self._get_pool()
        async with pool.acquire() as conn:
            async with conn.transaction():
                result = await conn.execute(
                    "INSERT INTO nodes (node_id, payload_json, content_hash, commitment) "
                    "VALUES ($1, $2, $3, $4) ON CONFLICT (node_id) DO NOTHING",
                    node_id, payload, content_hash, commitment
                )
                if result == "INSERT 0 0":
                    return False

                for p in parents:
                    await conn.execute(
                        "INSERT INTO edges (child_id, parent_id, edge_class) "
                        "VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                        node_id, p["parent_node_id"], p.get("edge_class", "MATERIAL")
                    )
                return True

    async def nodes_exist(self, node_ids: List[str]) -> Dict[str, bool]:
        if not node_ids:
            return {}
        uniq = list(dict.fromkeys(node_ids))
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT node_id FROM nodes WHERE node_id = ANY($1)", uniq
            )
            found = {r["node_id"] for r in rows}
        return {nid: (nid in found) for nid in uniq}

    async def get_node_content_hashes(self, node_ids: List[str]) -> Dict[str, str]:
        """Return {node_id: content_hash} for existing nodes."""
        if not node_ids:
            return {}
        uniq = list(dict.fromkeys(node_ids))
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT node_id, content_hash FROM nodes WHERE node_id = ANY($1)", uniq
            )
        return {r["node_id"]: r["content_hash"] for r in rows}

    async def are_quarantined(self, node_ids: List[str]) -> Dict[str, bool]:
        if not node_ids:
            return {}
        uniq = list(dict.fromkeys(node_ids))
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT node_id FROM quarantine_ledger WHERE node_id = ANY($1)", uniq
            )
            found = {r["node_id"] for r in rows}
        return {nid: (nid in found) for nid in uniq}

    # ---- Quarantine ----

    async def get_quarantine_ledger(self) -> List[str]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("SELECT node_id FROM quarantine_ledger")
            return [r["node_id"] for r in rows]

    async def log_quarantine_event(self, event: dict):
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO quarantine_events (event_id, event_json) VALUES ($1, $2) "
                "ON CONFLICT (event_id) DO UPDATE SET event_json = EXCLUDED.event_json",
                event["quarantine_event_id"], event
            )

    async def add_to_quarantine_ledger(self, node_id: str):
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO quarantine_ledger (node_id) VALUES ($1) ON CONFLICT DO NOTHING",
                node_id
            )

    async def apply_quarantine_transaction(self, event: dict, c_p: List[str]):
        event["max_traversal_depth"] = self._max_traversal_depth
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute(
                    "INSERT INTO quarantine_events (event_id, event_json) VALUES ($1, $2) "
                    "ON CONFLICT (event_id) DO UPDATE SET event_json = EXCLUDED.event_json",
                    event["quarantine_event_id"], event
                )
                for node_id in c_p:
                    await conn.execute(
                        "INSERT INTO quarantine_ledger (node_id) VALUES ($1) ON CONFLICT DO NOTHING",
                        node_id
                    )

    async def get_quarantine_events(self) -> List[dict]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("SELECT event_json FROM quarantine_events")
            return [r["event_json"] for r in rows]

    # ---- Blast radius (recursive CTE) ----

    async def compute_blast_radius(self, poisoned_root_id: str) -> List[str]:
        query = """
        WITH RECURSIVE blast_radius(node_id, depth) AS (
            SELECT $1::text, 0
            UNION
            SELECT e.child_id, br.depth + 1
            FROM edges e
            JOIN blast_radius br ON e.parent_id = br.node_id
            WHERE br.depth < $2
        )
        SELECT DISTINCT node_id FROM blast_radius;
        """
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(query, poisoned_root_id, self._max_traversal_depth)
            c_p = sorted([r["node_id"] for r in rows])

            # Affected compactions
            affected_compactions = []
            if c_p:
                comp_rows = await conn.fetch(
                    "SELECT DISTINCT child_id FROM edges "
                    "WHERE parent_id = ANY($1) AND edge_class = 'CARRIED'",
                    c_p
                )
                affected_compactions = [r["child_id"] for r in comp_rows]

        dag = await self.get_dag()
        checkpoints = await self.get_checkpoints()
        semantic_rollback = await self.has_external_effects(c_p)

        pool = await self._get_pool()
        for comp_node in affected_compactions:
            # Skip nodes that already reached a terminal disposition
            existing = (await self.get_repair_candidates()).get(comp_node, {})
            if existing.get("disposition") in ("REDUCIBLE", "IRREDUCIBLE"):
                continue

            if semantic_rollback:
                await self._set_repair_candidate(comp_node, {
                    "disposition": "IRREDUCIBLE",
                    "reason": "semantic_rollback_hazard",
                    "escalation_record": "Quarantined subgraph contains irreversible external effects"
                })
                continue

            covers = dag.get(comp_node, {}).get("covers", [])

            frontier = [n for n in covers if n not in c_p]
            if not frontier:
                await self._set_repair_candidate(comp_node, {
                    "disposition": "IRREDUCIBLE",
                    "reason": "empty_frontier",
                    "escalation_record": "Requires human review"
                })
                continue

            summarizer = dag.get(comp_node, {}).get("summarizer", {})
            if summarizer.get("method_id") == "llm-v1":
                admissible_checkpoint = None
                for cp_id, cp_data in checkpoints.items():
                    if cp_data["target_node_id"] in frontier:
                        admissible_checkpoint = cp_data
                        break

                if not admissible_checkpoint:
                    await self._set_repair_candidate(comp_node, {
                        "disposition": "IRREDUCIBLE",
                        "reason": "no_admissible_checkpoint",
                        "escalation_record": "Requires human review"
                    })
                    continue

                await self._set_repair_candidate(comp_node, {
                    "disposition": "PENDING_RECONSTRUCTION",
                    "frontier": frontier,
                    "method": "verified_checkpoint_reconstruction",
                    "checkpoint": admissible_checkpoint
                })
            else:
                await self._set_repair_candidate(comp_node, {
                    "disposition": "IRREDUCIBLE",
                    "reason": "no_reconstruction_backend",
                    "escalation_record": "Unknown summarizer method"
                })

        return c_p

    async def _set_repair_candidate(self, node_id: str, data: dict):
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO repair_candidates (node_id, candidate_json) VALUES ($1, $2) "
                "ON CONFLICT (node_id) DO UPDATE SET candidate_json = EXCLUDED.candidate_json",
                node_id, data
            )

    # ---- Repair candidates ----

    async def get_repair_candidates(self) -> Dict[str, Any]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("SELECT node_id, candidate_json FROM repair_candidates")
            return {r["node_id"]: r["candidate_json"] for r in rows}

    async def update_repair_candidate(self, node_id: str, data: dict):
        await self._set_repair_candidate(node_id, data)

    # ---- Checkpoints ----

    async def add_checkpoint(self, checkpoint: dict):
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO checkpoints (checkpoint_id, checkpoint_json) VALUES ($1, $2) "
                "ON CONFLICT (checkpoint_id) DO UPDATE SET checkpoint_json = EXCLUDED.checkpoint_json",
                checkpoint["checkpoint_id"], checkpoint
            )

    async def get_checkpoints(self) -> Dict[str, dict]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("SELECT checkpoint_id, checkpoint_json FROM checkpoints")
            return {r["checkpoint_id"]: r["checkpoint_json"] for r in rows}

    # ---- External effects ----

    async def add_external_effect(self, idempotency_key: str, node_id: str, effect_type: str):
        now = datetime.now(timezone.utc)
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO external_effects (idempotency_key, node_id, effect_type, recorded_at_utc) "
                "VALUES ($1, $2, $3, $4) "
                "ON CONFLICT (idempotency_key) DO UPDATE SET node_id = EXCLUDED.node_id",
                idempotency_key, node_id, effect_type, now
            )

    async def check_external_effect(self, idempotency_key: str) -> bool:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT 1 FROM external_effects WHERE idempotency_key = $1", idempotency_key
            )
            return row is not None

    async def has_external_effects(self, node_ids: List[str]) -> bool:
        if not node_ids:
            return False
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT 1 FROM external_effects WHERE node_id = ANY($1) LIMIT 1", node_ids
            )
            return row is not None

    # ---- Reintegration evidence (REQ-007) ----

    async def record_reintegration_evidence(self, node_id: str, pre_digest: str, post_digest: str, gate_evidence: list):
        """Record pre/post state digests and gate execution evidence for REQ-007."""
        now = datetime.now(timezone.utc)
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO reintegration_evidence (node_id, pre_state_digest, post_state_digest, gate_evidence_json, recorded_at_utc) "
                "VALUES ($1, $2, $3, $4, $5) ON CONFLICT (node_id) DO UPDATE SET "
                "pre_state_digest=$2, post_state_digest=$3, gate_evidence_json=$4, recorded_at_utc=$5",
                node_id, pre_digest, post_digest, json.dumps(gate_evidence), now
            )

    async def compute_state_digest(self) -> str:
        """Compute a digest of the current DAG + quarantine state for transition records."""
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            nodes = await conn.fetch("SELECT node_id, commitment FROM nodes ORDER BY node_id")
            q_nodes = await conn.fetch("SELECT node_id FROM quarantine_ledger ORDER BY node_id")
        combined = json.dumps({"nodes": [(r["node_id"], r["commitment"]) for r in nodes], "quarantine": [r["node_id"] for r in q_nodes]}, sort_keys=True)
        return hashlib.sha256(combined.encode()).hexdigest()

    async def record_continuity_exposure(self, exposure_id: str, node_id: str, substitute_status: str, quarantine_non_empty: bool, exposure_record: dict):
        """Record a continuity exposure event for REQ-004."""
        now = datetime.now(timezone.utc)
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO continuity_exposures (exposure_id, node_id, substitute_status, exposed_at_utc, quarantine_non_empty, exposure_record_json) "
                "VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT DO NOTHING",
                exposure_id, node_id, substitute_status, now, quarantine_non_empty, json.dumps(exposure_record)
            )

    async def get_continuity_exposures(self) -> List[dict]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("SELECT exposure_id, node_id, substitute_status, exposed_at_utc, quarantine_non_empty, exposure_record_json FROM continuity_exposures ORDER BY exposed_at_utc")
            return [{"exposure_id": r["exposure_id"], "node_id": r["node_id"], "substitute_status": r["substitute_status"], "exposed_at_utc": r["exposed_at_utc"].isoformat() + "Z", "quarantine_non_empty": r["quarantine_non_empty"], "exposure_record": r["exposure_record_json"]} for r in rows]

    # ---- Reintegration horizon ----

    async def record_reintegration(self, node_id: str, predecessor_id: str, horizon_seconds: int):
        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=horizon_seconds)
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO reintegration_horizon (node_id, admitted_at_utc, trust_expires_utc, predecessor_id) "
                "VALUES ($1, $2, $3, $4) "
                "ON CONFLICT (node_id) DO UPDATE SET "
                "admitted_at_utc = EXCLUDED.admitted_at_utc, "
                "trust_expires_utc = EXCLUDED.trust_expires_utc, "
                "predecessor_id = EXCLUDED.predecessor_id",
                node_id, now, expires, predecessor_id
            )

    async def get_active_horizon_set(self) -> Dict[str, dict]:
        now = datetime.now(timezone.utc)
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT node_id, trust_expires_utc, predecessor_id, renewal_count "
                "FROM reintegration_horizon WHERE trust_expires_utc > $1", now
            )
            return {
                r["node_id"]: {
                    "trust_expires_utc": r["trust_expires_utc"].strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                    "predecessor_id": r["predecessor_id"],
                    "renewal_count": r["renewal_count"]
                } for r in rows
            }

    async def get_expired_horizon_set(self) -> List[str]:
        now = datetime.now(timezone.utc)
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT node_id FROM reintegration_horizon WHERE trust_expires_utc <= $1", now
            )
            return [r["node_id"] for r in rows]

    async def renew_trust(self, node_id: str, horizon_seconds: int):
        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=horizon_seconds)
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE reintegration_horizon SET trust_expires_utc = $1, renewal_count = renewal_count + 1 "
                "WHERE node_id = $2",
                expires, node_id
            )

    # ---- Withdrawal / recurrence ----

    async def apply_withdrawal_transaction(self, event: dict, w_r: List[str]):
        now = datetime.now(timezone.utc)
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute(
                    "INSERT INTO recurrence_events (event_id, node_id, recurrence_class, detected_at_utc, signal_source, event_json) "
                    "VALUES ($1, $2, $3, $4, $5, $6) "
                    "ON CONFLICT (event_id) DO UPDATE SET event_json = EXCLUDED.event_json",
                    event["event_id"], event["node_id"], event["recurrence_class"],
                    now, event["signal_source"], event
                )
                for i, node_id in enumerate(w_r):
                    reason = "DIRECTLY_IMPLICATED" if i == 0 else "UNEXAMINED_DEPENDENT"
                    await conn.execute(
                        "INSERT INTO withdrawal_ledger (node_id, withdrawn_at_utc, triggering_event_id, withdrawal_reason) "
                        "VALUES ($1, $2, $3, $4) ON CONFLICT (node_id) DO NOTHING",
                        node_id, now, event["event_id"], reason
                    )

    async def get_withdrawal_ledger(self) -> Dict[str, dict]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT node_id, withdrawn_at_utc, triggering_event_id, withdrawal_reason FROM withdrawal_ledger"
            )
            return {
                r["node_id"]: {
                    "withdrawn_at_utc": r["withdrawn_at_utc"].strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                    "triggering_event_id": r["triggering_event_id"],
                    "withdrawal_reason": r["withdrawal_reason"]
                } for r in rows
            }

    # ---- Calibration ----

    async def record_calibration_run(self, run: dict):
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO calibration_runs (run_id, run_at_utc, seeded_count, detected_count, sensitivity_floor, monitored_period_json) "
                "VALUES ($1, $2, $3, $4, $5, $6) "
                "ON CONFLICT (run_id) DO UPDATE SET run_at_utc = EXCLUDED.run_at_utc",
                run["run_id"], _parse_utc(run["run_at_utc"]),
                run["seeded_count"], run["detected_count"], run["sensitivity_floor"],
                run["monitored_period"]
            )

    async def get_calibration_runs(self) -> List[dict]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT run_id, run_at_utc, seeded_count, detected_count, sensitivity_floor, monitored_period_json "
                "FROM calibration_runs"
            )
            return [{
                "run_id": r["run_id"],
                "run_at_utc": r["run_at_utc"].strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "seeded_count": r["seeded_count"],
                "detected_count": r["detected_count"],
                "sensitivity_floor": r["sensitivity_floor"],
                "monitored_period": r["monitored_period_json"]
            } for r in rows]

    # ---- Rate limiting (signal attempts) ----

    async def record_signal_attempt(self, signal_source: str, node_id: str,
                                    signal_kind: str, outcome: str) -> None:
        now = datetime.now(timezone.utc)
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO signal_attempts (signal_source, node_id, signal_kind, outcome, recorded_at_utc) "
                "VALUES ($1, $2, $3, $4, $5)",
                signal_source, node_id, signal_kind, outcome, now
            )

    async def count_recent_signals(self, signal_source: str, since_utc: str) -> int:
        since = _parse_utc(since_utc)
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT COUNT(*) FROM signal_attempts WHERE signal_source = $1 AND recorded_at_utc > $2",
                signal_source, since
            )
            return row[0]

    async def count_recent_signals_global(self, since_utc: str) -> int:
        since = _parse_utc(since_utc)
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT COUNT(*) FROM signal_attempts WHERE recorded_at_utc > $1", since
            )
            return row[0]

    async def get_signal_outcome_counts(self) -> Dict[str, int]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT outcome, COUNT(*) as cnt FROM signal_attempts GROUP BY outcome"
            )
            return {r["outcome"]: r["cnt"] for r in rows}

    # ---- Shadow decisions ----

    async def record_shadow_decision(self, decision_id: str, node_id: str,
                                     evaluated_at_utc: str, would_have_blocked: bool,
                                     reason: str, parent_status_json: str,
                                     policy_bundle_digest: str, writer_identity: str):
        eval_time = _parse_utc(evaluated_at_utc)
        # parent_status_json arrives as a JSON string from callers; decode for JSONB codec
        parent_obj = json.loads(parent_status_json) if isinstance(parent_status_json, str) else parent_status_json
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO shadow_decisions "
                "(decision_id, node_id, evaluated_at_utc, would_have_blocked, reason, "
                "parent_status_json, policy_bundle_digest, writer_identity) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                decision_id, node_id, eval_time, would_have_blocked,
                reason, parent_obj, policy_bundle_digest, writer_identity
            )

    # ---- Quarantine digest ----

    async def compute_quarantine_digest(self, additional_node_ids: List[str]) -> str:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("SELECT node_id FROM quarantine_ledger")
            existing = {r["node_id"] for r in rows}
        merged = sorted(existing | set(additional_node_ids))
        return hashlib.sha256(json.dumps(merged, sort_keys=True).encode()).hexdigest()

    # ---- Covers interval gap ----

    async def compute_covers_interval_gap(self, covers: List[str]) -> List[str]:
        if not covers:
            return []
        uniq = list(dict.fromkeys(covers))
        query = """
            WITH RECURSIVE
            descendants(node_id) AS (
                SELECT node_id FROM nodes WHERE node_id = ANY($1)
                UNION
                SELECT e.child_id FROM edges e
                INNER JOIN descendants d ON e.parent_id = d.node_id
            ),
            ancestors(node_id) AS (
                SELECT node_id FROM nodes WHERE node_id = ANY($1)
                UNION
                SELECT e.parent_id FROM edges e
                INNER JOIN ancestors a ON e.child_id = a.node_id
            )
            SELECT node_id FROM descendants
            INTERSECT
            SELECT node_id FROM ancestors
            EXCEPT
            SELECT node_id FROM nodes WHERE node_id = ANY($1)
        """
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch(query, uniq)
            return sorted([r["node_id"] for r in rows])

    # ---- Substitute declarations (M3) ----

    async def add_substitute_declaration(self, declaration: dict):
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO substitute_declarations (target_node_id, declaration_json) VALUES ($1, $2) "
                "ON CONFLICT (target_node_id) DO UPDATE SET declaration_json = EXCLUDED.declaration_json",
                declaration["target_node_id"], declaration
            )

    async def get_substitute_declarations(self) -> Dict[str, dict]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("SELECT target_node_id, declaration_json FROM substitute_declarations")
            return {r["target_node_id"]: r["declaration_json"] for r in rows}

    # ---- Detector event log ----

    async def record_detector_event(self, event: dict):
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            import uuid as _uuid
            await conn.execute(
                "INSERT INTO detector_events (event_id, event_json) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                event.get("event_id", str(_uuid.uuid4())), event
            )

    async def get_detector_events(self) -> List[dict]:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            rows = await conn.fetch("SELECT event_json FROM detector_events ORDER BY received_at_utc")
            return [r["event_json"] for r in rows]

    # ---- Critical function dependency tracking ----

    async def get_critical_dependents(self, quarantined_node_ids: List[str]) -> List[dict]:
        """Find DAG nodes with criticality_weight > 0 that are in or depend on quarantined nodes."""
        if not quarantined_node_ids:
            return []
        dag = await self.get_dag()
        q_set = set(quarantined_node_ids)
        results = []
        for nid, ndata in dag.items():
            cw = ndata.get("criticality_weight", 0)
            if cw <= 0:
                continue
            parents = [p["parent_node_id"] for p in ndata.get("parent_dependency_commitments", [])]
            tainted_parents = [p for p in parents if p in q_set]
            if nid in q_set or tainted_parents:
                results.append({
                    "node_id": nid,
                    "criticality_weight": cw,
                    "tainted_parents": tainted_parents if tainted_parents else [nid],
                })
        return results

    # ---- Tainted-action tracking (B.8) ----

    async def record_tainted_rejection(self, node_id: str, parent_id: str, rejected_at_utc: str):
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO tainted_rejections (node_id, tainted_parent_id, rejected_at_utc) VALUES ($1, $2, $3)",
                node_id, parent_id, rejected_at_utc
            )

    async def record_tainted_offer(self, rejection_node_id: str, replacement_node_id: str, replacement_type: str):
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE tainted_rejections SET offered = TRUE, offered_replacement = $1, replacement_type = $2 WHERE node_id = $3 AND offered = FALSE",
                replacement_node_id, replacement_type, rejection_node_id
            )

    async def record_tainted_completion(self, rejection_node_id: str, completed_by_node_id: str):
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE tainted_rejections SET completed = TRUE, completed_by = $1 WHERE node_id = $2 AND completed = FALSE",
                completed_by_node_id, rejection_node_id
            )

    async def check_retry_completion(self, payload: dict) -> None:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            retry_of = payload.get("retry_of")
            parent_ids = [p["parent_node_id"] for p in payload.get("parent_dependency_commitments", [])]

            pending = await conn.fetch(
                "SELECT node_id, offered_replacement FROM tainted_rejections WHERE offered = TRUE AND completed = FALSE"
            )
            for row in pending:
                node_id = row["node_id"]
                offered_replacement = row["offered_replacement"]
                matched = False
                if retry_of and retry_of == node_id:
                    matched = True
                elif offered_replacement and offered_replacement in parent_ids:
                    matched = True
                if matched:
                    await conn.execute(
                        "UPDATE tainted_rejections SET completed = TRUE, completed_by = $1 WHERE node_id = $2 AND completed = FALSE",
                        payload["payload_id"], node_id
                    )
                    break

    async def get_tainted_action_stats(self) -> dict:
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            total = await conn.fetchval("SELECT COUNT(*) FROM tainted_rejections")
            offered = await conn.fetchval("SELECT COUNT(*) FROM tainted_rejections WHERE offered = TRUE")
            completed = await conn.fetchval("SELECT COUNT(*) FROM tainted_rejections WHERE completed = TRUE")
            direct_offered = await conn.fetchval("SELECT COUNT(*) FROM tainted_rejections WHERE offered = TRUE AND replacement_type = 'direct'")
            ancestor_offered = await conn.fetchval("SELECT COUNT(*) FROM tainted_rejections WHERE offered = TRUE AND replacement_type = 'ancestor'")
            direct_completed = await conn.fetchval("SELECT COUNT(*) FROM tainted_rejections WHERE completed = TRUE AND replacement_type = 'direct'")
            ancestor_completed = await conn.fetchval("SELECT COUNT(*) FROM tainted_rejections WHERE completed = TRUE AND replacement_type = 'ancestor'")
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
        quarantined ancestors."""
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            # Build quarantined ancestor chain (BFS up parent edges)
            candidates = []
            visited_set = set()
            bfs_queue = [tainted_node_id]
            while bfs_queue:
                nid = bfs_queue.pop(0)
                if nid in visited_set:
                    continue
                visited_set.add(nid)
                q_check = await conn.fetchrow(
                    "SELECT 1 FROM quarantine_ledger WHERE node_id = $1", nid
                )
                if q_check:
                    candidates.append(nid)
                    parents = await conn.fetch(
                        "SELECT parent_id FROM edges WHERE child_id = $1", nid
                    )
                    for prow in parents:
                        bfs_queue.append(prow["parent_id"])

            exposures = await conn.fetch(
                "SELECT exposure_id, node_id, exposure_record_json FROM continuity_exposures"
            )

            for candidate in candidates:
                for exp in exposures:
                    node_id = exp["node_id"]
                    row = await conn.fetchrow(
                        "SELECT payload_json FROM nodes WHERE node_id = $1", node_id
                    )
                    if row is None:
                        continue
                    state_content = row["payload_json"].get("state_content", {})
                    if state_content.get("original_target") == candidate:
                        exposure_record = exp["exposure_record_json"] or {}
                        return {
                            "replacement_node_id": node_id,
                            "replacement_for": candidate,
                            "exposure_id": exp["exposure_id"],
                            "mechanism": exposure_record.get("mechanism", "unknown"),
                        }

                # Check pre-declared substitutes
                sub_row = await conn.fetchrow(
                    "SELECT declaration_json FROM substitute_declarations WHERE target_node_id = $1",
                    candidate
                )
                if sub_row:
                    sub_decl = json.loads(sub_row["declaration_json"]) if isinstance(sub_row["declaration_json"], str) else sub_row["declaration_json"]
                    sub_source = sub_decl.get("substitute_source_id")
                    if not sub_source:
                        continue
                    exists = await conn.fetchrow(
                        "SELECT 1 FROM nodes WHERE node_id = $1", sub_source
                    )
                    quarantined = await conn.fetchrow(
                        "SELECT 1 FROM quarantine_ledger WHERE node_id = $1", sub_source
                    )
                    if exists and not quarantined:
                        return {
                            "replacement_node_id": sub_source,
                            "replacement_for": candidate,
                            "exposure_id": None,
                            "mechanism": "M3_DECLARED_SUBSTITUTE",
                        }
        return None

    # ---- Reset ----

    async def reset(self):
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute("DELETE FROM nodes")
                await conn.execute("DELETE FROM edges")
                await conn.execute("DELETE FROM quarantine_ledger")
                await conn.execute("DELETE FROM quarantine_events")
                await conn.execute("DELETE FROM repair_candidates")
                await conn.execute("DELETE FROM checkpoints")
                await conn.execute("DELETE FROM external_effects")
                await conn.execute("DELETE FROM reintegration_horizon")
                await conn.execute("DELETE FROM recurrence_events")
                await conn.execute("DELETE FROM withdrawal_ledger")
                await conn.execute("DELETE FROM calibration_runs")
                await conn.execute("DELETE FROM signal_attempts")
                await conn.execute("DELETE FROM shadow_decisions")
                await conn.execute("DELETE FROM continuity_exposures")
                await conn.execute("DELETE FROM substitute_declarations")
                await conn.execute("DELETE FROM detector_events")
                await conn.execute("DELETE FROM tainted_rejections")

        await self.commit_node({"payload_id": "clean-parent-1", "parent_dependency_commitments": []})
        pool = await self._get_pool()
        async with pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO quarantine_ledger (node_id) VALUES ($1) ON CONFLICT DO NOTHING",
                "quarantined-node-A"
            )
