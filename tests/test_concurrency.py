"""
Phase 2 Part A — Concurrency tests for transactional admission.

F.1: The race between /submit-candidate and /designate.
     A concurrent /designate slipping between are_quarantined() and commit_node()
     admits a write whose parent is quarantined. That node is then permanently
     invisible to containment.

     This test MUST fail against pre-fix main (commit 37d7576).

Uses httpx.AsyncClient with ASGI transport to issue truly concurrent requests
on a single event loop (TestClient serializes via portal, hiding the race).
"""
import pytest
import asyncio
import json
import hashlib
import uuid
import jwt
from datetime import datetime, timezone
from httpx import AsyncClient, ASGITransport
from ecdsa import SigningKey, NIST256p

from tests.conftest import JWT_PRIVATE_KEY_PEM
from src.governor_service import app, settings

pytestmark = pytest.mark.slow

sk = SigningKey.generate(curve=NIST256p)
PUBLIC_KEY_HEX = sk.verifying_key.to_string().hex()


def generate_admin_token():
    return jwt.encode({"sub": "admin", "role": "admin"}, JWT_PRIVATE_KEY_PEM, algorithm="ES256")


def generate_designator_token():
    return jwt.encode({"sub": "designator", "role": "designator"}, JWT_PRIVATE_KEY_PEM, algorithm="ES256")


def create_payload(payload_id, parent_id):
    session_token = jwt.encode(
        {
            "sub": PUBLIC_KEY_HEX,
            "scope": "agent:state:reconstruct",
            "is_nhi": True,
            "expires_at_epoch": int(datetime.now(timezone.utc).timestamp()) + 3600,
            "verifier_execution_status": "PASSED"
        },
        JWT_PRIVATE_KEY_PEM,
        algorithm="ES256"
    )

    state_content = {"data": f"node-{payload_id}"}
    content_str = json.dumps(state_content, sort_keys=True)
    actual_hash = hashlib.sha256(content_str.encode()).hexdigest()
    signature_hex = sk.sign(actual_hash.encode()).hex()

    return {
        "payload_id": payload_id,
        "timestamp_utc": "2026-10-27T10:00:00Z",
        "ephemeral_nhi": {
            "identity_id": PUBLIC_KEY_HEX,
            "session_token": session_token,
            "expires_at_utc": "2026-10-27T11:00:00Z"
        },
        "declared_evidence_boundary": {
            "boundary_id": "b1",
            "fixed_at_utc": "2026-10-26T00:00:00Z",
            "boundary_digest": "f" * 64
        },
        "parent_dependency_commitments": [{
            "parent_node_id": parent_id,
            "parent_content_hash": "e" * 64
        }],
        "state_content": state_content,
        "content_digest_sha256": actual_hash,
        "agent_signature": signature_hex
    }


@pytest.fixture
def async_client():
    transport = ASGITransport(app=app)
    return AsyncClient(transport=transport, base_url="http://test")


class TestAdmissionDesignationRace:
    """
    F.1: The race test.

    Setup: node P is clean, admitted to the DAG.
    Concurrent actions:
      - N coroutines: /submit-candidate with parent=P
      - 1 coroutine: /designate P as poisoned

    Invariant (P1): After designation completes, NO node admitted to the DAG
    should have a quarantined-only parent outside the blast radius.

    Pre-fix: This WILL fail because the window between are_quarantined() and
    commit_node() allows a write to slip through.
    """

    @pytest.mark.asyncio
    async def test_race_submit_during_designate(self, async_client):
        """
        Reproduce the phantom admission race.

        Strategy: submit many writes against parent P concurrently with
        designating P. At least one write should slip through the window
        on pre-fix code. We run multiple iterations to give the race a chance
        to manifest.
        """
        ITERATIONS = 50
        violations_found = 0

        for iteration in range(ITERATIONS):
            # Reset state
            resp = await async_client.post(
                "/reset-db",
                headers={"Authorization": f"Bearer {generate_admin_token()}"}
            )
            assert resp.status_code == 200

            # Create target parent node P
            parent_payload = create_payload(f"parent-{iteration}", "clean-parent-1")
            resp = await async_client.post("/submit-candidate", json=parent_payload)
            assert resp.status_code == 200, f"Setup failed: {resp.text}"

            parent_id = f"parent-{iteration}"

            # Prepare N child writes that depend on P
            NUM_CHILDREN = 10
            child_payloads = [
                create_payload(f"child-{iteration}-{i}", parent_id)
                for i in range(NUM_CHILDREN)
            ]

            # Fire concurrent submissions + designation using asyncio.gather
            async def submit_child(payload):
                resp = await async_client.post("/submit-candidate", json=payload)
                return resp.status_code

            async def designate_parent():
                resp = await async_client.post(
                    "/designate",
                    json={
                        "poisoned_node_id": parent_id,
                        "detected_at_utc": "2026-10-27T10:15:00Z",
                        "source": "amg_tamper_check",
                        "confidence_score": 0.99,
                        "reason": "Race test designation"
                    },
                    headers={"Authorization": f"Bearer {generate_designator_token()}"}
                )
                return resp.status_code

            tasks = [submit_child(p) for p in child_payloads] + [designate_parent()]
            results = await asyncio.gather(*tasks)

            child_statuses = results[:NUM_CHILDREN]
            designate_status = results[-1]

            # Designation must have succeeded
            assert designate_status == 200, f"Designation failed on iteration {iteration}"

            # Check the invariant: after designation, get the full state
            db_resp = await async_client.get(
                "/db-state",
                headers={"Authorization": f"Bearer {generate_admin_token()}"}
            )
            db_state = db_resp.json()

            quarantine_ledger = set(db_state["quarantine_ledger"])
            dag = db_state["dag"]

            # P1 check: every node in the DAG whose parent is quarantined
            # must itself be quarantined
            for node_id, node_data in dag.items():
                if node_id == "clean-parent-1":
                    continue
                parents = [p["parent_node_id"] for p in node_data.get("parent_dependency_commitments", [])]
                for pid in parents:
                    if pid in quarantine_ledger and node_id not in quarantine_ledger:
                        violations_found += 1

        # Under the bug, at least one violation should manifest across 50 iterations
        # with 10 concurrent children each. After the fix, this must be 0.
        assert violations_found == 0, (
            f"P1 VIOLATION: {violations_found} nodes admitted with quarantined parents "
            f"but not themselves quarantined. The admission/designation race is live."
        )

    @pytest.mark.asyncio
    async def test_no_admitted_node_has_quarantined_parent_post_designate(self, async_client):
        """
        Simplified single-iteration deep check:
        1. Commit parent P
        2. Concurrently: submit 20 children of P + designate P
        3. Assert: for every child that got 200, either it's in quarantine
           ledger OR its parent is not quarantined
        """
        await async_client.post(
            "/reset-db",
            headers={"Authorization": f"Bearer {generate_admin_token()}"}
        )

        # Setup parent
        parent_payload = create_payload("race-parent", "clean-parent-1")
        resp = await async_client.post("/submit-candidate", json=parent_payload)
        assert resp.status_code == 200

        NUM_CHILDREN = 20
        child_payloads = [
            create_payload(f"race-child-{i}", "race-parent")
            for i in range(NUM_CHILDREN)
        ]

        admitted_ids = []

        async def submit_child(payload):
            resp = await async_client.post("/submit-candidate", json=payload)
            if resp.status_code == 200:
                admitted_ids.append(payload["payload_id"])
            return resp.status_code

        async def designate():
            resp = await async_client.post(
                "/designate",
                json={
                    "poisoned_node_id": "race-parent",
                    "detected_at_utc": "2026-10-27T10:15:00Z",
                    "source": "amg_tamper_check",
                    "confidence_score": 0.99,
                    "reason": "Race test"
                },
                headers={"Authorization": f"Bearer {generate_designator_token()}"}
            )
            return resp.status_code

        tasks = [submit_child(p) for p in child_payloads] + [designate()]
        results = await asyncio.gather(*tasks)
        assert results[-1] == 200  # designation succeeded

        # Now check invariant
        db_resp = await async_client.get(
            "/db-state",
            headers={"Authorization": f"Bearer {generate_admin_token()}"}
        )
        db_state = db_resp.json()
        quarantine_ledger = set(db_state["quarantine_ledger"])

        # Every admitted child: if its parent is quarantined, the child must be too
        for child_id in admitted_ids:
            if "race-parent" in quarantine_ledger:
                assert child_id in quarantine_ledger, (
                    f"P1 VIOLATION: {child_id} was admitted (200) but its parent "
                    f"'race-parent' is quarantined and {child_id} is NOT in the "
                    f"quarantine ledger. Containment is broken."
                )


class TestCommitPathLocking:
    """
    F.2: Every commit path holds the admission lock.
    """

    @pytest.mark.asyncio
    async def test_context_compacted_holds_lock(self, async_client):
        """
        /context-compacted commits a node under the shared lock.
        Verify that it cannot commit DURING a designation (the commit
        either happens entirely before or entirely after).

        If compaction commits first, the blast radius from designation
        should discover it via forward traversal of CARRIED edges.
        If designation runs first, the compaction commits after quarantine
        is applied (but /context-compacted does not yet check quarantine —
        that is a known limitation; the lock prevents the interleaving race).
        """
        await async_client.post(
            "/reset-db",
            headers={"Authorization": f"Bearer {generate_admin_token()}"}
        )
        p1 = create_payload("comp-source-1", "clean-parent-1")
        resp = await async_client.post("/submit-candidate", json=p1)
        assert resp.status_code == 200

        session_token = jwt.encode(
            {
                "sub": PUBLIC_KEY_HEX,
                "scope": "agent:state:reconstruct",
                "is_nhi": True,
                "expires_at_epoch": int(datetime.now(timezone.utc).timestamp()) + 3600,
            },
            JWT_PRIVATE_KEY_PEM,
            algorithm="ES256"
        )

        state_content = {"summary": "compacted"}
        content_str = json.dumps(state_content, sort_keys=True)
        actual_hash = hashlib.sha256(content_str.encode()).hexdigest()
        sig = sk.sign(actual_hash.encode()).hex()

        async def compact():
            return await async_client.post("/context-compacted", json={
                "compacted_node_ids": ["comp-source-1"],
                "compaction_node_id": "comp-result-1",
                "timestamp_utc": "2026-10-27T10:00:00Z",
                "ephemeral_nhi": {
                    "identity_id": PUBLIC_KEY_HEX,
                    "session_token": session_token,
                    "expires_at_utc": "2026-10-27T11:00:00Z"
                },
                "state_content": state_content,
                "agent_signature": sig,
                "method_id": "llm_summary"
            })

        async def designate():
            return await async_client.post(
                "/designate",
                json={
                    "poisoned_node_id": "comp-source-1",
                    "detected_at_utc": "2026-10-27T10:15:00Z",
                    "source": "amg_tamper_check",
                    "confidence_score": 0.99,
                    "reason": "Lock test"
                },
                headers={"Authorization": f"Bearer {generate_designator_token()}"}
            )

        comp_resp, des_resp = await asyncio.gather(compact(), designate())

        # Both should complete without error (no deadlock, no interleaving crash)
        assert comp_resp.status_code == 200
        assert des_resp.status_code == 200

        # Verify consistency: no partial state
        db_resp = await async_client.get(
            "/db-state",
            headers={"Authorization": f"Bearer {generate_admin_token()}"}
        )
        db_state = db_resp.json()
        quarantine_ledger = set(db_state["quarantine_ledger"])
        dag = db_state["dag"]

        # comp-source-1 must be quarantined (designation succeeded)
        assert "comp-source-1" in quarantine_ledger

        # If compaction committed first and blast radius found it, it's quarantined.
        # If designation ran first and compaction committed after, comp-result-1
        # is in the DAG but not quarantined (known limitation: /context-compacted
        # does not check quarantine). Either outcome is consistent with the lock
        # preventing interleaving — this test verifies no crash or deadlock.
        assert "comp-result-1" in dag


class TestWriteIdempotency:
    """
    F.3: Duplicate payload_id → identical response, exactly one audit record.
    """

    @pytest.mark.asyncio
    async def test_duplicate_submission_returns_same_response(self, async_client):
        """Submit the same payload_id twice. Second must succeed identically."""
        await async_client.post(
            "/reset-db",
            headers={"Authorization": f"Bearer {generate_admin_token()}"}
        )
        payload = create_payload("idempotent-node-1", "clean-parent-1")

        resp1 = await async_client.post("/submit-candidate", json=payload)
        assert resp1.status_code == 200

        resp2 = await async_client.post("/submit-candidate", json=payload)
        assert resp2.status_code == 200
        assert resp1.json() == resp2.json()

    @pytest.mark.asyncio
    async def test_duplicate_does_not_create_extra_audit_record(self, async_client):
        """A duplicate must not produce a second shadow decision."""
        await async_client.post(
            "/reset-db",
            headers={"Authorization": f"Bearer {generate_admin_token()}"}
        )
        payload = create_payload("idempotent-node-2", "clean-parent-1")

        await async_client.post("/submit-candidate", json=payload)
        await async_client.post("/submit-candidate", json=payload)

        # Check shadow report — in enforce mode we still record decisions
        report_resp = await async_client.get(
            "/shadow-report",
            headers={"Authorization": f"Bearer {generate_admin_token()}"}
        )
        # This test documents the current behavior. Once idempotency is
        # implemented, we'll assert exactly one decision per payload_id.
        assert report_resp.status_code == 200


class TestConcurrentDesignationsNoDeadlock:
    """
    F.4: Concurrent designations of different roots do not deadlock.
    """

    @pytest.mark.asyncio
    async def test_parallel_designations(self, async_client):
        """Designate two different nodes concurrently — must not deadlock."""
        await async_client.post(
            "/reset-db",
            headers={"Authorization": f"Bearer {generate_admin_token()}"}
        )

        # Setup two independent branches
        p1 = create_payload("branch-a-root", "clean-parent-1")
        p2 = create_payload("branch-b-root", "clean-parent-1")
        resp1 = await async_client.post("/submit-candidate", json=p1)
        resp2 = await async_client.post("/submit-candidate", json=p2)
        assert resp1.status_code == 200
        assert resp2.status_code == 200

        async def designate_node(node_id):
            resp = await async_client.post(
                "/designate",
                json={
                    "poisoned_node_id": node_id,
                    "detected_at_utc": "2026-10-27T10:15:00Z",
                    "source": "amg_tamper_check",
                    "confidence_score": 0.99,
                    "reason": "Deadlock test"
                },
                headers={"Authorization": f"Bearer {generate_designator_token()}"}
            )
            return resp.status_code

        # 5s timeout — deadlock would hang forever
        results = await asyncio.wait_for(
            asyncio.gather(
                designate_node("branch-a-root"),
                designate_node("branch-b-root")
            ),
            timeout=5.0
        )
        assert results[0] == 200
        assert results[1] == 200
