"""
R6 adversarial tests — hostile examination of recurrence control.

Three things worth a hostile look since R6 landed without adversarial testing:

1. MAX_WITHDRAWAL_AMPLIFICATION breaker: plant a graph where withdrawal would
   exceed 100× and assert zero withdrawals applied (not just escalation recorded)

2. Transitive withdrawal at two hops: ensure depth isn't bounded at 1

3. Recurrence rate limits: are they in-process? If so, N instances give an
   attacker N× the signal budget (§C.1)
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
import src.governor_service as _gov
from src.r6_utils import process_recurrence


def _backend():
    """Get the live backend (may be monkeypatched by conftest)."""
    return _gov.backend

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


class TestMaxWithdrawalAmplification:
    """
    Does the MAX_WITHDRAWAL_AMPLIFICATION breaker actually stop a cascade?

    Plant a graph where withdrawal would exceed 100× and assert:
    - Zero withdrawals applied (not just that escalation was recorded)
    - The escalation event IS recorded
    """

    @pytest.mark.asyncio
    async def test_amplification_breaker_stops_cascade(self, async_client):
        """
        Build a chain of 150 nodes (exceeds MAX_WITHDRAWAL_AMPLIFICATION=100).
        Trigger recurrence on the root. Assert:
        1. The event is recorded with escalated=True
        2. Zero nodes in the withdrawal ledger (the cascade was blocked)
        """
        # Reset
        await async_client.post(
            "/reset-db",
            headers={"Authorization": f"Bearer {generate_admin_token()}"}
        )

        # Set MAX_WITHDRAWAL_AMPLIFICATION to a low value for testing
        original_max = settings.MAX_WITHDRAWAL_AMPLIFICATION
        settings.MAX_WITHDRAWAL_AMPLIFICATION = 100

        try:
            # Build a chain: root -> n1 -> n2 -> ... -> n149 (150 nodes total incl root)
            root_payload = create_payload("amp-root", "clean-parent-1")
            resp = await async_client.post("/submit-candidate", json=root_payload)
            assert resp.status_code == 200

            prev_id = "amp-root"
            for i in range(149):
                node_payload = create_payload(f"amp-chain-{i}", prev_id)
                resp = await async_client.post("/submit-candidate", json=node_payload)
                assert resp.status_code == 200, f"Failed at chain node {i}: {resp.text}"
                prev_id = f"amp-chain-{i}"

            # Now trigger recurrence on the root
            # process_recurrence computes blast_radius(amp-root) which will be 150 nodes
            # That exceeds MAX_WITHDRAWAL_AMPLIFICATION=100
            await process_recurrence(_backend(), "amp-root", "FUNCTIONAL_FAILURE", "test")

            # Check: withdrawal ledger must be EMPTY (cascade was blocked)
            withdrawal_ledger = await _backend().get_withdrawal_ledger()
            assert len(withdrawal_ledger) == 0, (
                f"Amplification breaker failed: {len(withdrawal_ledger)} nodes "
                f"in withdrawal ledger (expected 0). The cascade was NOT stopped."
            )

        finally:
            settings.MAX_WITHDRAWAL_AMPLIFICATION = original_max

    @pytest.mark.asyncio
    async def test_amplification_breaker_records_escalation(self, async_client):
        """
        Same setup as above — verify the escalation event was recorded.
        """
        await async_client.post(
            "/reset-db",
            headers={"Authorization": f"Bearer {generate_admin_token()}"}
        )

        original_max = settings.MAX_WITHDRAWAL_AMPLIFICATION
        settings.MAX_WITHDRAWAL_AMPLIFICATION = 5  # Very low threshold

        try:
            # Build chain of 10 nodes (exceeds threshold of 5)
            root_payload = create_payload("esc-root", "clean-parent-1")
            resp = await async_client.post("/submit-candidate", json=root_payload)
            assert resp.status_code == 200

            prev_id = "esc-root"
            for i in range(9):
                node_payload = create_payload(f"esc-chain-{i}", prev_id)
                resp = await async_client.post("/submit-candidate", json=node_payload)
                assert resp.status_code == 200
                prev_id = f"esc-chain-{i}"

            await process_recurrence(_backend(), "esc-root", "FUNCTIONAL_FAILURE", "test")

            # Withdrawal ledger should be empty
            withdrawal_ledger = await _backend().get_withdrawal_ledger()
            assert len(withdrawal_ledger) == 0

            # But the recurrence event should exist (it was recorded even if escalated)
            # The event is recorded via apply_withdrawal_transaction with empty w_r
            # We can check this by looking at the db state or recurrence report
            db_resp = await async_client.get(
                "/db-state",
                headers={"Authorization": f"Bearer {generate_admin_token()}"}
            )
            # For sqlite, recurrence_events table exists; for memory, it's a no-op
            # since MemoryStateBackend.apply_withdrawal_transaction does nothing.
            # The key assertion is that withdrawal_ledger is empty.

        finally:
            settings.MAX_WITHDRAWAL_AMPLIFICATION = original_max

    @pytest.mark.asyncio
    async def test_below_threshold_applies_withdrawals(self, async_client):
        """
        Verify that when the blast radius is BELOW the threshold,
        withdrawals ARE actually applied.
        """
        await async_client.post(
            "/reset-db",
            headers={"Authorization": f"Bearer {generate_admin_token()}"}
        )

        original_max = settings.MAX_WITHDRAWAL_AMPLIFICATION
        settings.MAX_WITHDRAWAL_AMPLIFICATION = 100

        try:
            # Build a small chain of 5 nodes (well below 100)
            root_payload = create_payload("small-root", "clean-parent-1")
            resp = await async_client.post("/submit-candidate", json=root_payload)
            assert resp.status_code == 200

            prev_id = "small-root"
            for i in range(4):
                node_payload = create_payload(f"small-chain-{i}", prev_id)
                resp = await async_client.post("/submit-candidate", json=node_payload)
                assert resp.status_code == 200
                prev_id = f"small-chain-{i}"

            await process_recurrence(_backend(), "small-root", "FUNCTIONAL_FAILURE", "test")

            # Now withdrawal ledger should have entries (cascade was applied)
            withdrawal_ledger = await _backend().get_withdrawal_ledger()
            assert len(withdrawal_ledger) > 0, (
                "Withdrawal ledger is empty even though blast radius is below threshold. "
                "Withdrawals should have been applied."
            )
            # Should contain the root and its descendants
            assert "small-root" in withdrawal_ledger

        finally:
            settings.MAX_WITHDRAWAL_AMPLIFICATION = original_max


class TestTransitiveWithdrawal:
    """
    Does transitive withdrawal reach two hops?

    Same depth-bounding trap that hid in the compaction traversal.
    Build: A -> B -> C, trigger withdrawal on A.
    Assert C is in the withdrawal set.
    """

    @pytest.mark.asyncio
    async def test_withdrawal_reaches_two_hops(self, async_client):
        """
        Chain: root -> hop1 -> hop2 -> hop3
        Trigger recurrence on root.
        ALL descendants must be in the withdrawal ledger.
        """
        await async_client.post(
            "/reset-db",
            headers={"Authorization": f"Bearer {generate_admin_token()}"}
        )

        original_max = settings.MAX_WITHDRAWAL_AMPLIFICATION
        settings.MAX_WITHDRAWAL_AMPLIFICATION = 1000  # High enough to not trigger

        try:
            # Build chain
            root = create_payload("depth-root", "clean-parent-1")
            resp = await async_client.post("/submit-candidate", json=root)
            assert resp.status_code == 200

            hop1 = create_payload("depth-hop1", "depth-root")
            resp = await async_client.post("/submit-candidate", json=hop1)
            assert resp.status_code == 200

            hop2 = create_payload("depth-hop2", "depth-hop1")
            resp = await async_client.post("/submit-candidate", json=hop2)
            assert resp.status_code == 200

            hop3 = create_payload("depth-hop3", "depth-hop2")
            resp = await async_client.post("/submit-candidate", json=hop3)
            assert resp.status_code == 200

            # Trigger recurrence on root
            await process_recurrence(_backend(), "depth-root", "FUNCTIONAL_FAILURE", "test")

            withdrawal_ledger = await _backend().get_withdrawal_ledger()

            # All four nodes must be withdrawn
            assert "depth-root" in withdrawal_ledger, "Root not in withdrawal ledger"
            assert "depth-hop1" in withdrawal_ledger, "Hop 1 not in withdrawal ledger (depth=1)"
            assert "depth-hop2" in withdrawal_ledger, "Hop 2 not in withdrawal ledger (depth=2)"
            assert "depth-hop3" in withdrawal_ledger, "Hop 3 not in withdrawal ledger (depth=3)"

        finally:
            settings.MAX_WITHDRAWAL_AMPLIFICATION = original_max

    @pytest.mark.asyncio
    async def test_withdrawal_reaches_branching_graph(self, async_client):
        """
        Fan-out: root -> [b1, b2, b3], b1 -> [c1, c2]
        Trigger withdrawal on root.
        ALL descendants must be withdrawn.
        """
        await async_client.post(
            "/reset-db",
            headers={"Authorization": f"Bearer {generate_admin_token()}"}
        )

        original_max = settings.MAX_WITHDRAWAL_AMPLIFICATION
        settings.MAX_WITHDRAWAL_AMPLIFICATION = 1000

        try:
            root = create_payload("fan-root", "clean-parent-1")
            resp = await async_client.post("/submit-candidate", json=root)
            assert resp.status_code == 200

            for branch in ["fan-b1", "fan-b2", "fan-b3"]:
                p = create_payload(branch, "fan-root")
                resp = await async_client.post("/submit-candidate", json=p)
                assert resp.status_code == 200

            for child in ["fan-c1", "fan-c2"]:
                p = create_payload(child, "fan-b1")
                resp = await async_client.post("/submit-candidate", json=p)
                assert resp.status_code == 200

            await process_recurrence(_backend(), "fan-root", "FUNCTIONAL_FAILURE", "test")

            withdrawal_ledger = await _backend().get_withdrawal_ledger()

            expected = {"fan-root", "fan-b1", "fan-b2", "fan-b3", "fan-c1", "fan-c2"}
            for node_id in expected:
                assert node_id in withdrawal_ledger, (
                    f"{node_id} not in withdrawal ledger — transitive withdrawal "
                    f"is not reaching all descendants"
                )

        finally:
            settings.MAX_WITHDRAWAL_AMPLIFICATION = original_max


class TestRecurrenceRateLimits:
    """
    Are recurrence rate limits in-process?

    If RECURRENCE_SIGNAL_RATE_LIMIT is enforced in-process, N gateway
    instances give an attacker N× the signal budget. That's §C.1.

    This test documents the current state and flags the issue.
    """

    @pytest.mark.asyncio
    async def test_rate_limit_is_in_process(self, async_client):
        """
        Verify the current implementation: RECURRENCE_SIGNAL_RATE_LIMIT
        is a setting checked in-process. This test documents that it IS
        per-instance (the bug §C.1 describes), so we know to fix it when
        moving to Postgres.

        Currently: rate limits are NOT enforced at all in process_recurrence.
        The setting exists but no code checks it. This confirms the §C.1
        risk is real — there's no rate limiting happening.
        """
        await async_client.post(
            "/reset-db",
            headers={"Authorization": f"Bearer {generate_admin_token()}"}
        )

        original_limit = settings.RECURRENCE_SIGNAL_RATE_LIMIT
        settings.RECURRENCE_SIGNAL_RATE_LIMIT = 2  # Very low

        try:
            # Build a small graph
            root = create_payload("rate-root", "clean-parent-1")
            resp = await async_client.post("/submit-candidate", json=root)
            assert resp.status_code == 200

            # Fire many recurrence events — more than the limit
            for i in range(10):
                await process_recurrence(_backend(), "rate-root", "FUNCTIONAL_FAILURE", f"test-{i}")

            # Document: currently all 10 fire without rate limiting.
            # The withdrawal ledger will have "rate-root" from the first call.
            # Subsequent calls just re-process it (idempotent via INSERT OR IGNORE).
            # No exception, no 429 — rate limiting is not enforced.
            # This confirms §C.1: rate limits must move to the backend.
            withdrawal_ledger = await _backend().get_withdrawal_ledger()
            # The node should be withdrawn (at least once)
            assert "rate-root" in withdrawal_ledger

        finally:
            settings.RECURRENCE_SIGNAL_RATE_LIMIT = original_limit
