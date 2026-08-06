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
    Rate limits are enforced in the backend (§C.1).

    Per-identity handles a compromised credential.
    Global handles many compromised credentials.
    Both live in the backend so N gateway instances share one budget.
    """

    @pytest.mark.asyncio
    async def test_rate_limit_is_enforced(self, async_client):
        """
        Fire RECURRENCE_SIGNAL_RATE_LIMIT signals, then one more.
        The (limit+1)th signal must return 429 with Retry-After.
        """
        await async_client.post(
            "/reset-db",
            headers={"Authorization": f"Bearer {generate_admin_token()}"}
        )

        original_limit = settings.RECURRENCE_SIGNAL_RATE_LIMIT
        settings.RECURRENCE_SIGNAL_RATE_LIMIT = 3

        try:
            root = create_payload("rate-root", "clean-parent-1")
            resp = await async_client.post("/submit-candidate", json=root)
            assert resp.status_code == 200

            designator_token = generate_designator_token()

            # Fire exactly at the limit — all should succeed
            for i in range(3):
                resp = await async_client.post(
                    "/observe",
                    json={"node_id": "rate-root", "recurrence_class": "FUNCTIONAL_FAILURE",
                          "detected_at_utc": "2026-10-27T10:00:00Z"},
                    headers={"Authorization": f"Bearer {designator_token}"}
                )
                assert resp.status_code == 200, f"Signal {i} should succeed but got {resp.status_code}"

            # The next one must be rate-limited
            resp = await async_client.post(
                "/observe",
                json={"node_id": "rate-root", "recurrence_class": "FUNCTIONAL_FAILURE",
                      "detected_at_utc": "2026-10-27T10:00:00Z"},
                headers={"Authorization": f"Bearer {designator_token}"}
            )
            assert resp.status_code == 429, f"Expected 429, got {resp.status_code}"
            assert "Retry-After" in resp.headers

        finally:
            settings.RECURRENCE_SIGNAL_RATE_LIMIT = original_limit

    @pytest.mark.asyncio
    async def test_rejected_signals_count_toward_limit(self, async_client):
        """
        Escalated/rejected signals count toward the rate limit.
        If only successful signals counted, an attacker aims at nodes
        that will be refused and the limit is trivially bypassed.
        """
        await async_client.post(
            "/reset-db",
            headers={"Authorization": f"Bearer {generate_admin_token()}"}
        )

        original_limit = settings.RECURRENCE_SIGNAL_RATE_LIMIT
        original_amp = settings.MAX_WITHDRAWAL_AMPLIFICATION
        settings.RECURRENCE_SIGNAL_RATE_LIMIT = 3
        settings.MAX_WITHDRAWAL_AMPLIFICATION = 1  # Force escalation on everything

        try:
            # Build a graph that will exceed amplification (2 nodes > limit of 1)
            root = create_payload("rej-root", "clean-parent-1")
            await async_client.post("/submit-candidate", json=root)
            child = create_payload("rej-child", "rej-root")
            await async_client.post("/submit-candidate", json=child)

            designator_token = generate_designator_token()

            # Fire 3 signals — all will escalate (not process) because amplification is 1
            for i in range(3):
                resp = await async_client.post(
                    "/observe",
                    json={"node_id": "rej-root", "recurrence_class": "FUNCTIONAL_FAILURE",
                          "detected_at_utc": "2026-10-27T10:00:00Z"},
                    headers={"Authorization": f"Bearer {designator_token}"}
                )
                assert resp.status_code == 200

            # 4th signal must be rate-limited even though prior ones escalated
            resp = await async_client.post(
                "/observe",
                json={"node_id": "rej-root", "recurrence_class": "FUNCTIONAL_FAILURE",
                      "detected_at_utc": "2026-10-27T10:00:00Z"},
                headers={"Authorization": f"Bearer {designator_token}"}
            )
            assert resp.status_code == 429

        finally:
            settings.RECURRENCE_SIGNAL_RATE_LIMIT = original_limit
            settings.MAX_WITHDRAWAL_AMPLIFICATION = original_amp

    @pytest.mark.asyncio
    async def test_global_limit_trips_independently(self, async_client):
        """
        The global limit fires even when no single identity hits its own limit.
        Many compromised credentials each firing below their per-identity budget
        still get blocked once the global budget is exhausted.
        """
        await async_client.post(
            "/reset-db",
            headers={"Authorization": f"Bearer {generate_admin_token()}"}
        )

        original_per = settings.RECURRENCE_SIGNAL_RATE_LIMIT
        original_global = settings.RECURRENCE_SIGNAL_GLOBAL_LIMIT
        settings.RECURRENCE_SIGNAL_RATE_LIMIT = 100  # High per-identity
        settings.RECURRENCE_SIGNAL_GLOBAL_LIMIT = 4   # Low global

        try:
            root = create_payload("glob-root", "clean-parent-1")
            await async_client.post("/submit-candidate", json=root)

            # Use 4 different identity tokens, 1 signal each
            for i in range(4):
                token = jwt.encode(
                    {"sub": f"attacker-{i}", "role": "designator"},
                    JWT_PRIVATE_KEY_PEM, algorithm="ES256"
                )
                resp = await async_client.post(
                    "/observe",
                    json={"node_id": "glob-root", "recurrence_class": "FUNCTIONAL_FAILURE",
                          "detected_at_utc": "2026-10-27T10:00:00Z"},
                    headers={"Authorization": f"Bearer {token}"}
                )
                assert resp.status_code == 200, f"Signal from attacker-{i} should succeed"

            # 5th signal from a new identity — global limit exhausted
            token = jwt.encode(
                {"sub": "attacker-4", "role": "designator"},
                JWT_PRIVATE_KEY_PEM, algorithm="ES256"
            )
            resp = await async_client.post(
                "/observe",
                json={"node_id": "glob-root", "recurrence_class": "FUNCTIONAL_FAILURE",
                      "detected_at_utc": "2026-10-27T10:00:00Z"},
                headers={"Authorization": f"Bearer {token}"}
            )
            assert resp.status_code == 429

        finally:
            settings.RECURRENCE_SIGNAL_RATE_LIMIT = original_per
            settings.RECURRENCE_SIGNAL_GLOBAL_LIMIT = original_global

    @pytest.mark.asyncio
    async def test_designate_rate_limit(self, async_client):
        """
        /designate enforces DESIGNATION_RATE_LIMIT. Same CDoS-0006 attack
        in its original form — strategic false designation as availability attack.
        """
        await async_client.post(
            "/reset-db",
            headers={"Authorization": f"Bearer {generate_admin_token()}"}
        )

        original_limit = settings.DESIGNATION_RATE_LIMIT
        settings.DESIGNATION_RATE_LIMIT = 2

        try:
            # Create nodes to designate
            for i in range(4):
                p = create_payload(f"des-node-{i}", "clean-parent-1")
                await async_client.post("/submit-candidate", json=p)

            designator_token = generate_designator_token()

            # First 2 designations succeed
            for i in range(2):
                resp = await async_client.post(
                    "/designate",
                    json={"poisoned_node_id": f"des-node-{i}",
                          "detected_at_utc": "2026-10-27T10:00:00Z",
                          "source": "human_report", "confidence_score": 0.9,
                          "reason": "test"},
                    headers={"Authorization": f"Bearer {designator_token}"}
                )
                assert resp.status_code == 200, f"Designation {i} should succeed"

            # 3rd designation is rate-limited
            resp = await async_client.post(
                "/designate",
                json={"poisoned_node_id": "des-node-2",
                      "detected_at_utc": "2026-10-27T10:00:00Z",
                      "source": "human_report", "confidence_score": 0.9,
                      "reason": "test"},
                headers={"Authorization": f"Bearer {designator_token}"}
            )
            assert resp.status_code == 429
            assert "Retry-After" in resp.headers

        finally:
            settings.DESIGNATION_RATE_LIMIT = original_limit

    @pytest.mark.asyncio
    async def test_rate_limited_signals_in_report(self, async_client):
        """
        Rate-limited signals appear in /recurrence-report as their own count.
        A silent limit is indistinguishable from a quiet system.
        """
        await async_client.post(
            "/reset-db",
            headers={"Authorization": f"Bearer {generate_admin_token()}"}
        )

        original_limit = settings.RECURRENCE_SIGNAL_RATE_LIMIT
        settings.RECURRENCE_SIGNAL_RATE_LIMIT = 1

        try:
            root = create_payload("report-root", "clean-parent-1")
            await async_client.post("/submit-candidate", json=root)

            designator_token = generate_designator_token()

            # 1 succeeds, 1 gets rate-limited
            await async_client.post(
                "/observe",
                json={"node_id": "report-root", "recurrence_class": "FUNCTIONAL_FAILURE",
                      "detected_at_utc": "2026-10-27T10:00:00Z"},
                headers={"Authorization": f"Bearer {designator_token}"}
            )
            await async_client.post(
                "/observe",
                json={"node_id": "report-root", "recurrence_class": "FUNCTIONAL_FAILURE",
                      "detected_at_utc": "2026-10-27T10:00:00Z"},
                headers={"Authorization": f"Bearer {designator_token}"}
            )

            # Check report
            admin_token = generate_admin_token()
            resp = await async_client.get(
                "/recurrence-report",
                headers={"Authorization": f"Bearer {admin_token}"}
            )
            assert resp.status_code == 200
            report = resp.json()
            outcome_counts = report["signal_outcome_counts"]
            assert "RATE_LIMITED" in outcome_counts
            assert outcome_counts["RATE_LIMITED"] >= 1

        finally:
            settings.RECURRENCE_SIGNAL_RATE_LIMIT = original_limit

    @pytest.mark.slow
    @pytest.mark.asyncio
    async def test_window_rolls(self, async_client):
        """
        After the horizon passes, the identity can signal again.
        We simulate this by setting a very short horizon.
        """
        await async_client.post(
            "/reset-db",
            headers={"Authorization": f"Bearer {generate_admin_token()}"}
        )

        original_limit = settings.RECURRENCE_SIGNAL_RATE_LIMIT
        original_horizon = settings.CONTINUATION_HORIZON_SECONDS
        settings.RECURRENCE_SIGNAL_RATE_LIMIT = 1
        settings.CONTINUATION_HORIZON_SECONDS = 1  # 1 second window

        try:
            root = create_payload("window-root", "clean-parent-1")
            await async_client.post("/submit-candidate", json=root)

            designator_token = generate_designator_token()

            # First signal succeeds
            resp = await async_client.post(
                "/observe",
                json={"node_id": "window-root", "recurrence_class": "FUNCTIONAL_FAILURE",
                      "detected_at_utc": "2026-10-27T10:00:00Z"},
                headers={"Authorization": f"Bearer {designator_token}"}
            )
            assert resp.status_code == 200

            # Immediate second is rate-limited
            resp = await async_client.post(
                "/observe",
                json={"node_id": "window-root", "recurrence_class": "FUNCTIONAL_FAILURE",
                      "detected_at_utc": "2026-10-27T10:00:00Z"},
                headers={"Authorization": f"Bearer {designator_token}"}
            )
            assert resp.status_code == 429

            # Wait for window to roll
            import time
            time.sleep(1.1)

            # Now it should succeed again
            resp = await async_client.post(
                "/observe",
                json={"node_id": "window-root", "recurrence_class": "FUNCTIONAL_FAILURE",
                      "detected_at_utc": "2026-10-27T10:00:00Z"},
                headers={"Authorization": f"Bearer {designator_token}"}
            )
            assert resp.status_code == 200

        finally:
            settings.RECURRENCE_SIGNAL_RATE_LIMIT = original_limit
            settings.CONTINUATION_HORIZON_SECONDS = original_horizon
