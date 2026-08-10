"""
Phase 2D — Concurrency benchmark.

Fires /submit-candidate at concurrency levels 1/10/50/100 and reports
p50/p95/p99 latencies.  The p99 at 50 concurrency is a CI gate.

This benchmark exercises the REAL admission path including OPA policy
evaluation. Only JWT and ECDSA signature verification are stubbed (they
are CPU-bound pure functions whose cost is measured separately). The OPA
evaluation, taint checks, and commit are all live.

Regression guard: asserts that evaluate_opa_policy was actually called,
preventing silent mock drift from making the benchmark meaningless.
"""
import asyncio
import os
import time
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock
import pytest
import jwt
import json
import hashlib
import numpy as np
from ecdsa import SigningKey, NIST256p
from httpx import AsyncClient, ASGITransport

from tests.conftest import JWT_PRIVATE_KEY_PEM, JWT_PUBLIC_KEY
from src.governor_service import app, backend, settings
import src.governor_service as gs


pytestmark = [pytest.mark.slow, pytest.mark.skipif(not JWT_PUBLIC_KEY, reason="JWT keys not configured")]

sk = SigningKey.generate(curve=NIST256p)
PUBLIC_KEY_HEX = sk.verifying_key.to_string().hex()


def _admin_token():
    return jwt.encode({"sub": "admin", "role": "admin"}, JWT_PRIVATE_KEY_PEM, algorithm="ES256")


def _valid_payload(seq: int):
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

    state_content = {"data": f"bench-{seq}"}
    content_str = json.dumps(state_content, sort_keys=True)
    actual_hash = hashlib.sha256(content_str.encode()).hexdigest()
    signature_hex = sk.sign(actual_hash.encode()).hex()

    return {
        "payload_id": f"bench-payload-{seq}",
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
            "parent_node_id": "clean-parent-1",
            "parent_content_hash": "e" * 64
        }],
        "state_content": state_content,
        "content_digest_sha256": actual_hash,
        "agent_signature": signature_hex
    }


async def _reset_db(client: AsyncClient):
    await client.post(
        "/reset-db",
        headers={"Authorization": f"Bearer {_admin_token()}"}
    )


async def _run_level(client: AsyncClient, concurrency: int, total: int) -> list[float]:
    """Fire `total` requests at `concurrency` parallel width and return latencies in ms."""
    sem = asyncio.Semaphore(concurrency)
    results = []

    async def one(seq):
        async with sem:
            payload = _valid_payload(seq)
            start = time.perf_counter()
            res = await client.post("/submit-candidate", json=payload)
            end = time.perf_counter()
            return (end - start) * 1000, res.status_code

    tasks = [one(i) for i in range(total)]
    collected = await asyncio.gather(*tasks)
    for ms, status in collected:
        if status != 200:
            raise AssertionError(f"Expected 200, got {status}")
        results.append(ms)
    return results


@pytest.mark.asyncio
async def test_concurrency_benchmark():
    """
    Benchmark /submit-candidate at 1/10/50/100 concurrency and gate p99@50.

    Exercises the real admission path: OPA policy evaluation (WASM if available,
    subprocess fallback otherwise), taint checks, and commit. Only JWT/ECDSA
    verification is stubbed to isolate policy+commit latency from CPU-bound crypto.
    """
    # Track whether evaluate_opa_policy was actually invoked
    opa_call_count = 0
    _original_evaluate_opa = gs.evaluate_opa_policy

    async def _counting_evaluate_opa(*args, **kwargs):
        nonlocal opa_call_count
        opa_call_count += 1
        return await _original_evaluate_opa(*args, **kwargs)

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        await _reset_db(client)

        # Stub only JWT and ECDSA — these are CPU-bound pure functions measured
        # separately. The admission decision (OPA, taint, commit) runs live.
        valid_auth = {
            "sub": PUBLIC_KEY_HEX,
            "scope": "agent:state:reconstruct",
            "is_nhi": True,
            "expires_at_epoch": int(datetime.now(timezone.utc).timestamp()) + 3600,
            "verifier_execution_status": "PASSED"
        }
        with patch('src.governor_service.verify_nhi_jwt', return_value=valid_auth):
            with patch('src.governor_service.verify_cryptographic_signature', return_value=True):
                with patch.object(gs, 'evaluate_opa_policy', side_effect=_counting_evaluate_opa):
                    levels = [1, 10, 50, 100]
                    total_per_level = 100
                    summaries = {}

                    for level in levels:
                        await _reset_db(client)
                        latencies = await _run_level(client, level, total_per_level)
                        p50 = float(np.percentile(latencies, 50))
                        p95 = float(np.percentile(latencies, 95))
                        p99 = float(np.percentile(latencies, 99))

                        summaries[level] = {
                            "p50_ms": p50,
                            "p95_ms": p95,
                            "p99_ms": p99,
                            "samples": len(latencies),
                        }

                        print(f"concurrency={level:3d}  p50={p50:.2f}ms  p95={p95:.2f}ms  p99={p99:.2f}ms")

    # Regression guard: the benchmark must have actually exercised the policy path.
    # Each admission makes at least 1 OPA call (combined) or 2 (fallback).
    # 4 levels * 100 requests = 400 minimum OPA calls.
    assert opa_call_count >= 400, (
        f"Regression guard failed: evaluate_opa_policy called only {opa_call_count} times "
        f"(expected >= 400). The benchmark is not measuring the real admission path."
    )
    print(f"\nRegression guard: evaluate_opa_policy called {opa_call_count} times (OK)")

    # CI gate: p99 at 50 concurrency must stay below threshold.
    threshold_ms = getattr(settings, "BENCHMARK_P99_50_MS", 500.0)
    p99_50 = summaries[50]["p99_ms"]
    assert p99_50 <= threshold_ms, (
        f"p99 at 50 concurrency ({p99_50:.2f} ms) exceeds {threshold_ms} ms gate"
    )
