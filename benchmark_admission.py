import asyncio
import time
import numpy as np
from fastapi.testclient import TestClient
from src.governor_service import app
import datetime
from unittest.mock import patch, AsyncMock
import src.governor_service as gs
from src.config import settings

client = TestClient(app)

payload = {
    "payload_id": "bench-node-1",
    "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z",
    "ephemeral_nhi": {
        "identity_id": "agent-1",
        "session_token": "mocked",
        "expires_at_utc": (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).isoformat() + "Z"
    },
    "node_type": "STANDARD",
    "declared_evidence_boundary": {
        "boundary_id": "b1",
        "fixed_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z",
        "boundary_digest": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    },
    "parent_dependency_commitments": [{"parent_node_id": "p1", "parent_content_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}],
    "content_digest_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "agent_signature": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "signature_algorithm": "ECDSA-P256-SHA256",
    "state_content": {}
}

valid_auth = {
    "is_nhi": True,
    "expires_at_epoch": int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 3600,
    "scope": "agent:state:reconstruct",
    "verifier_execution_status": "PASSED"
}

def run_bench():
    print(f"Running benchmark in ENFORCEMENT_MODE: {settings.ENFORCEMENT_MODE}")
    with patch('src.governor_service.verify_nhi_jwt', return_value=valid_auth):
        with patch('src.governor_service.verify_cryptographic_signature', return_value=True):
            with patch.object(gs.backend, 'nodes_exist', new_callable=AsyncMock) as mock_exist:
                mock_exist.return_value = {"p1": True}
                
                # Warmup
                for _ in range(10):
                    client.post("/submit-candidate", json=payload)
                
                # Benchmark
                iters = 100
                latencies = []
                for _ in range(iters):
                    start = time.time()
                    client.post("/submit-candidate", json=payload)
                    end = time.time()
                    latencies.append((end - start) * 1000)
                
                p50 = np.percentile(latencies, 50)
                p95 = np.percentile(latencies, 95)
                p99 = np.percentile(latencies, 99)
                avg = np.mean(latencies)
                
                print(f"Stats over {iters} iterations:")
                print(f"  Average: {avg:.2f} ms")
                print(f"  p50:     {p50:.2f} ms")
                print(f"  p95:     {p95:.2f} ms")
                print(f"  p99:     {p99:.2f} ms")

if __name__ == "__main__":
    run_bench()
