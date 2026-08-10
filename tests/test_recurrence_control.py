import pytest
import asyncio
import uuid
import datetime
from fastapi.testclient import TestClient
from src.governor_service import app, backend
import json
import httpx
from tests.conftest import ECDSASigner
from unittest.mock import patch, MagicMock

@pytest.fixture(autouse=True)
async def setup_db():
    if hasattr(backend, "init_db"):
        await backend.init_db()
    await backend.reset()
    yield

def test_calibration_endpoint():
    client = TestClient(app)
    
    # Needs debug mode
    from src.config import settings
    settings.DEBUG_MODE = True
    
    import jwt
    admin_token = jwt.encode({"sub": "admin", "role": "admin"}, __import__("os").environ["JWT_PRIVATE_KEY_PEM"], algorithm="ES256")
    headers = {"Authorization": f"Bearer {admin_token}"}
    
    now = datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z"
    run_data = {
        "run_id": str(uuid.uuid4()),
        "run_at_utc": now,
        "seeded_count": 10,
        "detected_count": 8,
        "sensitivity_floor": 0.8,
        "monitored_period": {
            "start": now,
            "end": now
        }
    }
    
    res = client.post("/calibrate", json=run_data, headers=headers)
    assert res.status_code == 200
    
    # Now it should be in the DB (recurrence-report)
    res = client.get("/db-state", headers=headers)
    assert res.status_code == 200

def test_observe_endpoint_verification():
    client = TestClient(app)
    import jwt
    from src.config import settings
    
    designator_token = jwt.encode({"sub": "des", "role": "designator"}, __import__("os").environ["JWT_PRIVATE_KEY_PEM"], algorithm="ES256")
    headers = {"Authorization": f"Bearer {designator_token}"}
    
    # 1. Invalid class
    res = client.post("/observe", json={
        "node_id": "n1",
        "recurrence_class": "INVALID",
        "detected_at_utc": "2026-01-01T00:00:00Z"
    }, headers=headers)
    assert res.status_code == 400
    
    # 2. FUNCTIONAL_FAILURE works without signature
    res = client.post("/observe", json={
        "node_id": "n1",
        "recurrence_class": "FUNCTIONAL_FAILURE",
        "detected_at_utc": "2026-01-01T00:00:00Z"
    }, headers=headers)
    assert res.status_code == 200
    
    # 3. VERIFIER_CONTRADICTION needs signature
    res = client.post("/observe", json={
        "node_id": "n1",
        "recurrence_class": "VERIFIER_CONTRADICTION",
        "detected_at_utc": "2026-01-01T00:00:00Z"
    }, headers=headers)
    assert res.status_code == 403
    assert "adapter_signature required" in res.text
    
    # 4. Valid signature
    adapter_signer = ECDSASigner()
    settings.RECOVERY_ADAPTER_PUBLIC_KEY = adapter_signer.public_key_hex
    
    sig = adapter_signer.sign("n1".encode())
    res = client.post("/observe", json={
        "node_id": "n1",
        "recurrence_class": "VERIFIER_CONTRADICTION",
        "detected_at_utc": "2026-01-01T00:00:00Z",
        "adapter_signature": sig
    }, headers=headers)
    assert res.status_code == 200

