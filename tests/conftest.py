import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization

if "JWT_PUBLIC_KEY" not in os.environ:
    jwt_private_key = ec.generate_private_key(ec.SECP256R1())
    JWT_PUBLIC_KEY = jwt_private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    JWT_PRIVATE_KEY_PEM = jwt_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    os.environ["JWT_PUBLIC_KEY"] = JWT_PUBLIC_KEY
    # Save the private key to environ so the second load can get it!
    os.environ["JWT_PRIVATE_KEY_PEM"] = JWT_PRIVATE_KEY_PEM
else:
    JWT_PUBLIC_KEY = os.environ["JWT_PUBLIC_KEY"]
    JWT_PRIVATE_KEY_PEM = os.environ["JWT_PRIVATE_KEY_PEM"]

os.environ["DEBUG_MODE"] = "true"

import pytest
import asyncio
from pathlib import Path

_OPA_BIN = Path(__file__).parent.parent / "bin" / "opa"

def pytest_collection_modifyitems(config, items):
    if not _OPA_BIN.exists():
        skip_opa = pytest.mark.skip(
            reason="OPA binary not found — run: mkdir -p bin && "
                   "curl -L -o bin/opa https://openpolicyagent.org/downloads/latest/opa_$(uname -s | tr A-Z a-z)_$(uname -m) && "
                   "chmod +x bin/opa"
        )
        for item in items:
            item.add_marker(skip_opa)


@pytest.fixture(params=["memory", "sqlite"], autouse=True)
def backend_setup(request, monkeypatch, tmp_path):
    if request.param == "memory":
        from src.governor_service import MemoryStateBackend; test_backend = MemoryStateBackend()
    else:
        from src.sqlite_backend import SqliteStateBackend
        db_path = str(tmp_path / "test_state.db")
        test_backend = SqliteStateBackend(db_path=db_path)
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            import threading
            def run_init():
                asyncio.run(test_backend.init_db())
            t = threading.Thread(target=run_init)
            t.start()
            t.join()
        else:
            asyncio.run(test_backend.init_db())
            
    import src.governor_service
    monkeypatch.setattr(src.governor_service, "backend", test_backend)
    # Reset the admission lock for each test to avoid event-loop binding issues
    from src.governor_service import _AdmissionLock
    monkeypatch.setattr(src.governor_service, "_admission_lock", _AdmissionLock())

from src.config import settings
settings.ENFORCEMENT_MODE = 'enforce'
