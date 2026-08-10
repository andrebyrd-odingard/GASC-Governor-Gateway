import os
from cryptography.hazmat.primitives.asymmetric import ec, utils as asy_utils
from cryptography.hazmat.primitives import hashes, serialization

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


_POSTGRES_TEST_DSN = os.environ.get("POSTGRES_TEST_DSN", "")

def _backend_params():
    params = ["memory", "sqlite"]
    if _POSTGRES_TEST_DSN:
        params.append("postgres")
    return params


@pytest.fixture(params=_backend_params(), autouse=True)
def backend_setup(request, monkeypatch, tmp_path):
    if request.param == "memory":
        from src.governor_service import MemoryStateBackend
        test_backend = MemoryStateBackend()
    elif request.param == "postgres":
        from src.postgres_backend import PostgresStateBackend
        test_backend = PostgresStateBackend(dsn=_POSTGRES_TEST_DSN)

        async def _init_and_reset():
            await test_backend.init_db()
            await test_backend.reset()
            await test_backend.close()

        def _init_pg():
            asyncio.run(_init_and_reset())
            test_backend._pool = None

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            import threading
            t = threading.Thread(target=_init_pg)
            t.start()
            t.join()
        else:
            _init_pg()

        def _teardown():
            if test_backend._pool is not None:
                try:
                    test_backend._pool.terminate()
                except Exception:
                    pass
                test_backend._pool = None
        request.addfinalizer(_teardown)
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
    # Reset readiness/drain state so tests that use a bare TestClient(app)
    # (which does not trigger lifespan) start from a known-good state.
    src.governor_service._ready = True
    src.governor_service._drain_event.clear()
    src.governor_service._in_flight = 0

from src.config import settings
settings.ENFORCEMENT_MODE = 'enforce'


# --- Signing helper: single source of truth for ECDSA-P256-SHA256 ---
# Every test that produces a signature imports this. The library default
# can never leak back in because no test imports ecdsa directly.

class ECDSASigner:
    """ECDSA-P256-SHA256 signer. Raw r||s hex output, 64-byte uncompressed public key hex."""

    def __init__(self, private_key=None):
        self._private_key = private_key or ec.generate_private_key(ec.SECP256R1())
        pub = self._private_key.public_key().public_numbers()
        self.public_key_hex = (
            pub.x.to_bytes(32, "big") + pub.y.to_bytes(32, "big")
        ).hex()

    def sign(self, message: bytes) -> str:
        """Sign message bytes with ECDSA-P256-SHA256, return raw r||s hex."""
        der = self._private_key.sign(message, ec.ECDSA(hashes.SHA256()))
        r, s = asy_utils.decode_dss_signature(der)
        return (r.to_bytes(32, "big") + s.to_bytes(32, "big")).hex()
