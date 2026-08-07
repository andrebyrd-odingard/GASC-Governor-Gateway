"""Phase 2C — readiness, graceful drain, and backpressure tests."""
import pytest
from fastapi.testclient import TestClient
from tests.conftest import JWT_PRIVATE_KEY_PEM
from src.governor_service import app
import jwt


def generate_admin_token():
    return jwt.encode({"sub": "admin", "role": "admin"}, JWT_PRIVATE_KEY_PEM, algorithm="ES256")


class TestReadiness:
    def test_ready_endpoint_returns_200_when_ready(self):
        """/ready returns 200 with status=ready when the service is up."""
        with TestClient(app) as client:
            response = client.get("/ready")
            assert response.status_code == 200
            assert response.json()["status"] == "ready"

    def test_ready_endpoint_returns_503_when_not_ready(self, monkeypatch):
        """/ready returns 503 when the service is not initialized."""
        with TestClient(app) as client:
            monkeypatch.setattr("src.governor_service._ready", False)
            response = client.get("/ready")
            assert response.status_code == 503


class TestBackpressure:
    def test_backpressure_rejects_when_inflight_limit_reached(self, monkeypatch):
        """When in-flight requests exceed MAX_IN_FLIGHT_REQUESTS, new requests get 429."""
        from src.config import settings
        from src import governor_service

        monkeypatch.setattr(settings, "MAX_IN_FLIGHT_REQUESTS", 1)
        with TestClient(app) as client:
            monkeypatch.setattr(governor_service, "_in_flight", 1)
            try:
                # /ready is exempt from backpressure counting
                response = client.get("/ready")
                assert response.status_code == 200

                # Any non-probe path should be rejected
                response = client.get(
                    "/db-state",
                    headers={"Authorization": f"Bearer {generate_admin_token()}"}
                )
                assert response.status_code == 429
                assert "Retry-After" in response.headers
            finally:
                monkeypatch.setattr(governor_service, "_in_flight", 0)


class TestGracefulDrain:
    def test_drain_returns_503_for_new_requests(self, monkeypatch):
        """Once shutdown starts, new non-probe requests receive 503."""
        import asyncio
        from src import governor_service

        with TestClient(app) as client:
            drain = asyncio.Event()
            drain.set()
            monkeypatch.setattr(governor_service, "_drain_event", drain)
            response = client.get(
                "/db-state",
                headers={"Authorization": f"Bearer {generate_admin_token()}"}
            )
            assert response.status_code == 503
            assert "Retry-After" in response.headers
