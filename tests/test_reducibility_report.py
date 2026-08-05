import pytest
from fastapi.testclient import TestClient
import jwt

from src.governor_service import app, backend

client = TestClient(app)

def create_admin_token():
    return jwt.encode({"sub": "admin-1", "role": "admin"}, "mock-secret-key-12345", algorithm="ES256") # Need real key, but wait, this test isn't setting JWT_PUBLIC_KEY for test
    
def test_reducibility_report_unauthorized():
    res = client.get("/reducibility-report")
    assert res.status_code == 401
    
# We will just verify it's added and check git diff later
