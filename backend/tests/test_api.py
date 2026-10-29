import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.database.session import Base, get_db

from sqlalchemy.pool import StaticPool

# Use an in-memory SQLite database with StaticPool so all threads/sessions share the same in-memory DB
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"
test_engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

Base.metadata.create_all(bind=test_engine)
app.dependency_overrides[get_db] = override_get_db
client = TestClient(app)

def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data

def test_analyze_valid_url():
    response = client.post("/api/analyze", json={"url": "https://www.github.com"})
    assert response.status_code == 200
    data = response.json()
    assert "scan_id" in data
    assert data["normalized_url"].startswith("https://")
    assert 0 <= data["risk_score"] <= 100
    assert data["risk_level"] in ("low", "moderate", "high", "critical")
    assert len(data["indicators"]) > 0
    assert "threat_intelligence" in data
    assert len(data["recommendations"]) > 0

def test_analyze_suspicious_url():
    response = client.post("/api/analyze", json={"url": "http://paypal-verification-update.xyz/login.php"})
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] >= 50
    assert data["risk_level"] in ("high", "critical")

def test_analyze_invalid_url_scheme():
    response = client.post("/api/analyze", json={"url": "javascript:alert(document.cookie)"})
    assert response.status_code == 422
    assert "Unsupported or dangerous" in response.json()["detail"]

def test_analyze_malformed_empty():
    response = client.post("/api/analyze", json={"url": ""})
    assert response.status_code == 422

def test_stats_and_history_lifecycle():
    # Fetch initial stats
    stats_res = client.get("/api/stats")
    assert stats_res.status_code == 200
    initial_total = stats_res.json()["total_scans"]

    # Perform a scan
    scan_res = client.post("/api/analyze", json={"url": "https://docs.python.org"})
    assert scan_res.status_code == 200
    scan_id = scan_res.json()["scan_id"]

    # Check history contains scan
    history_res = client.get("/api/history")
    assert history_res.status_code == 200
    items = history_res.json()["items"]
    assert any(i["scan_id"] == scan_id for i in items)

    # Check get by id
    detail_res = client.get(f"/api/history/{scan_id}")
    assert detail_res.status_code == 200
    assert detail_res.json()["scan_id"] == scan_id

    # Check delete
    del_res = client.delete(f"/api/history/{scan_id}")
    assert del_res.status_code == 200

    # Ensure 404 after deletion
    detail_res_after = client.get(f"/api/history/{scan_id}")
    assert detail_res_after.status_code == 404

def test_no_arbitrary_outbound_fetches_to_target():
    """
    CRITICAL SECURITY TEST: Ensure the backend NEVER performs HTTP/socket requests
    to arbitrary target URLs submitted by users (SSRF prevention).
    """
    with patch("httpx.AsyncClient.get") as mock_get, patch("urllib.request.urlopen") as mock_urlopen:
        response = client.post("/api/analyze", json={"url": "http://169.254.169.254/latest/meta-data/"})
        assert response.status_code == 200
        # Neither mock should be called with the target URL
        mock_get.assert_not_called()
        mock_urlopen.assert_not_called()
