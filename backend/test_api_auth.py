"""Test FastAPI endpoints for auth:
- POST /api/auth/otp/send
- POST /api/auth/otp/verify
- POST /api/auth/google
- GET /api/auth/me
- POST /api/login
"""
import sys
from fastapi.testclient import TestClient

from app.database import init_db
from app.main import app

init_db()
client = TestClient(app)


def test_auth_endpoints():
    print("[TEST] Testing FastAPI auth endpoints...")

    # 1. Test OTP Send
    email = "deputy.wyatt@frontier.sec"
    resp = client.post("/api/auth/otp/send", json={"email": email})
    assert resp.status_code == 200, f"Failed OTP send: {resp.text}"
    data = resp.json()
    assert data["success"] is True
    dev_code = data.get("dev_code")
    assert dev_code and len(dev_code) == 6
    print(f"  [OK] /api/auth/otp/send success (dev_code={dev_code})")

    # 2. Test OTP Verify with correct code
    resp = client.post("/api/auth/otp/verify", json={"email": email, "code": dev_code})
    assert resp.status_code == 200, f"Failed OTP verify: {resp.text}"
    token_data = resp.json()
    assert "access_token" in token_data
    assert token_data["email"] == email
    assert token_data["auth_provider"] == "email_otp"
    jwt_token = token_data["access_token"]
    print("  [OK] /api/auth/otp/verify success, received JWT token")

    # 3. Test /api/auth/me with the JWT
    headers = {"Authorization": f"Bearer {jwt_token}"}
    resp = client.get("/api/auth/me", headers=headers)
    assert resp.status_code == 200, f"Failed /api/auth/me: {resp.text}"
    me_data = resp.json()
    assert me_data["email"] == email
    assert me_data["auth_provider"] == "email_otp"
    print(f"  [OK] /api/auth/me verified: {me_data['email']}")

    # 4. Test Google Dev Simulation Token
    google_sim = "dev-google-sim:sheriff.callahan@sentinel.sec:Sheriff Callahan"
    resp = client.post("/api/auth/google", json={"credential": google_sim})
    assert resp.status_code == 200, f"Failed Google auth: {resp.text}"
    g_data = resp.json()
    assert g_data["email"] == "sheriff.callahan@sentinel.sec"
    assert g_data["name"] == "Sheriff Callahan"
    assert g_data["auth_provider"] == "google"
    print("  [OK] /api/auth/google verified with simulation credential")

    # 5. Test Operator Password Login
    resp = client.post(
        "/api/login",
        data={"username": "demo.user@example.com", "password": "DemoPass123!"},
    )
    assert resp.status_code == 200, f"Failed demo login: {resp.text}"
    demo_data = resp.json()
    assert "access_token" in demo_data
    print("  [OK] /api/login verified for demo operator")

    # 6. Test Legacy Demo Token on /api/auth/me
    resp = client.get("/api/auth/me", headers={"Authorization": "Bearer demo-token-12345"})
    assert resp.status_code == 200, f"Failed legacy token: {resp.text}"
    print("  [OK] Legacy demo-token-12345 backwards compatibility verified")

    print("\n>>> ALL FASTAPI AUTH ENDPOINT TESTS PASSED! <<<")


if __name__ == "__main__":
    test_auth_endpoints()
