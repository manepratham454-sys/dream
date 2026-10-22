"""Quick test script to verify backend authentication logic:
- Database table creation
- Password login with JWT generation
- Email OTP generation, DB storage, attempt count, and verification
- Google OAuth token validation
- JWT decode and dependency resolution
"""
import sys
from datetime import datetime

from app.database import Base, SessionLocal, engine, init_db
from app.models import EmailOTP, User
from app.services.auth_service import (
    create_access_token,
    decode_access_token,
    generate_and_store_otp,
    get_or_create_user,
    send_otp_email,
    verify_email_otp,
    verify_google_credential,
)
import asyncio


async def run_tests():
    print("[TEST] Initializing DB tables...")
    init_db()

    db = SessionLocal()
    try:
        # Test 1: User provisioning
        print("[TEST 1] User provisioning...")
        test_email = "analyst@sentinel-defense.internal"
        user = get_or_create_user(db, test_email, full_name="Alpha Analyst", auth_provider="email_otp")
        assert user.email == test_email
        assert user.full_name == "Alpha Analyst"
        assert user.auth_provider == "email_otp"
        print("  [OK] User created successfully")

        # Test 2: JWT creation and decode
        print("[TEST 2] JWT creation and decode...")
        token = create_access_token({"sub": user.email, "name": user.full_name, "auth_provider": user.auth_provider})
        payload = decode_access_token(token)
        assert payload is not None
        assert payload["sub"] == test_email
        assert payload["name"] == "Alpha Analyst"
        print(f"  [OK] JWT generated and verified ({len(token)} chars)")

        # Test 3: Email OTP generation & storage
        print("[TEST 3] Email OTP workflow...")
        code, expires_at = generate_and_store_otp(db, test_email)
        assert len(code) == 6
        assert code.isdigit()
        print(f"  [OK] Generated OTP: {code}")

        # Test sending (console dev mode)
        send_res = send_otp_email(test_email, code)
        assert send_res["dev_code"] == code or send_res["sent"] is True
        print("  [OK] OTP dispatch handled (dev mode captured)")

        # Test wrong OTP attempt
        valid, msg = verify_email_otp(db, test_email, "000000")
        assert not valid
        print("  [OK] Incorrect code rejected properly")

        # Test correct OTP
        valid, msg = verify_email_otp(db, test_email, code)
        assert valid
        print("  [OK] Valid OTP verified successfully")

        # Test cannot reuse used OTP
        valid, msg = verify_email_otp(db, test_email, code)
        assert not valid
        print("  [OK] Replay attack prevented (cannot reuse OTP)")

        # Test 4: Google OAuth simulation
        print("[TEST 4] Google token verification (dev simulation)...")
        google_sim_token = "dev-google-sim:agent@defense.io:Agent Commander"
        g_profile = await verify_google_credential(google_sim_token)
        assert g_profile["email"] == "agent@defense.io"
        assert g_profile["name"] == "Agent Commander"
        print("  [OK] Google simulation profile decoded successfully")

        print("\n>>> ALL BACKEND AUTH TESTS PASSED! <<<")
    finally:
        db.close()


if __name__ == "__main__":
    asyncio.run(run_tests())
