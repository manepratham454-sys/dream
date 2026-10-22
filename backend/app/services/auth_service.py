"""Authentication and security services for Sentinel:
JWT tokens, Email OTP dispatch & verification, and Google OAuth credential validation.
"""
import logging
import re
import secrets
import smtplib
from datetime import datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional, Tuple

import httpx
import jwt
from sqlalchemy.orm import Session

from ..config import (
    GOOGLE_CLIENT_ID,
    JWT_ALGORITHM,
    JWT_EXPIRE_MINUTES,
    JWT_SECRET,
    OTP_EXPIRE_MINUTES,
    SMTP_FROM,
    SMTP_HOST,
    SMTP_PASSWORD,
    SMTP_PORT,
    SMTP_USER,
)
from ..models import EmailOTP, User

logger = logging.getLogger("sentinel.auth")


# =============================================================================
# JWT Token Handling
# =============================================================================

def create_access_token(
    data: dict,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Generate a signed JWT bearer token containing user claims."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=JWT_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Optional[dict]:
    """Decode and validate a JWT bearer token."""
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except (jwt.PyJWTError, Exception) as err:
        logger.debug("JWT decode failed: %s", err)
        return None


# =============================================================================
# Database User Management
# =============================================================================

def get_or_create_user(
    db: Session,
    email: str,
    full_name: Optional[str] = None,
    avatar_url: Optional[str] = None,
    auth_provider: str = "password",
) -> User:
    """Retrieve existing user by normalized email or provision a new user."""
    normalized_email = email.strip().lower()
    user = db.query(User).filter(User.email == normalized_email).first()

    now = datetime.utcnow()
    if user:
        user.last_login = now
        if full_name and not user.full_name:
            user.full_name = full_name
        if avatar_url:
            user.avatar_url = avatar_url
        if auth_provider and user.auth_provider != auth_provider:
            user.auth_provider = auth_provider
        db.commit()
        db.refresh(user)
        return user

    user = User(
        email=normalized_email,
        full_name=full_name or normalized_email.split("@")[0].replace(".", " ").title(),
        avatar_url=avatar_url,
        auth_provider=auth_provider,
        is_active=True,
        created_at=now,
        last_login=now,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


# =============================================================================
# Email OTP (Passwordless Login)
# =============================================================================

def is_valid_email(email: str) -> bool:
    """Basic RFC 5322 regex validation for incoming email addresses."""
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return bool(re.match(pattern, email.strip()))


def generate_and_store_otp(db: Session, email: str) -> Tuple[str, datetime]:
    """Generate a secure 6-digit numeric OTP and save to the database."""
    normalized_email = email.strip().lower()

    # Invalidate any existing unused OTPs for this email
    db.query(EmailOTP).filter(
        EmailOTP.email == normalized_email,
        EmailOTP.is_used == False,
    ).update({"is_used": True})

    # Generate a cryptographically secure 6-digit code
    code = f"{secrets.randbelow(900000) + 100000:06d}"
    expires_at = datetime.utcnow() + timedelta(minutes=OTP_EXPIRE_MINUTES)

    otp_record = EmailOTP(
        email=normalized_email,
        otp_code=code,
        expires_at=expires_at,
        is_used=False,
        attempts=0,
        created_at=datetime.utcnow(),
    )
    db.add(otp_record)
    db.commit()
    return code, expires_at


def verify_email_otp(db: Session, email: str, code: str) -> Tuple[bool, str]:
    """Validate user-entered OTP against active database records."""
    normalized_email = email.strip().lower()
    clean_code = code.strip()

    otp_record = (
        db.query(EmailOTP)
        .filter(
            EmailOTP.email == normalized_email,
            EmailOTP.is_used == False,
        )
        .order_by(EmailOTP.created_at.desc())
        .first()
    )

    if not otp_record:
        return False, "No active OTP request found. Please request a new code."

    # Check expiration
    if datetime.utcnow() > otp_record.expires_at:
        otp_record.is_used = True
        db.commit()
        return False, "OTP code has expired. Please request a new code."

    # Check attempt threshold (max 5 attempts)
    if otp_record.attempts >= 5:
        otp_record.is_used = True
        db.commit()
        return False, "Too many failed attempts. Please request a fresh OTP."

    # Verify code match
    if otp_record.otp_code != clean_code:
        otp_record.attempts += 1
        db.commit()
        remaining = 5 - otp_record.attempts
        return False, f"Incorrect verification code. {remaining} attempt(s) remaining."

    # Success: mark used
    otp_record.is_used = True
    db.commit()
    return True, "Code verified successfully"


def send_otp_email(email: str, code: str) -> dict:
    """Send OTP passcode via SMTP if configured, or print to console for development."""
    normalized_email = email.strip().lower()

    # When SMTP is not configured, operate in Zero-Setup Dev Mode
    if not SMTP_HOST:
        print("\n" + "=" * 65)
        print("[SENTINEL VAULT DEV AUTHENTICATION]")
        print(f"-> Target Email : {normalized_email}")
        print(f"-> 6-Digit OTP  : {code}")
        print(f"-> Valid For    : {OTP_EXPIRE_MINUTES} minutes")
        print("=" * 65 + "\n")
        return {
            "sent": False,
            "channel": "dev_console",
            "dev_code": code,
            "message": f"Dev OTP logged to console: {code}",
        }

    # Dispatch via live SMTP
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[{code}] Sentinel Security Vault - Access Verification Passcode"
        msg["From"] = SMTP_FROM
        msg["To"] = normalized_email

        text_content = f"""
Sentinel Security Vault - Authentication Request

Your one-time security access passcode is:
{code}

This code will expire in {OTP_EXPIRE_MINUTES} minutes.
If you did not request this login, you can safely ignore this email.
"""

        html_content = f"""
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0b0f19; color: #f1f5f9; padding: 20px; }}
    .container {{ max-width: 520px; margin: 0 auto; background: #0f172a; border: 1px solid #1e293b; border-radius: 16px; padding: 32px; box-shadow: 0 10px 25px rgba(0,0,0,0.5); }}
    .logo {{ display: flex; align-items: center; gap: 8px; color: #10b981; font-weight: 800; font-size: 1.25rem; letter-spacing: 0.05em; margin-bottom: 24px; }}
    .title {{ font-size: 1.4rem; font-weight: 700; color: #ffffff; margin-bottom: 8px; }}
    .subtitle {{ color: #94a3b8; font-size: 0.95rem; line-height: 1.5; margin-bottom: 24px; }}
    .code-box {{ background: rgba(16, 185, 129, 0.08); border: 2px dashed #10b981; border-radius: 12px; padding: 20px; text-align: center; margin: 24px 0; }}
    .code {{ font-family: 'Courier New', Courier, monospace; font-size: 2.2rem; font-weight: 800; letter-spacing: 0.35em; color: #34d399; margin: 0; }}
    .footer {{ font-size: 0.8rem; color: #64748b; margin-top: 24px; border-top: 1px solid #1e293b; padding-top: 16px; text-align: center; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="logo">
      <span>SENTINEL SECURITY VAULT</span>
    </div>
    <div class="title">Operator Verification Code</div>
    <div class="subtitle">
      Use the one-time passcode below to authenticate into the Sentinel Security Recon & Remediation Console.
    </div>
    <div class="code-box">
      <div class="code">{code}</div>
    </div>
    <div class="subtitle" style="font-size: 0.85rem;">
      This passcode will expire in <strong>{OTP_EXPIRE_MINUTES} minutes</strong>. Never share this code with anyone.
    </div>
    <div class="footer">
      Autonomous DevSecOps Recon & Vulnerability Auto-Solver • Zero-Trust Operations
    </div>
  </div>
</body>
</html>
"""
        msg.attach(MIMEText(text_content, "plain"))
        msg.attach(MIMEText(html_content, "html"))

        if SMTP_PORT == 465:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10) as server:
                if SMTP_USER and SMTP_PASSWORD:
                    server.login(SMTP_USER, SMTP_PASSWORD)
                server.send_message(msg)
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
                server.ehlo()
                if server.has_extn("STARTTLS"):
                    server.starttls()
                    server.ehlo()
                if SMTP_USER and SMTP_PASSWORD:
                    server.login(SMTP_USER, SMTP_PASSWORD)
                server.send_message(msg)

        return {"sent": True, "channel": "smtp", "dev_code": None, "message": "Email sent"}
    except Exception as err:
        logger.error("Failed to send email via SMTP: %s", err)
        # Fallback to console so operator is never locked out
        print(f"[SMTP ERROR: {err}] Fallback Console OTP: {code}")
        return {
            "sent": False,
            "channel": "dev_console_fallback",
            "dev_code": code,
            "message": f"SMTP dispatch failed ({err}). Console OTP code: {code}",
        }


# =============================================================================
# Google OAuth Credential Verification
# =============================================================================

async def verify_google_credential(credential: str, client_id: Optional[str] = None) -> dict:
    """Verify a Google ID Token (from Google Identity Services) and extract user identity.
    Supports development simulation tokens and real Google token validation.
    """
    credential = credential.strip()

    # 1. Check for Dev Mode simulation token (convenient testing without Google Cloud setup)
    if credential.startswith("dev-google-sim:"):
        parts = credential.split(":")
        sim_email = parts[1] if len(parts) > 1 and parts[1] else "security.analyst@sentinel.sec"
        sim_name = parts[2] if len(parts) > 2 and parts[2] else "Security Analyst (Google)"
        return {
            "email": sim_email,
            "name": sim_name,
            "picture": "https://lh3.googleusercontent.com/a/default-user",
            "sub": f"google-dev-sub-{secrets.token_hex(6)}",
        }

    # 2. Try verification using official google-auth library if installed
    try:
        from google.auth.transport import requests as google_requests
        from google.oauth2 import id_token as google_id_token

        effective_client_id = client_id or GOOGLE_CLIENT_ID or None
        idinfo = google_id_token.verify_oauth2_token(
            credential,
            google_requests.Request(),
            audience=effective_client_id,
        )

        email = idinfo.get("email")
        if not email:
            raise ValueError("Google token did not contain an email address")

        return {
            "email": email,
            "name": idinfo.get("name") or email.split("@")[0].title(),
            "picture": idinfo.get("picture"),
            "sub": idinfo.get("sub"),
        }
    except Exception as google_err:
        logger.warning("google.oauth2 verification failed, trying Google tokeninfo endpoint: %s", google_err)

    # 3. Fallback verification via Google's tokeninfo endpoint over HTTPS
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            resp = await client.get(
                "https://oauth2.googleapis.com/tokeninfo",
                params={"id_token": credential},
            )
            if resp.status_code == 200:
                data = resp.json()
                email = data.get("email")
                if email:
                    return {
                        "email": email,
                        "name": data.get("name") or email.split("@")[0].title(),
                        "picture": data.get("picture"),
                        "sub": data.get("sub"),
                    }
            logger.error("Google tokeninfo error: %s %s", resp.status_code, resp.text)
    except Exception as http_err:
        logger.error("HTTP verification error with Google tokeninfo: %s", http_err)

    raise ValueError("Invalid Google credential token or verification failed")
