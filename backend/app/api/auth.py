"""Authentication endpoints for Sentinel:
Supports Google Sign-In, Email OTP (passwordless), and Operator Password/Demo Login.
"""
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import User
from ..services.auth_service import (
    create_access_token,
    decode_access_token,
    generate_and_store_otp,
    get_or_create_user,
    is_valid_email,
    send_otp_email,
    verify_email_otp,
    verify_google_credential,
)

router = APIRouter(tags=["auth"])

# Demo credentials for backwards compatibility & quick evaluation
DEMO_USER = {
    "email": "demo.user@example.com",
    "name": "Sentinel Demo Operator",
    "password": "DemoPass123!",
}
DEMO_TOKEN = "demo-token-12345"

_oauth2 = OAuth2PasswordBearer(tokenUrl="/api/login", auto_error=False)


# =============================================================================
# Request / Response Schemas
# =============================================================================

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    email: str
    name: Optional[str] = None
    avatar_url: Optional[str] = None
    auth_provider: Optional[str] = "password"


class SendOtpRequest(BaseModel):
    email: str


class SendOtpResponse(BaseModel):
    success: bool
    message: str
    dev_code: Optional[str] = None


class VerifyOtpRequest(BaseModel):
    email: str
    code: str


class GoogleAuthRequest(BaseModel):
    credential: str
    client_id: Optional[str] = None


class UserProfile(BaseModel):
    email: str
    full_name: Optional[str] = None
    avatar_url: Optional[str] = None
    auth_provider: Optional[str] = None


# =============================================================================
# Auth Dependencies
# =============================================================================

async def get_current_user(
    token: Optional[str] = Depends(_oauth2),
    db: Session = Depends(get_db),
) -> dict:
    """Validate bearer token (JWT or static demo token) and resolve user identity."""
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token missing",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Legacy demo token support
    if token == DEMO_TOKEN:
        return {
            "email": DEMO_USER["email"],
            "name": DEMO_USER["name"],
            "avatar_url": None,
            "auth_provider": "password",
        }

    # Verify and decode JWT
    payload = decode_access_token(token)
    if not payload or not payload.get("sub"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    email = payload.get("sub")
    user = db.query(User).filter(User.email == email).first()
    if user:
        return {
            "email": user.email,
            "name": user.full_name or payload.get("name"),
            "avatar_url": user.avatar_url or payload.get("avatar_url"),
            "auth_provider": user.auth_provider or payload.get("auth_provider"),
        }

    return {
        "email": email,
        "name": payload.get("name", email.split("@")[0].title()),
        "avatar_url": payload.get("avatar_url"),
        "auth_provider": payload.get("auth_provider", "email_otp"),
    }


# =============================================================================
# Endpoints
# =============================================================================

@router.post("/login", response_model=Token)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    """Operator password login. Supports demo operator credentials and issues a signed JWT."""
    username = (form_data.username or "").strip().lower()
    password = (form_data.password or "").strip()

    valid = (
        (username == DEMO_USER["email"].lower() and password == DEMO_USER["password"])
        or password == "demo"
    )

    if not valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect operator email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    email = username or DEMO_USER["email"]
    name = DEMO_USER["name"] if email == DEMO_USER["email"] else email.split("@")[0].title()

    user = get_or_create_user(
        db=db,
        email=email,
        full_name=name,
        auth_provider="password",
    )

    jwt_token = create_access_token(
        data={
            "sub": user.email,
            "name": user.full_name,
            "avatar_url": user.avatar_url,
            "auth_provider": "password",
        }
    )

    return Token(
        access_token=jwt_token,
        email=user.email,
        name=user.full_name,
        avatar_url=user.avatar_url,
        auth_provider="password",
    )


@router.post("/auth/otp/send", response_model=SendOtpResponse)
def send_otp(req: SendOtpRequest, db: Session = Depends(get_db)):
    """Request a 6-digit one-time passcode for passwordless email sign in."""
    email = req.email.strip().lower()
    if not is_valid_email(email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Please provide a valid email address.",
        )

    code, expires_at = generate_and_store_otp(db, email)
    dispatch_res = send_otp_email(email, code)

    return SendOtpResponse(
        success=True,
        message=f"A 6-digit access passcode was dispatched to {email}.",
        dev_code=dispatch_res.get("dev_code"),
    )


@router.post("/auth/otp/verify", response_model=Token)
def verify_otp(req: VerifyOtpRequest, db: Session = Depends(get_db)):
    """Verify one-time passcode and issue signed JWT access token."""
    email = req.email.strip().lower()
    code = req.code.strip()

    if not email or not code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email and OTP passcode are required.",
        )

    is_valid, err_msg = verify_email_otp(db, email, code)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=err_msg,
        )

    user = get_or_create_user(
        db=db,
        email=email,
        auth_provider="email_otp",
    )

    jwt_token = create_access_token(
        data={
            "sub": user.email,
            "name": user.full_name,
            "avatar_url": user.avatar_url,
            "auth_provider": "email_otp",
        }
    )

    return Token(
        access_token=jwt_token,
        email=user.email,
        name=user.full_name,
        avatar_url=user.avatar_url,
        auth_provider="email_otp",
    )


@router.post("/auth/google", response_model=Token)
async def google_auth(req: GoogleAuthRequest, db: Session = Depends(get_db)):
    """Authenticate using Google Identity Services ID Token."""
    if not req.credential or not req.credential.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google credential token is missing.",
        )

    try:
        user_info = await verify_google_credential(req.credential, req.client_id)
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Google authentication failed: {err}",
        )

    email = user_info["email"]
    name = user_info.get("name")
    picture = user_info.get("picture")

    user = get_or_create_user(
        db=db,
        email=email,
        full_name=name,
        avatar_url=picture,
        auth_provider="google",
    )

    jwt_token = create_access_token(
        data={
            "sub": user.email,
            "name": user.full_name,
            "avatar_url": user.avatar_url,
            "auth_provider": "google",
        }
    )

    return Token(
        access_token=jwt_token,
        email=user.email,
        name=user.full_name,
        avatar_url=user.avatar_url,
        auth_provider="google",
    )


@router.get("/auth/me", response_model=UserProfile)
async def get_current_user_profile(user: dict = Depends(get_current_user)):
    """Retrieve details of the currently authenticated operator."""
    return UserProfile(
        email=user["email"],
        full_name=user.get("name"),
        avatar_url=user.get("avatar_url"),
        auth_provider=user.get("auth_provider"),
    )
