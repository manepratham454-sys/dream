from fastapi import Header, HTTPException, status

from .services.auth_service import decode_access_token


def get_current_user(authorization: str = Header(None, alias="Authorization")) -> dict:
    """Validate the bearer token (JWT or static demo token).
    Expects header format: "Bearer <token>".
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        scheme, token = authorization.split()
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication scheme",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Legacy demo token fallback
    if token == "demo-token-12345":
        return {
            "email": "demo.user@example.com",
            "name": "Sentinel Demo Operator",
            "auth_provider": "password",
        }

    # Verify JWT
    payload = decode_access_token(token)
    if not payload or not payload.get("sub"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return {
        "email": payload.get("sub"),
        "name": payload.get("name"),
        "avatar_url": payload.get("avatar_url"),
        "auth_provider": payload.get("auth_provider", "jwt"),
    }
