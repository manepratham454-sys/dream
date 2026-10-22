import os
import tempfile
from pathlib import Path

# Base directory for temporary scan workspaces. Override via env var if needed.
SCAN_ROOT: str = os.getenv("SCAN_ROOT", str(Path(tempfile.gettempdir()) / "sentinel_scans"))

# Maximum upload size in bytes (100 MB)
MAX_UPLOAD_SIZE: int = int(os.getenv("MAX_UPLOAD_SIZE", str(100 * 1024 * 1024)))

# Secret file patterns to exclude from analysis and AI submission (comma‑separated glob list)
SECRET_PATTERNS: list[str] = [
    "*.env",
    "*.pem",
    "*.key",
    "*.crt",
    "*.p12",
    "*.pfx",
    "*.jks",
    "*.keystore",
    "id_rsa",
    "id_ed25519",
    "credentials.json",
    "secrets.json",
    ".npmrc",
    ".pypirc",
    "terraform.tfstate",
]

# GitHub OAuth configuration
GITHUB_CLIENT_ID: str = os.getenv("GITHUB_CLIENT_ID", "")
GITHUB_CLIENT_SECRET: str = os.getenv("GITHUB_CLIENT_SECRET", "")
GITHUB_OAUTH_REDIRECT_URI: str = os.getenv(
    "GITHUB_OAUTH_REDIRECT_URI",
    "http://localhost:8000/api/auth/github/callback",
)

# AI provider configuration – default to Anthropic Claude 3.5 Sonnet (can be overridden)
AI_PROVIDER: str = os.getenv("AI_PROVIDER", "anthropic")
ANTHROPIC_API_KEY: str = os.getenv("ANTHROPIC_API_KEY", "")
OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
# For local Ollama you can set OLLAMA_BASE_URL, e.g. http://localhost:11434
OLLAMA_BASE_URL: str = os.getenv("OLLAMA_BASE_URL", "")

# Default linters (set to true to enable)
ENABLE_ESLINT: bool = os.getenv("ENABLE_ESLINT", "true").lower() == "true"
ENABLE_FLAKE8: bool = os.getenv("ENABLE_FLAKE8", "true").lower() == "true"
ENABLE_GOLINT: bool = os.getenv("ENABLE_GOLINT", "true").lower() == "true"
ENABLE_BANDIT: bool = os.getenv("ENABLE_BANDIT", "true").lower() == "true"
ENABLE_SEMGREP: bool = os.getenv("ENABLE_SEMGREP", "true").lower() == "true"

# Misc constants
SCAN_STATUS_PENDING = "pending"
SCAN_STATUS_RUNNING = "running"
SCAN_STATUS_COMPLETED = "completed"
SCAN_STATUS_FAILED = "failed"

# Authentication & Security
JWT_SECRET: str = os.getenv("JWT_SECRET", "sentinel-vault-super-secure-jwt-secret-key-2026")
JWT_ALGORITHM: str = os.getenv("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_MINUTES: int = int(os.getenv("JWT_EXPIRE_MINUTES", "1440"))  # 24 hours

# Google OAuth
GOOGLE_CLIENT_ID: str = os.getenv("GOOGLE_CLIENT_ID", "")

# Email OTP / SMTP Dispatch
SMTP_HOST: str = os.getenv("SMTP_HOST", "")
SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER: str = os.getenv("SMTP_USER", "")
SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
SMTP_FROM: str = os.getenv("SMTP_FROM", "Sentinel Vault <no-reply@sentinel.sec>")
OTP_EXPIRE_MINUTES: int = int(os.getenv("OTP_EXPIRE_MINUTES", "10"))

