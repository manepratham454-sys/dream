# Sentinel Security Platform

A premium, enterprise-grade Cybersecurity Reconnaissance, Vulnerability Management, and Remediation Command Center.

---

## Architecture Overview

- **Frontend**: React 19 + Vite 8 + React Router 7 styled with a custom dark-mode cybersecurity design system (`#030712` deep space palette, cyan glows, glassmorphism).
- **Backend**: FastAPI (Python 3.14) REST API supporting JWT authentication, Email OTP dispatch, role-based access, and vulnerability management.
- **Database**: SQLite / SQLAlchemy database with pre-built models for users, findings, rooms, and audit logs.
- **Containerization**: Docker & Docker Compose setup ready for deployment.

---

## Quick Start (Local Development)

### Prerequisites
- Node.js (v18+)
- Python 3.10+
- npm

### 1. Launch All Services (Windows One-Click)
Run the automated launcher:
```cmd
run_all.bat
```
This will automatically launch:
- **Backend API**: `http://localhost:8000` (Swagger docs at `http://localhost:8000/docs`)
- **Frontend App**: `http://localhost:5173`

---

## Running Services Manually

### Backend Setup
```bash
cd backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

---

## Testing & Verification

### Backend Automated Test Suite
Run unit & authentication flow tests:
```bash
python -m pytest backend/
python backend/test_auth_flow.py
```

### Frontend Production Build Test
Verify CSS and React bundle compilation:
```bash
cd frontend
npx vite build
```

---

## Environment Variables (`.env`)
Refer to `.env.example` for default variables:
- `SECRET_KEY`: JWT secret key
- `DATABASE_URL`: `sqlite:///./test.db`
- `ENV`: `development` / `production`

---

## License
Enterprise License — Proprietary & Confidential.
