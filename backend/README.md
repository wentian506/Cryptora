# CRYPTORA backend — auth + persistence

## Local run (SQLite, zero setup)

```bash
pip install -r requirements.txt
DEV_MODE=true uvicorn app.main:app --port 8000
# → http://localhost:8000/health  ·  docs at /docs
```

## Production (MySQL)

```bash
export DATABASE_URL="mysql+pymysql://cryptora:SECRET@mysql:3306/cryptora"
export CRYPTORA_JWT_SECRET="$(openssl rand -hex 32)"
export FRONTEND_ORIGIN="https://your-domain"
export GOOGLE_CLIENT_ID="..."   # optional, enables Google sign-in
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

See `/deploy` for the one-command Docker setup.

## Notes

- Passwords: PBKDF2-HMAC-SHA256 (210k). OTPs: SHA-256 hash + expiry, rate-limited 5/hr.
- Sessions: HS256 JWT. Every project/scan read/write checks ownership (IDOR-safe).
- Google sign-in verifies the ID token server-side with Google's tokeninfo endpoint.
- OTP SMS provider hook: set TWILIO_*/MSG91_* and wire `auth.otp_request` sender;
  without a provider, `DEV_MODE=true` echoes the code to the requester for testing.
