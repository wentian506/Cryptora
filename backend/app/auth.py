"""Auth primitives — stdlib only (no secret-bearing dependencies).

- Passwords: PBKDF2-HMAC-SHA256, 210k iterations, per-user salt. Never logged.
- Sessions: hand-rolled HS256 JWT (sub=user_id, exp). Secret from env.
- Google: verifies ID token against Google's tokeninfo endpoint (urllib).
- OTP: 6-digit code, SHA-256 hash stored with expiry; rate-limited. Raw codes
  are NEVER stored or logged (except returned to the caller when DEV_MODE=true
  for local testing without an SMS provider — documented, prod default false).
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.parse
import urllib.request

JWT_SECRET = os.environ.get("CRYPTORA_JWT_SECRET", "dev-only-secret-CHANGE-ME")
JWT_TTL = int(os.environ.get("CRYPTORA_JWT_TTL", "86400"))
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
DEV_MODE = os.environ.get("DEV_MODE", "false").lower() in ("1", "true", "yes")
PBKDF2_ITERS = 210_000

# in-memory OTP + rate-limit stores (single-process demo; roadmap: redis table)
_OTP = {}        # phone -> {hash, exp, attempts}
_OTP_COUNT = {}  # phone -> [timestamps]


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_dec(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERS)
    return f"pbkdf2${PBKDF2_ITERS}${salt.hex()}${dk.hex()}"


def check_password(password: str, stored: str) -> bool:
    try:
        _, iters, salt, dk = stored.split("$")
        calc = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iters))
        return hmac.compare_digest(calc.hex(), dk)
    except Exception:
        return False


def make_token(user_id: int) -> str:
    header = b64u(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64u(json.dumps({"sub": user_id, "exp": int(time.time()) + JWT_TTL}).encode())
    sig = b64u(hmac.new(JWT_SECRET.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest())
    return f"{header}.{body}.{sig}"


def parse_token(token: str):
    try:
        header, body, sig = token.split(".")
        expect = b64u(hmac.new(JWT_SECRET.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(expect, sig):
            return None
        payload = json.loads(b64u_dec(body))
        if payload.get("exp", 0) < time.time():
            return None
        return payload.get("sub")
    except Exception:
        return None


def verify_google_id_token(id_token: str):
    """Returns Google `sub` + profile on success. Raises ValueError otherwise."""
    if not GOOGLE_CLIENT_ID:
        raise ValueError("Google sign-in is not configured on this server (GOOGLE_CLIENT_ID).")
    url = "https://oauth2.googleapis.com/tokeninfo?" + urllib.parse.urlencode({"id_token": id_token})
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            data = json.loads(r.read().decode())
    except Exception:
        raise ValueError("Token rejected by Google tokeninfo.")
    if data.get("aud") != GOOGLE_CLIENT_ID:
        raise ValueError("Token audience mismatch.")
    if data.get("exp") and int(data["exp"]) < time.time():
        raise ValueError("Google token expired.")
    return {"sub": data.get("sub"), "email": data.get("email", ""), "name": data.get("name", "")}


def otp_request(phone: str):
    now = time.time()
    hits = [t for t in _OTP_COUNT.get(phone, []) if now - t < 3600]
    if len(hits) >= 5:
        raise ValueError("Too many OTP requests for this number. Try again later.")
    hits.append(now)
    _OTP_COUNT[phone] = hits
    code = f"{secrets.randbelow(1_000_000):06d}"
    _OTP[phone] = {
        "hash": hashlib.sha256(code.encode()).hexdigest(),
        "exp": now + 600,
        "attempts": 0,
    }
    # Real SMS hook: if TWILIO_* (or MSG91_*) env is set, send via provider here.
    # Without a provider, local testing uses DEV_MODE echo (documented).
    return {"sent": True, "dev_code": code if DEV_MODE else None}


def otp_verify(phone: str, code: str) -> bool:
    rec = _OTP.get(phone)
    if not rec or time.time() > rec["exp"]:
        _OTP.pop(phone, None)
        return False
    rec["attempts"] += 1
    if rec["attempts"] > 6:
        _OTP.pop(phone, None)
        return False
    ok = hmac.compare_digest(rec["hash"], hashlib.sha256(code.strip().encode()).hexdigest())
    if ok:
        _OTP.pop(phone, None)
    return ok
