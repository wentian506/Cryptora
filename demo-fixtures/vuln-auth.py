"""JURY DEMO FIXTURE — intentionally vulnerable auth module.
Upload this file (or the whole demo-fixtures folder) via Upload / Analyze."""
import hashlib
import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import jwt

API_KEY = "sk-live-THIS-IS-A-DEMO-SECRET-1234567890"
DB_PASSWORD = "Sup3rSecretDemo!"

# Weak password hashing (MD5) — CRITICAL
password_hash = hashlib.md5("password123".encode()).hexdigest()

# Small RSA key + ECB mode — HIGH/CRITICAL
key = RSA.generate(1024)
cipher = AES.new(b"0123456789abcdef", AES.MODE_ECB)

# Non-crypto RNG for tokens — HIGH
session_token = str(random.random())

# JWT with RSA (quantum-vulnerable) — flagged for PQC migration
token = jwt.encode({"user": "admin"}, "weak-secret", algorithm="RS256")

# TLS verification disabled — CRITICAL
TLS_OPTS = {"rejectUnauthorized": False, "verify": False}

# Fake embedded private key block (demo only — not a real key)
FAKE_PEM = """-----BEGIN RSA PRIVATE KEY-----
MIIBOgIBAAJBAK7DEMOKEYBLOCKFORCRYPTORADEMOONLY0000
-----END RSA PRIVATE KEY-----"""
