/* ============================================================
   CRYPTORA — In-browser static scanner engine (deterministic)
   No network calls except user-requested GitHub/raw fetches.
   Never executes scanned code. Regex + AST-lite + manifests +
   entropy + PEM/cert + Dockerfile + binary-strings analysis.
   ============================================================ */

export const PQC = {
  KEM: 'ML-KEM (FIPS 203)',
  DSA: 'ML-DSA (FIPS 204)',
  SLH: 'SLH-DSA (FIPS 205)'
};

/* ---------- Algorithm knowledge base ---------- */
export const ALGO_KB = [
  // asymmetric — quantum vulnerable
  { id: 'RSA', label: 'RSA', cat: 'asymmetric', quantum: true, weakIf: 'key < 2048 or PKCS#1 v1.5 padding', severity: 'high',
    rx: [/\bRSA\b/i, /\bRS256\b|\bRS384\b|\bRS512\b/, /rsa\.generate/i, /RSA_PKCS1|RSASSA/i, /crypto\.publicEncrypt|privateDecrypt/i],
    libs: ['cryptography', 'Crypto.PublicKey.RSA', 'node:crypto', 'java.security', 'javax.crypto', 'openssl', 'forge', 'CryptoJS', 'jose', 'jsonwebtoken'],
    rec: { hybrid: 'RSA-2048+ + ML-KEM-768 (hybrid key exchange)', pqc: 'ML-KEM-768 / ML-KEM-1024 (FIPS 203)', note: 'Signatures: migrate RSA-PSS/PKCS1 → ML-DSA-65 (FIPS 204). KEX/encryption → ML-KEM.' } },
  { id: 'DSA', label: 'DSA', cat: 'asymmetric', quantum: true, weakIf: 'always — legacy, small keys', severity: 'high',
    rx: [/\bDSA\b(?!-?\d)/i, /\bDSS\b/i, /dsa\.generate/i],
    libs: ['cryptography', 'java.security', 'openssl'],
    rec: { hybrid: 'DSA → ECDSA interim, then hybrid ECDSA + ML-DSA', pqc: 'ML-DSA-65 (FIPS 204)', note: 'DSA is legacy. Move to ECDSA/ECDH short-term, then ML-DSA.' } },
  { id: 'DH', label: 'Diffie-Hellman (classic)', cat: 'kex', quantum: true, weakIf: 'group < 2048 bits', severity: 'high',
    rx: [/\bDiffie[-\s]?Hellman\b/i, /\bdhparam\b/i, /createDiffieHellman/i, /DH_anon|TLS_DH_/i],
    libs: ['node:crypto', 'openssl', 'cryptography', 'java.security'],
    rec: { hybrid: 'Classic DH + ML-KEM-768 hybrid', pqc: 'ML-KEM-768 (FIPS 203)', note: 'Replace static/ephemeral DH with hybrid KEM.' } },
  { id: 'ECDH', label: 'ECDH', cat: 'kex', quantum: true, weakIf: 'curve < 256 bits', severity: 'high',
    rx: [/\bECDH\b/i, /\bX25519\b/, /ecdh\.computeSecret|deriveBits.*ECDH/i, /TLS_ECDHE_/i],
    libs: ['node:crypto', 'WebCrypto', 'cryptography', 'libsodium', 'noble'],
    rec: { hybrid: 'X25519 + ML-KEM-768 (draft-ietf hybrid)', pqc: 'ML-KEM-768 (FIPS 203)', note: 'NIST-endorsed hybrid: X25519+ML-KEM-768 during transition.' } },
  { id: 'ECDSA', label: 'ECDSA', cat: 'signature', quantum: true, weakIf: 'curve < 256 bits, nonce reuse', severity: 'high',
    rx: [/\bECDSA\b/i, /\bES256\b|\bES384\b|\bES512\b/, /ecdsa\.sign|createSign\(['"]SHA/i],
    libs: ['node:crypto', 'WebCrypto', 'cryptography', 'ethers', 'noble', 'jose'],
    rec: { hybrid: 'ECDSA + ML-DSA dual-sign (hybrid certs)', pqc: 'ML-DSA-65 (FIPS 204)', note: 'Dual signatures during migration; verify both.' } },
  { id: 'EdDSA', label: 'EdDSA / Ed25519', cat: 'signature', quantum: true, weakIf: 'n/a classically strong, quantum-broken', severity: 'high',
    rx: [/\bEd25519\b|\bEdDSA\b|\bED25519\b/, /\bEdDSA\b/i],
    libs: ['libsodium', 'noble', 'cryptography', 'node:crypto'],
    rec: { hybrid: 'Ed25519 + ML-DSA dual-sign', pqc: 'ML-DSA-65 / SLH-DSA (FIPS 204/205)', note: 'Classically strong but Shor-broken. Hybrid-sign for transition.' } },
  // symmetric
  { id: 'AES', label: 'AES', cat: 'symmetric', quantum: false, weakIf: 'ECB mode, key < 128, static IV', severity: 'medium',
    rx: [/\bAES[-_ ]?(128|192|256)?\b/i, /\baes-[0-9]+-(ecb|cbc|gcm|ctr|ccm|ofb)\b/i, /createCipheriv\(['"]aes/i, /AES\.new\(/],
    libs: ['node:crypto', 'WebCrypto', 'CryptoJS', 'cryptography', 'javax.crypto', 'openssl', 'forge'],
    rec: { hybrid: '— (symmetric: no hybrid needed)', pqc: 'AES-256-GCM (Grover-resistant at 256-bit)', note: 'AES-256 remains safe (Grover halves strength). Kill ECB; use random IV/nonce.' } },
  { id: 'DES', label: 'DES', cat: 'symmetric', quantum: false, weakIf: 'always — 56-bit', severity: 'critical',
    rx: [/(?<![A-Z0-9_])DES(?![A-Z0-9_])/i, /des crypto|DES\.new\(/i],
    libs: ['javax.crypto', 'openssl', 'cryptography'],
    rec: { hybrid: '—', pqc: 'AES-256-GCM or ChaCha20-Poly1305', note: 'DES is broken (brute-forced). Replace immediately.' } },
  { id: '3DES', label: '3DES / TripleDES', cat: 'symmetric', quantum: false, weakIf: 'Sweet32, 64-bit blocks', severity: 'critical',
    rx: [/\b3DES\b|\bTriple\s?DES\b|\bDESede\b/i],
    libs: ['javax.crypto', 'openssl', 'cryptography'],
    rec: { hybrid: '—', pqc: 'AES-256-GCM', note: 'NIST disallowed 3DES (2023). Migrate urgently.' } },
  { id: 'RC4', label: 'RC4', cat: 'symmetric', quantum: false, weakIf: 'always — biased keystream', severity: 'critical',
    rx: [/\bRC4\b|\bARC4\b/i, /TLS_RSA_WITH_RC4/i],
    libs: ['openssl', 'cryptography'],
    rec: { hybrid: '—', pqc: 'ChaCha20-Poly1305 or AES-256-GCM', note: 'RC4 broken (RFC 7465 prohibits in TLS).' } },
  { id: 'Blowfish', label: 'Blowfish', cat: 'symmetric', quantum: false, weakIf: '64-bit blocks (Sweet32)', severity: 'high',
    rx: [/\bBlowfish\b/i],
    libs: ['openssl', 'cryptography', 'bcrypt-bundle'],
    rec: { hybrid: '—', pqc: 'AES-256-GCM', note: '64-bit block → Sweet32. Replace.' } },
  { id: 'ChaCha20', label: 'ChaCha20-Poly1305', cat: 'symmetric', quantum: false, weakIf: 'nonce reuse', severity: 'low',
    rx: [/\bChaCha20\b|\bPoly1305\b|\bXChaCha20\b/i],
    libs: ['libsodium', 'node:crypto', 'cryptography', 'noble'],
    rec: { hybrid: '—', pqc: 'Keep ChaCha20-Poly1305 (256-bit, quantum-safe margin)', note: 'Modern AEAD. Keep; enforce unique nonces.' } },
  // hashes
  { id: 'MD5', label: 'MD5', cat: 'hash', quantum: false, weakIf: 'always for security use', severity: 'critical',
    rx: [/\bMD5\b/i, /createHash\(['"]md5['"]\)/i, /hashlib\.md5|MessageDigest\.getInstance\(["']MD5/i],
    libs: ['hashlib', 'node:crypto', 'java.security', 'openssl', 'CryptoJS'],
    rec: { hybrid: '—', pqc: 'SHA-384/SHA-512 or SHA3-256 / BLAKE2b', note: 'Collision-broken. OK only for non-security checksums — flag anyway.' } },
  { id: 'SHA1', label: 'SHA-1', cat: 'hash', quantum: false, weakIf: 'signatures/certs/GIT ok-ish; else broken', severity: 'high',
    rx: [/\bSHA[-_ ]?1\b/i, /createHash\(['"]sha1['"]\)/i, /hashlib\.sha1|SHA1withRSA/i],
    libs: ['hashlib', 'node:crypto', 'java.security', 'openssl'],
    rec: { hybrid: '—', pqc: 'SHA-384/SHA-512 or SHA3-256', note: 'SHAttered collision. Migrate signatures/HMAC to SHA-2/3.' } },
  { id: 'SHA2', label: 'SHA-2 (256/384/512)', cat: 'hash', quantum: false, weakIf: 'length-extension in raw use', severity: 'low',
    rx: [/\bSHA[-_ ]?(224|256|384|512)\b/i, /SHA256withRSA|SHA384withECDSA|createHash\(['"]sha(256|384|512)/i, /hashlib\.sha(256|384|512)/],
    libs: ['hashlib', 'node:crypto', 'WebCrypto', 'java.security', 'openssl'],
    rec: { hybrid: '—', pqc: 'Keep SHA-384/512 (prefer 384+ for PQC hybrids)', note: 'Quantum-safe margin at ≥384-bit output for most uses.' } },
  { id: 'SHA3', label: 'SHA-3 / Keccak', cat: 'hash', quantum: false, weakIf: '—', severity: 'info',
    rx: [/\bSHA3[-_ ]?(224|256|384|512)?\b|\bKeccak\b/i],
    libs: ['hashlib', 'cryptography', 'noble'],
    rec: { hybrid: '—', pqc: 'Keep SHA3-256/384 (PQC-friendly)', note: 'Preferred alongside ML-KEM/ML-DSA stacks.' } },
  { id: 'BLAKE2', label: 'BLAKE2', cat: 'hash', quantum: false, weakIf: '—', severity: 'info',
    rx: [/\bBLAKE2[bs]?\b/i],
    libs: ['hashlib', 'libsodium', 'noble'],
    rec: { hybrid: '—', pqc: 'Keep BLAKE2b-512 (Grover-safe margin)', note: 'Modern fast hash. Keep.' } },
  { id: 'HMAC', label: 'HMAC', cat: 'mac', quantum: false, weakIf: 'with MD5/SHA1, short keys', severity: 'medium',
    rx: [/\bHMAC\b/i, /createHmac\(/],
    libs: ['node:crypto', 'hmac', 'javax.crypto', 'openssl'],
    rec: { hybrid: '—', pqc: 'HMAC-SHA-384/512 or KMAC', note: 'Fine with SHA-2/3 + ≥256-bit keys.' } },
  // KDF / passwords
  { id: 'PBKDF2', label: 'PBKDF2', cat: 'kdf', quantum: false, weakIf: 'low iterations (<100k)', severity: 'medium',
    rx: [/\bPBKDF2\b/i, /pbkdf2Sync|deriveKey.*PBKDF2/i],
    libs: ['node:crypto', 'WebCrypto', 'hashlib', 'javax.crypto'],
    rec: { hybrid: '—', pqc: 'Argon2id (preferred) or PBKDF2 ≥ 310k iters + salt', note: 'Raise iterations; prefer Argon2id for passwords.' } },
  { id: 'bcrypt', label: 'bcrypt', cat: 'kdf', quantum: false, weakIf: 'cost < 10', severity: 'low',
    rx: [/\bbcrypt\b/i],
    libs: ['bcrypt', 'passlib'],
    rec: { hybrid: '—', pqc: 'Keep bcrypt cost ≥12 (or Argon2id)', note: 'Password-hashing appropriate. Verify cost factor.' } },
  { id: 'scrypt', label: 'scrypt', cat: 'kdf', quantum: false, weakIf: 'weak N/r/p', severity: 'low',
    rx: [/\bscrypt\b/i],
    libs: ['node:crypto', 'hashlib'],
    rec: { hybrid: '—', pqc: 'Keep scrypt (N≥2^15) or Argon2id', note: 'Memory-hard. Keep with strong params.' } },
  { id: 'Argon2', label: 'Argon2', cat: 'kdf', quantum: false, weakIf: '—', severity: 'info',
    rx: [/\bArgon2(id|d|i)?\b/i],
    libs: ['argon2', 'libsodium'],
    rec: { hybrid: '—', pqc: 'Keep Argon2id (PHC winner)', note: 'Best practice for passwords.' } },
  // protocols / libs / tokens
  { id: 'ML-KEM', label: 'Post-quantum (ML-KEM / Kyber)', cat: 'pqc', quantum: false, weakIf: '', severity: 'info',
    rx: [/\bML-KEM(-\d{3,4})?\b|\bKyber(-\d{3,4})?\b/i, /FIPS[-\s]?203/],
    libs: ['liboqs', 'oqs-provider', 'openssl'],
    rec: { hybrid: '— (already PQC)', pqc: 'Keep ML-KEM-768/1024 (FIPS 203)', note: 'NIST-standard PQC key encapsulation. Counts toward crypto agility.' } },
  { id: 'ML-DSA', label: 'Post-quantum (ML-DSA / Dilithium)', cat: 'pqc', quantum: false, weakIf: '', severity: 'info',
    rx: [/\bML-DSA(-\d{2})?\b|\bDilithium\d?\b/i, /FIPS[-\s]?204/],
    libs: ['liboqs', 'oqs-provider', 'openssl'],
    rec: { hybrid: '— (already PQC)', pqc: 'Keep ML-DSA-65/87 (FIPS 204)', note: 'NIST-standard PQC signatures. Counts toward crypto agility.' } },
  { id: 'SLH-DSA', label: 'Post-quantum (SLH-DSA / SPHINCS+)', cat: 'pqc', quantum: false, weakIf: '', severity: 'info',
    rx: [/\bSLH-DSA\b|\bSPHINCS\+\b/i, /FIPS[-\s]?205/],
    libs: ['liboqs', 'oqs-provider'],
    rec: { hybrid: '— (already PQC)', pqc: 'Keep SLH-DSA (FIPS 205, conservative backup)', note: 'Hash-based PQC signatures. Counts toward crypto agility.' } },
  { id: 'TLS10', label: 'TLS 1.0 / 1.1 / SSL (deprecated)', cat: 'protocol', quantum: false, weakIf: 'always — deprecated, broken ciphers', severity: 'high',
    rx: [/\bTLSv?1\.[01]\b|\bSSLv?[23]\b/i],
    libs: ['openssl', 'node:tls', 'javax.net.ssl'],
    rec: { hybrid: '—', pqc: 'TLS 1.3 (disable everything below 1.2)', note: 'TLS < 1.2 deprecated by RFC 8996. Upgrade now.' } },
  { id: 'TLS13', label: 'TLS 1.2 / 1.3', cat: 'protocol', quantum: false, weakIf: '1.2 with weak ciphers', severity: 'low',
    rx: [/\bTLSv?1\.[23]\b/i],
    libs: ['openssl', 'node:tls', 'javax.net.ssl'],
    rec: { hybrid: '—', pqc: 'TLS 1.3 + hybrid X25519+ML-KEM-768 groups when available', note: 'Modern TLS. Plan hybrid KEM groups.' } },
  { id: 'TLS', label: 'TLS/SSL', cat: 'protocol', quantum: false, weakIf: 'verification disabled, old versions', severity: 'medium',
    rx: [/\bTLS\b(?![\s-]*v?1\.[0-3])|\bSTARTTLS\b/i, /rejectUnauthorized\s*:\s*false|setVerify\(.*VERIFY_NONE|InsecureSkipVerify\s*:\s*true/i],
    libs: ['openssl', 'node:tls', 'javax.net.ssl'],
    rec: { hybrid: '—', pqc: 'TLS 1.3 + hybrid X25519+ML-KEM-768 groups when available', note: 'Disable <TLS1.2; flag verification-disabled code as Critical.' } },
  { id: 'JWT', label: 'JWT / JOSE', cat: 'protocol', quantum: true, weakIf: 'none-alg, HS256 w/ weak secret, RS256→quantum', severity: 'medium',
    rx: [/\bJWT\b|\bjsonwebtoken\b|\bjwt\.sign\b|\bjwt\.verify\b/i, /\bJOSE\b|\bJWS\b|\bJWE\b/i],
    libs: ['jsonwebtoken', 'jose', 'PyJWT', 'authlib'],
    rec: { hybrid: '—', pqc: 'Migrate RS/ES-JWS → ML-DSA when JOSE PQC profiles finalize; use EdDSA interim', note: 'Check alg allow-lists; quantum breaks RS/ES-JWS.' } },
  { id: 'OpenSSL', label: 'OpenSSL / libcrypto', cat: 'library', quantum: false, weakIf: 'version < 3.0 (EOL 1.1.1)', severity: 'medium',
    rx: [/\bOpenSSL\b/i, /#include\s*<\s*openssl\//, /libcrypto|libssl/i],
    libs: ['openssl'],
    rec: { hybrid: '—', pqc: 'OpenSSL 3.2+ with provider-based ML-KEM/ML-DSA (oqsprovider)', note: 'Upgrade to 3.x; enables PQC providers.' } },
  { id: 'WebCrypto', label: 'WebCrypto / SubtleCrypto', cat: 'library', quantum: false, weakIf: 'weak params chosen by caller', severity: 'low',
    rx: [/subtle\.(encrypt|decrypt|sign|verify|generateKey|deriveKey|digest)\b/i, /window\.crypto|globalThis\.crypto/i],
    libs: ['WebCrypto'],
    rec: { hybrid: '—', pqc: 'Keep; add PQC via libs (noble/circom oqs) until native', note: 'Native PQC pending — hybrid via JS libs.' } },
  { id: 'NaCl', label: 'libsodium / NaCl', cat: 'library', quantum: false, weakIf: '—', severity: 'info',
    rx: [/\bsodium\b|\blibsodium\b|\bnacl\b|tweetnacl/i, /crypto_box|crypto_sign|crypto_secretbox/i],
    libs: ['libsodium', 'tweetnacl'],
    rec: { hybrid: '—', pqc: 'Keep; track sodium PQC additions (AEGIS + ML-KEM hybrids)', note: 'Modern misuse-resistant API. Keep.' } },
  { id: 'PGP', label: 'PGP / GPG', cat: 'protocol', quantum: true, weakIf: 'RSA/ElGamal keys (quantum)', severity: 'medium',
    rx: [/\bPGP\b|\bGPG\b|\bOpenPGP\b/i, /-----BEGIN PGP/],
    libs: ['gnupg', 'openpgp'],
    rec: { hybrid: '—', pqc: 'Track PQC OpenPGP (ML-KEM hybrids, draft-ietf-openpgp-pqc)', note: 'Classical PGP keys are harvest-now-decrypt-later targets.' } },
  { id: 'SSH', label: 'SSH keys / config', cat: 'protocol', quantum: true, weakIf: 'ssh-rsa (RSA), DSA keys', severity: 'medium',
    rx: [/ssh-rsa\b|ssh-ed25519|ecdsa-sha2-|-----BEGIN OPENSSH PRIVATE KEY-----/i],
    libs: ['openssh'],
    rec: { hybrid: '—', pqc: 'OpenSSH with ML-KEM hybrid KEX (sntrup761x25519-sha512 in 9.x)', note: 'Prefer ed25519 + hybrid KEX builds.' } },
  { id: 'ECB', label: 'ECB mode', cat: 'mode', quantum: false, weakIf: 'always', severity: 'critical',
    rx: [/\bECB\b/i, /AES\/ECB/i],
    libs: ['javax.crypto', 'node:crypto', 'cryptography'],
    rec: { hybrid: '—', pqc: 'AES-256-GCM (never ECB)', note: 'ECB leaks patterns. Replace with GCM/ChaCha20-Poly1305.' } },
  { id: 'CBC', label: 'CBC mode (no auth)', cat: 'mode', quantum: false, weakIf: 'without HMAC/AEAD, static IV', severity: 'medium',
    rx: [/\bCBC\b/i, /AES\/CBC/i, /createCipheriv\(['"][^'"]*cbc/i],
    libs: ['javax.crypto', 'node:crypto'],
    rec: { hybrid: '—', pqc: 'AES-256-GCM (authenticated)', note: 'Unauthenticated CBC → padding oracles. Prefer AEAD.' } },
  { id: 'Random', label: 'Weak randomness', cat: 'random', quantum: false, weakIf: 'Math.random for secrets', severity: 'high',
    rx: [/\bMath\.random\s*\(/, /\brandom\.random\s*\(/, /\bsrand\s*\(/, /\brand\s*\(\s*\)/],
    libs: [],
    rec: { hybrid: '—', pqc: 'CSPRNG: getRandomValues / secrets / SecureRandom', note: 'Non-crypto RNG for keys/nonces/tokens is Critical-adjacent.' } },
];

export const MANIFEST_FILES = [
  'package.json', 'package-lock.json', 'requirements.txt', 'Pipfile', 'pyproject.toml',
  'pom.xml', 'build.gradle', 'build.gradle.kts', 'go.mod', 'go.sum', 'Cargo.toml',
  'Cargo.lock', 'Gemfile', 'Gemfile.lock', 'composer.json', 'composer.lock',
  'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml', '.env', '.env.example'
];

export const CODE_EXT = new Set(['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs', 'py', 'java', 'c', 'h', 'hpp', 'cpp', 'cc', 'cs', 'go', 'rs', 'rb', 'php', 'swift', 'kt', 'kts', 'scala', 'sh', 'bash', 'ps1', 'yaml', 'yml', 'toml', 'json', 'xml', 'gradle', 'env', 'properties', 'ini', 'cfg', 'conf', 'crt', 'pem', 'key', 'cer', 'p12', 'pfx', 'der', 'sql', 'vue', 'svelte']);

/* ---------- helpers ---------- */
export function extOf(name = '') {
  const i = name.lastIndexOf('.');
  if (i < 0) return '';
  return name.slice(i + 1).toLowerCase();
}
export function baseOf(path = '') {
  const p = path.replace(/\\/g, '/');
  return p.slice(p.lastIndexOf('/') + 1);
}
export function isManifest(name = '') {
  return MANIFEST_FILES.includes(baseOf(name));
}
export function isDockerfile(name = '') {
  const b = baseOf(name).toLowerCase();
  return b === 'dockerfile' || b.startsWith('dockerfile.') || b.endsWith('.dockerfile');
}
export function looksBinary(bytes) {
  if (!bytes || !bytes.length) return false;
  const n = Math.min(bytes.length, 8000);
  let nul = 0;
  for (let i = 0; i < n; i++) if (bytes[i] === 0) nul++;
  return nul > 0;
}
export function bytesToText(bytes) {
  try { return new TextDecoder('utf-8', { fatal: false }).decode(bytes); } catch { return ''; }
}
export function printableStrings(bytes, minLen = 6, maxCount = 4000) {
  const out = [];
  let cur = '';
  const push = () => { if (cur.length >= minLen) out.push(cur); cur = ''; };
  for (let i = 0; i < bytes.length && out.length < maxCount; i++) {
    const c = bytes[i];
    if (c >= 32 && c <= 126) cur += String.fromCharCode(c);
    else if (c === 9 || c === 10 || c === 13) cur += ' ';
    else push();
  }
  push();
  return out;
}
export async function sha256Hex(textOrBytes) {
  const data = typeof textOrBytes === 'string' ? new TextEncoder().encode(textOrBytes) : textOrBytes;
  const d = await crypto.subtle.digest('SHA-256', data);
  return [...new Uint8Array(d)].map(b => b.toString(16).padStart(2, '0')).join('');
}
export function shannonEntropy(s) {
  if (!s || s.length < 8) return 0;
  const f = {};
  for (const ch of s) f[ch] = (f[ch] || 0) + 1;
  let e = 0;
  for (const k in f) { const p = f[k] / s.length; e -= p * Math.log2(p); }
  return e;
}
export function detectFormat(bytes, name = '') {
  if (!bytes || bytes.length < 4) return 'unknown';
  const h = [...bytes.slice(0, 12)].map(b => b.toString(16).padStart(2, '0')).join(' ');
  const asc = bytesToText(bytes.slice(0, 64));
  if (bytes[0] === 0x7f && asc.slice(1, 4) === 'ELF') return 'ELF executable';
  if (bytes[0] === 0x4d && bytes[1] === 0x5a) return 'PE executable (MZ)';
  if (bytes[0] === 0xce || bytes[0] === 0xcf || bytes[0] === 0xca || bytes[0] === 0xfe) {
    if (bytes[1] === 0xfa || bytes[1] === 0xed) return 'Mach-O binary';
  }
  if (asc.startsWith('%PDF')) return 'PDF document';
  if (bytes[0] === 0x50 && bytes[1] === 0x4b) {
    if (/\.docx$/i.test(name)) return 'DOCX document';
    if (/\.xlsx$/i.test(name)) return 'XLSX workbook';
    if (/\.jar$/i.test(name) || /\.apk$/i.test(name)) return 'Java archive (ZIP)';
    return 'ZIP archive';
  }
  if (bytes[0] === 0x1f && bytes[1] === 0x8b) return 'GZIP archive';
  if (asc.startsWith('{') || asc.startsWith('[')) return 'JSON/text';
  if (asc.startsWith('<')) return 'XML/HTML text';
  if (asc.startsWith('MZ')) return 'PE executable';
  return 'binary/unknown (' + h.slice(0, 23) + '…)';
}

/* ---------- AST-lite for JS/TS ---------- */
function astLiteJS(text) {
  const calls = [];
  const lines = text.split('\n');
  const callRx = /\b([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(\s*(['"`][^'"`\n]{0,80}['"`])?/g;
  const interesting = /(createCipher|createDecipher|createCipheriv|createDecipheriv|createHash|createHmac|createSign|createVerify|publicEncrypt|privateDecrypt|generateKey|generateKeyPair|subtle\.(encrypt|decrypt|sign|verify|deriveKey|digest)|sign|verify|encrypt|decrypt|hash|encode|decode|AES|RSA|HMAC|pbkdf2|scrypt|randomBytes|getRandomValues|require\(|import\s|from\s+['"])/;
  lines.forEach((ln, idx) => {
    if (!interesting.test(ln)) return;
    let m;
    callRx.lastIndex = 0;
    const rx = new RegExp(callRx);
    while ((m = rx.exec(ln)) !== null) {
      const sym = m[1];
      if (/^(if|for|while|switch|catch|function|return|const|let|var)$/.test(sym)) continue;
      calls.push({ line: idx + 1, symbol: sym, arg: (m[2] || '').slice(0, 60), code: ln.trim().slice(0, 220) });
      if (calls.length > 900) return;
    }
  });
  const imports = [];
  const impRx = /(?:import\s+[^'"]*?from\s+['"]([^'"]+)['"]|require\(\s*['"]([^'"]+)['"]\s*\))/g;
  let im;
  while ((im = impRx.exec(text)) !== null) imports.push(im[1] || im[2]);
  return { calls: calls.slice(0, 900), imports: [...new Set(imports)].slice(0, 120) };
}
function astLitePy(text) {
  const calls = [];
  const lines = text.split('\n');
  const rx = /\b([A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*)\s*\(/g;
  const interesting = /(encrypt|decrypt|sign|verify|hash|md5|sha|hmac|AES|RSA|Fernet|cipher|digest|pbkdf2|generate|load_|serialization|hashlib|Crypto|jwt|encode|decode)/i;
  lines.forEach((ln, idx) => {
    if (!interesting.test(ln)) return;
    let m; const r = new RegExp(rx);
    while ((m = r.exec(ln)) !== null) calls.push({ line: idx + 1, symbol: m[1], arg: '', code: ln.trim().slice(0, 220) });
    if (calls.length > 900) return;
  });
  const imports = [];
  const impRx = /^(?:import\s+([\w.,\s]+)|from\s+([\w.]+)\s+import)/gm;
  let im;
  while ((im = impRx.exec(text)) !== null) imports.push((im[1] || im[2] || '').split(',')[0].trim());
  return { calls: calls.slice(0, 900), imports: [...new Set(imports)].slice(0, 120) };
}

/* ---------- secret / PEM detection ---------- */
const SECRET_RX = [
  { id: 'PEM-PRIVATE', label: 'PEM private key block', sev: 'critical', rx: /-----BEGIN ([A-Z0-9 ]*PRIVATE KEY|OPENSSH PRIVATE KEY|RSA PRIVATE KEY|EC PRIVATE KEY)[\s\S]{0,40}?-----/m },
  { id: 'PEM-PUBLIC', label: 'PEM public key / certificate block', sev: 'medium', rx: /-----BEGIN (PUBLIC KEY|CERTIFICATE|RSA PUBLIC KEY|EC PUBLIC KEY)[\s\S]{0,40}?-----/m },
  { id: 'AWS-KEY', label: 'Possible AWS access key', sev: 'critical', rx: /\bAKIA[0-9A-Z]{16}\b/ },
  { id: 'ASSIGN-SECRET', label: 'Hardcoded secret assignment', sev: 'high', rx: /\b(api[_-]?key|secret|passwd|password|private[_-]?key|client[_-]?secret|auth[_-]?token|access[_-]?token)\b\s*[:=]\s*['"][^'"]{6,}['"]/i },
  { id: 'JWT-TOKEN', label: 'Hardcoded JWT', sev: 'high', rx: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/ },
  { id: 'GENERIC-KEY', label: 'Suspicious key-like literal', sev: 'medium', rx: /['"](?:sk|pk|rk)[-_][a-z]{4,}[A-Za-z0-9_-]{8,}['"]/i },
];
const TLS_VERIFY_OFF_RX = /rejectUnauthorized\s*:\s*false|VERIFY_NONE|InsecureSkipVerify\s*:\s*true|check_hostname\s*=\s*False|verify\s*=\s*False/i;

/* ---------- DER / cert minimal parser ---------- */
const SIG_OIDS = {
  '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
  '1.2.840.113549.1.1.12': 'sha384WithRSAEncryption',
  '1.2.840.113549.1.1.13': 'sha512WithRSAEncryption',
  '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption (WEAK)',
  '1.2.840.113549.1.1.4': 'md5WithRSAEncryption (BROKEN)',
  '1.2.840.10045.4.3.2': 'ecdsa-with-SHA256',
  '1.2.840.10045.4.3.3': 'ecdsa-with-SHA384',
  '1.2.840.10045.4.3.4': 'ecdsa-with-SHA512',
  '1.2.840.10045.4.1': 'ecdsa-with-SHA1 (WEAK)',
  '1.3.101.112': 'Ed25519', '1.3.101.113': 'Ed448',
  '1.2.840.10040.4.3': 'dsa-with-SHA256',
  '2.16.840.1.101.3.4.2.1': 'SHA-256 (hash)',
};
function pemToDer(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function readLen(buf, off) {
  let len = buf[off++];
  if (len & 0x80) {
    const n = len & 0x7f;
    len = 0;
    for (let i = 0; i < n; i++) len = (len << 8) | buf[off++];
  }
  return [len, off];
}
function parseDerTlvs(buf, depth = 0, out = []) {
  let off = 0;
  while (off + 2 <= buf.length && out.length < 400) {
    const tag = buf[off++];
    if (off >= buf.length) break;
    let len, noff;
    try { [len, noff] = readLen(buf, off); } catch { break; }
    off = noff;
    if (off + len > buf.length) break;
    const val = buf.slice(off, off + len);
    out.push({ tag, len, depth, value: val });
    if ((tag & 0x20) && depth < 6 && len > 0) {
      try { parseDerTlvs(val, depth + 1, out); } catch { /* ignore */ }
    }
    off += len;
    if (depth > 0 && out.length > 0) { /* continue siblings */ }
    if (depth === 0) break; // top-level single element typically
  }
  return out;
}
function oidToString(bytes) {
  if (!bytes.length) return '';
  const first = bytes[0];
  const parts = [Math.floor(first / 40), first % 40];
  let v = 0;
  for (let i = 1; i < bytes.length; i++) {
    v = (v << 7) | (bytes[i] & 0x7f);
    if (!(bytes[i] & 0x80)) { parts.push(v); v = 0; }
  }
  return parts.join('.');
}
function derTimeToISO(tag, bytes) {
  try {
    const s = String.fromCharCode(...bytes);
    if (tag === 0x17 && s.length >= 12) { // UTCTime YYMMDDHHMMSSZ
      const yy = +s.slice(0, 2); const full = yy >= 50 ? 1900 + yy : 2000 + yy;
      return `${full}-${s.slice(2, 4)}-${s.slice(4, 6)}T${s.slice(6, 8)}:${s.slice(8, 10)}:${s.slice(10, 12)}Z`;
    }
    if (tag === 0x18 && s.length >= 14) {
      return `${s.slice(0, 4)}-${s.slice(4, 6)}-${s.slice(6, 8)}T${s.slice(8, 10)}:${s.slice(10, 12)}:${s.slice(12, 14)}Z`;
    }
  } catch { /* ignore */ }
  return null;
}
export function parseCertificatePem(pemText) {
  const blocks = [...pemText.matchAll(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g)].map(m => m[0]);
  const certs = [];
  for (const b of blocks) {
    try {
      const der = pemToDer(b);
      const tlvs = parseDerTlvs(der);
      const oids = tlvs.filter(t => t.tag === 0x06).map(t => oidToString(t.value));
      const sigOid = oids[0] || '';
      const sigName = SIG_OIDS[sigOid] || (sigOid ? `OID ${sigOid}` : 'unknown');
      const times = tlvs.filter(t => t.tag === 0x17 || t.tag === 0x18).map(t => derTimeToISO(t.tag, t.value)).filter(Boolean);
      // key size heuristic: largest INTEGER or BIT STRING
      let keyBits = 0;
      for (const t of tlvs) {
        if (t.tag === 0x02 && t.len > 64) keyBits = Math.max(keyBits, (t.len - 1) * 8);
        if (t.tag === 0x03 && t.len > 64) keyBits = Math.max(keyBits, (t.len - 1) * 8);
      }
      // subject/cn heuristic from printable strings inside
      const strs = printableStrings(der, 3, 200);
      const cn = (strs.find(s => /CN=|commonName/i.test(s)) || strs.find(s => /\./.test(s) && s.length < 80) || '').slice(0, 120);
      const weak = /md5|sha1/i.test(sigName);
      certs.push({
        subject: cn || '(subject DN present — see raw)',
        sigAlg: sigName, sigOid, notBefore: times[0] || null, notAfter: times[1] || null,
        keyBits: keyBits || null, derLen: der.length, weak,
        expired: times[1] ? new Date(times[1]) < new Date() : null,
        expiringSoon: times[1] ? (new Date(times[1]) - new Date()) < 90 * 864e5 && new Date(times[1]) >= new Date() : false
      });
    } catch (e) {
      certs.push({ subject: '(unparseable block)', sigAlg: 'parse-error', weak: false, error: String(e && e.message || e) });
    }
  }
  return certs;
}

/* ---------- manifest / docker parsing ---------- */
function parseManifest(base, text) {
  const deps = [];
  try {
    if (base === 'package.json') {
      const j = JSON.parse(text);
      for (const sec of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
        const o = j[sec] || {};
        for (const [n, v] of Object.entries(o)) deps.push({ name: n, version: String(v), ecosystem: 'npm', section: sec });
      }
    } else if (base === 'requirements.txt') {
      text.split('\n').forEach(l => {
        const m = l.trim().match(/^([A-Za-z0-9_.\-]+)\s*([=<>!~]+.*)?$/);
        if (m && !l.trim().startsWith('#')) deps.push({ name: m[1], version: (m[2] || '').trim() || '*', ecosystem: 'pypi' });
      });
    } else if (base === 'go.mod') {
      text.split('\n').forEach(l => {
        const m = l.trim().match(/^([a-z0-9./_~\-]+)\s+v([0-9][^\s]*)/i);
        if (m) deps.push({ name: m[1], version: m[2], ecosystem: 'go' });
      });
    } else if (base === 'Cargo.toml' || base === 'Cargo.lock') {
      const rx = /name\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"/g;
      let m; while ((m = rx.exec(text)) !== null) deps.push({ name: m[1], version: m[2], ecosystem: 'cargo' });
    } else if (base === 'pom.xml') {
      const rx = /<artifactId>([^<]+)<\/artifactId>\s*<version>([^<]+)<\/version>/g;
      let m; while ((m = rx.exec(text)) !== null) deps.push({ name: m[1].trim(), version: m[2].trim(), ecosystem: 'maven' });
    } else if (base === 'Gemfile.lock' || base === 'Gemfile') {
      const rx = /^\s{2,4}([a-z0-9_\-]+)\s+\(([^)]+)\)/gim;
      let m; while ((m = rx.exec(text)) !== null) deps.push({ name: m[1], version: m[2], ecosystem: 'gem' });
    } else if (base === 'composer.json' || base === 'composer.lock') {
      try {
        const j = JSON.parse(text);
        const all = { ...(j.require || {}), ...(j['require-dev'] || {}) };
        for (const [n, v] of Object.entries(all)) deps.push({ name: n, version: String(v), ecosystem: 'composer' });
        (j.packages || []).forEach(p => deps.push({ name: p.name, version: p.version, ecosystem: 'composer' }));
      } catch { /* lock may be parsed loosely */ }
    } else if (base === 'pyproject.toml') {
      const rx = /^\s*["']?([A-Za-z0-9_.\-]+)["']?\s*[=<>!~^]/gm;
      let m; while ((m = rx.exec(text)) !== null) deps.push({ name: m[1], version: '*', ecosystem: 'pypi' });
    }
  } catch { /* ignore */ }
  return deps.slice(0, 500);
}
const CRYPTO_DEP_RX = /(crypto|ssl|tls|sodium|nacl|bcrypt|argon|scrypt|jwt|jose|openssl|gnupg|pgp|forge|noble|elliptic|hash|md5|sha|aes|rsa|ecdsa|tls|ssh|cert|pki|x509|kms|vault|secret|cipher|noise|mbedtls|boringssl|wolfssl|botan|libgcrypt|nettle)/i;

function analyzeDockerfile(text) {
  const out = [];
  text.split('\n').forEach((ln, i) => {
    const t = ln.trim();
    if (/^FROM\s+/i.test(t)) out.push({ line: i + 1, kind: 'base-image', text: t.slice(0, 160) });
    if (/openssl|libssl|gnupg|openssh|ca-certificates|certbot/i.test(t)) out.push({ line: i + 1, kind: 'crypto-package', text: t.slice(0, 160) });
    if (/--insecure|verify\s*=\s*false|wget.*http:\/\/|curl.*http:\/\//i.test(t)) out.push({ line: i + 1, kind: 'insecure-fetch', text: t.slice(0, 160) });
    if (/^EXPOSE\s+/i.test(t)) out.push({ line: i + 1, kind: 'exposed-port', text: t.slice(0, 120) });
    if (/COPY\s+.*\.pem|COPY\s+.*\.key|ADD\s+.*\.pem/i.test(t)) out.push({ line: i + 1, kind: 'key-material-copy', text: t.slice(0, 160) });
  });
  return out;
}

/* ---------- main per-file scan ---------- */
let FIND_ID = 1;
const nid = () => 'F-' + String(FIND_ID++).padStart(4, '0');

export function scanTextFile(path, text) {
  const findings = [];
  const lines = text.split('\n');
  const base = baseOf(path);
  const ext = extOf(path);

  // 1) algorithm regex sweep (line-aware)
  for (const algo of ALGO_KB) {
    for (const rx of algo.rx) {
      const g = new RegExp(rx.source, rx.flags.includes('g') ? rx.flags : rx.flags + 'g');
      let m;
      // cap matches per algo per file to avoid noise explosion
      let count = 0;
      while ((m = g.exec(text)) !== null && count < 25) {
        const upto = text.slice(0, m.index);
        const lineNo = upto.split('\n').length;
        const code = (lines[lineNo - 1] || '').trim().slice(0, 220);
        // guess library from nearby imports
        const window = text.slice(Math.max(0, m.index - 1200), m.index + 200);
        const lib = (algo.libs || []).find(l => window.toLowerCase().includes(l.toLowerCase().split(':').pop())) || guessLib(text, algo.id);
        let sev = algo.severity;
        // escalations
        if (algo.id === 'TLS' && /rejectUnauthorized\s*:\s*false|VERIFY_NONE|InsecureSkipVerify\s*:\s*true/i.test(code)) sev = 'critical';
        if (algo.id === 'Random' && /(key|secret|nonce|iv|token|salt|password)/i.test(code)) sev = 'critical';
        else if (algo.id === 'Random') sev = 'high';
        if (algo.id === 'AES' && /ecb/i.test(code)) sev = 'critical';
        if ((algo.id === 'MD5' || algo.id === 'SHA1') && /(password|signature|sign|cert|hmac|token|auth)/i.test(code)) sev = 'critical';
        findings.push({
          id: nid(), file: path, line: lineNo, symbol: guessSymbol(code),
          algorithm: algo.id, algoLabel: algo.label, category: algo.cat,
          library: lib || '—', detector: 'Regex', confidence: algo.rx.length > 1 ? 0.82 : 0.76,
          severity: sev, quantum: algo.quantum, evidence: code || m[0].slice(0, 120),
          reason: buildReason(algo, code, path), weakIf: algo.weakIf
        });
        count++;
        if (m[0].length === 0) g.lastIndex++;
      }
    }
  }

  // 2) AST-lite for JS/TS/Py (raises confidence / adds context)
  if (['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs', 'vue'].includes(ext)) {
    const { calls, imports } = astLiteJS(text);
    const cryptoCalls = calls.filter(c => /(Cipher|Hash|Hmac|Sign|Verify|Encrypt|Decrypt|generateKey|subtle|pbkdf2|scrypt|randomBytes|jsonwebtoken|jwt|forge|crypto)/i.test(c.symbol + ' ' + c.code));
    for (const c of cryptoCalls.slice(0, 60)) {
      if (findings.some(f => f.file === path && f.line === c.line)) {
        const f = findings.find(f => f.file === path && f.line === c.line);
        f.detector = 'Regex + AST'; f.confidence = Math.min(0.97, f.confidence + 0.12); f.symbol = c.symbol;
      } else if (/(createCipher|createHash|createHmac|generateKey|subtle\.)/i.test(c.symbol + c.code)) {
        findings.push({
          id: nid(), file: path, line: c.line, symbol: c.symbol, algorithm: mapCallToAlgo(c.code),
          algoLabel: mapCallToAlgo(c.code), category: 'library', library: imports.find(i => /crypto|jose|jsonwebtoken|forge|noble|sodium/i.test(i)) || 'node:crypto/WebCrypto',
          detector: 'AST', confidence: 0.88, severity: 'medium', quantum: /rsa|ecdsa|ecdh|dh\b/i.test(c.code),
          evidence: c.code, reason: ['Structured API call detected via AST-lite parsing', 'Call: ' + c.symbol]
        });
      }
    }
  }
  if (ext === 'py') {
    const { calls, imports } = astLitePy(text);
    for (const c of calls.slice(0, 80)) {
      if (findings.some(f => f.file === path && f.line === c.line)) {
        const f = findings.find(f => f.file === path && f.line === c.line);
        f.detector = 'Regex + AST'; f.confidence = Math.min(0.97, f.confidence + 0.12); f.symbol = c.symbol;
      }
    }
    if (imports.length && findings.some(f => f.file === path)) {
      const libHit = imports.find(i => /crypto|Crypto|hashlib|hmac|jwt|ssl|OpenSSL/i.test(i));
      if (libHit) findings.filter(f => f.file === path && f.library === '—').forEach(f => { f.library = libHit; });
    }
  }

  // 3) secrets / PEM
  for (const s of SECRET_RX) {
    let sfl = s.rx.flags; if (!sfl.includes('g')) sfl += 'g'; if (!sfl.includes('m')) sfl += 'm';
    const g = new RegExp(s.rx.source, sfl);
    let m; let n = 0;
    while ((m = g.exec(text)) !== null && n < 10) {
      const lineNo = text.slice(0, m.index).split('\n').length;
      const code = (lines[lineNo - 1] || '').trim().slice(0, 160);
      findings.push({
        id: nid(), file: path, line: lineNo, symbol: '(secret material)', algorithm: s.id,
        algoLabel: s.label, category: 'secret', library: '—', detector: s.id.startsWith('PEM') ? 'PEM-scan' : 'Secret-scan',
        confidence: s.id === 'PEM-PRIVATE' ? 0.99 : 0.85, severity: s.sev, quantum: false,
        evidence: redact(code || m[0].slice(0, 80)), reason: [s.label + ' detected', 'Embedded key/secret material is extractable from this file']
      });
      n++;
      if (m[0].length === 0) g.lastIndex++;
    }
  }
  if (TLS_VERIFY_OFF_RX.test(text)) {
    const idx = text.search(TLS_VERIFY_OFF_RX);
    const lineNo = text.slice(0, idx).split('\n').length;
    findings.push({
      id: nid(), file: path, line: lineNo, symbol: '(tls verify)', algorithm: 'TLS', algoLabel: 'TLS verification disabled',
      category: 'protocol', library: '—', detector: 'Regex', confidence: 0.95, severity: 'critical', quantum: false,
      evidence: (lines[lineNo - 1] || '').trim().slice(0, 200),
      reason: ['Certificate verification explicitly disabled', 'Enables trivial MITM interception']
    });
  }

  // 4) entropy sweep (hidden/embedded key material)
  const entropyHits = [];
  const tokenRx = /[A-Za-z0-9+/=_-]{24,}/g;
  let tm; let checked = 0;
  while ((tm = tokenRx.exec(text)) !== null && checked < 2500) {
    checked++;
    const tok = tm[0];
    if (tok.length > 512) continue;
    const e = shannonEntropy(tok);
    if (e >= 4.6 && tok.length >= 28) {
      const lineNo = text.slice(0, tm.index).split('\n').length;
      entropyHits.push({ file: path, line: lineNo, tokenPreview: tok.slice(0, 12) + '…' + tok.slice(-6), len: tok.length, entropy: +e.toFixed(2) });
      if (entropyHits.length >= 40) break;
    }
  }
  for (const h of entropyHits.slice(0, 25)) {
    // skip if already covered by a secret finding on same line
    if (findings.some(f => f.file === path && f.line === h.line && f.category === 'secret')) continue;
    findings.push({
      id: nid(), file: path, line: h.line, symbol: '(high-entropy blob)', algorithm: 'ENTROPY',
      algoLabel: `High-entropy string (H=${h.entropy}, len=${h.len})`, category: 'hidden', library: '—',
      detector: 'Entropy-scan', confidence: 0.62, severity: 'medium', quantum: false,
      evidence: h.tokenPreview, reason: [`Shannon entropy ${h.entropy} ≥ 4.6 threshold`, 'May be embedded key/token/ciphertext — review manually']
    });
  }

  // 5) manifest deps
  let deps = [];
  if (isManifest(path)) {
    deps = parseManifest(base, text);
    for (const d of deps.filter(d => CRYPTO_DEP_RX.test(d.name))) {
      findings.push({
        id: nid(), file: path, line: findLineOf(lines, d.name), symbol: d.name, algorithm: 'DEP',
        algoLabel: `Crypto-relevant dependency: ${d.name}@${d.version}`, category: 'dependency', library: d.name,
        detector: 'Manifest', confidence: 0.9, severity: /md5|sha1|des|rc4|tripledes/i.test(d.name) ? 'high' : 'medium',
        quantum: /rsa|ecdsa|ecdh|dh\b|dsa|ed25519/i.test(d.name), evidence: `${d.ecosystem}: ${d.name}@${d.version}`,
        reason: [`Direct dependency (${d.ecosystem}) with crypto relevance`, 'Transitive crypto may hide behind this package']
      });
    }
  }

  // 6) Dockerfile
  let dockerNotes = [];
  if (isDockerfile(path) || base === 'docker-compose.yml' || base === 'docker-compose.yaml') {
    dockerNotes = analyzeDockerfile(text);
    for (const d of dockerNotes) {
      if (d.kind === 'insecure-fetch' || d.kind === 'key-material-copy') {
        findings.push({
          id: nid(), file: path, line: d.line, symbol: '(docker)', algorithm: 'DOCKER',
          algoLabel: d.kind === 'insecure-fetch' ? 'Insecure fetch in container build' : 'Key material copied into image',
          category: 'container', library: 'docker', detector: 'Dockerfile-scan', confidence: 0.9,
          severity: d.kind === 'key-material-copy' ? 'critical' : 'high', quantum: false,
          evidence: d.text, reason: [d.kind === 'key-material-copy' ? 'Private keys baked into image layers leak via registry' : 'Plaintext HTTP fetch in build is MITM-able']
        });
      }
    }
  }

  // 7) certificates
  let certs = [];
  if (/-----BEGIN CERTIFICATE-----/.test(text) || /\.(pem|crt|cer)$/i.test(path)) {
    certs = parseCertificatePem(text).map(c => ({ ...c, file: path }));
    for (const c of certs) {
      if (c.weak || c.expired || c.expiringSoon || (c.keyBits && c.keyBits < 2048)) {
        findings.push({
          id: nid(), file: path, line: 1, symbol: '(certificate)', algorithm: 'X509',
          algoLabel: `X.509 certificate: ${c.sigAlg}`, category: 'certificate', library: 'x509',
          detector: 'ASN.1-parse', confidence: 0.93,
          severity: c.weak || c.expired ? 'high' : 'medium',
          quantum: /rsa|ecdsa|dsa|ed25519/i.test(c.sigAlg || ''),
          evidence: `sig=${c.sigAlg} key≈${c.keyBits || '?'}bits valid:${c.notBefore || '?'}→${c.notAfter || '?'}`,
          reason: [
            ...(c.weak ? ['Weak signature algorithm (' + c.sigAlg + ')'] : ['Signature: ' + c.sigAlg]),
            ...(c.keyBits ? [`Approx key size ${c.keyBits} bits`] : []),
            ...(c.expired ? ['Certificate EXPIRED'] : c.expiringSoon ? ['Expires within 90 days'] : []),
          ]
        });
      }
    }
  }

  // dedupe: multiple patterns matching the same algo on the same line = one fact (boost confidence)
  const seen = new Set();
  const deduped = [];
  for (const f of findings) {
    const k = f.algorithm + '@' + f.file + ':' + f.line;
    if (seen.has(k)) {
      const prev = deduped.find(d => d.algorithm === f.algorithm && d.file === f.file && d.line === f.line);
      if (prev) prev.confidence = Math.min(0.97, prev.confidence + 0.04);
      continue;
    }
    seen.add(k); deduped.push(f);
  }
  for (const f of deduped) {
    if (!f.context) f.context = ctxLines(lines, f.line);
    if (f.category === 'secret' && f.context) f.context = f.context.map(c => ({ ...c, t: c.hit ? redact(c.t) : c.t }));
  }
  return { findings: deduped, deps, dockerNotes, certs, entropyHits };
}

function guessLib(text, algoId) {
  const t = text.slice(0, 4000).toLowerCase();
  const cands = ['node:crypto', 'crypto', 'cryptography', 'cryptojs', 'jose', 'jsonwebtoken', 'forge', 'openssl', 'javax.crypto', 'java.security', 'webcrypto', 'subtle', 'libsodium', 'nacl', 'hashlib', 'bcrypt', 'passlib', 'ethers', 'noble', 'openpgp', 'gnupg', 'mbedtls'];
  const hit = cands.find(c => t.includes(c.replace('node:', '')));
  return hit || '';
}
function guessSymbol(code = '') {
  const m = code.match(/([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(/);
  if (m) return m[1].slice(0, 60);
  const m2 = code.match(/^\s*(?:const|let|var|def|function|class)\s+([A-Za-z_]\w*)/);
  if (m2) return m2[1];
  return '(match)';
}
function mapCallToAlgo(code = '') {
  if (/rsa|publicEncrypt|privateDecrypt|RS256|RSASSA/i.test(code)) return 'RSA';
  if (/ecdsa|ES256|createSign/i.test(code)) return 'ECDSA';
  if (/ecdh|deriveBits|computeSecret/i.test(code)) return 'ECDH';
  if (/createHash|digest/i.test(code)) return /md5/i.test(code) ? 'MD5' : /sha1/i.test(code) ? 'SHA1' : 'SHA2';
  if (/createHmac/i.test(code)) return 'HMAC';
  if (/Cipheriv|AES/i.test(code)) return 'AES';
  if (/jwt|jose/i.test(code)) return 'JWT';
  return 'CRYPTO-API';
}
function buildReason(algo, code, path) {
  const r = [`${algo.label} usage matched (${algo.cat})`];
  if (algo.quantum) r.push('Quantum-vulnerable: Shor algorithm breaks this on a cryptographically-relevant quantum computer');
  if (algo.weakIf) r.push('Weak when: ' + algo.weakIf);
  if (/route|controller|api|server|public|handler|endpoint|app\./i.test(path)) r.push('Located in potentially externally-exposed path: ' + path);
  if (/test|spec|mock|example|demo/i.test(path)) r.push('Note: inside test/example path — confirm production relevance');
  return r;
}
function findLineOf(lines, needle) {
  const i = lines.findIndex(l => l.includes(needle));
  return i >= 0 ? i + 1 : 1;
}
function redact(s) {
  s = String(s || '');
  if (s.length <= 24) return s.slice(0, 8) + '•••(redacted)';
  return s.slice(0, 16) + '•••(redacted — full value hidden)';
}
function ctxLines(lines, n, w = 2) {
  const out = [];
  for (let i = Math.max(1, n - w); i <= Math.min(lines.length, n + w); i++) {
    out.push({ n: i, t: (lines[i - 1] || '').slice(0, 200), hit: i === n });
  }
  return out;
}
/* whole-file byte entropy (bits/byte over raw bytes) — the Hidden Encryption signal */
export function byteEntropy(bytes) {
  const n = Math.min((bytes && bytes.length) || 0, 300000);
  if (!n) return 0;
  const f = new Array(256).fill(0);
  for (let i = 0; i < n; i++) f[bytes[i]]++;
  let e = 0;
  for (let i = 0; i < 256; i++) {
    if (!f[i]) continue;
    const p = f[i] / n;
    e -= p * Math.log2(p);
  }
  return +e.toFixed(2);
}
/* which engine layer produced a finding (L1..L8 multi-layer engine) */
export const LAYERS = [
  'L1 · Regex patterns', 'L2 · AST-lite', 'L3 · Secrets / PEM', 'L4 · Token entropy',
  'L5 · Manifests', 'L6 · Containers', 'L7 · Certificates (ASN.1)', 'L8 · Binary strings'
];
export function layerOf(f) {
  if (f.category === 'secret') return LAYERS[2];
  if (f.category === 'hidden') return LAYERS[3];
  if (f.category === 'dependency') return LAYERS[4];
  if (f.category === 'container') return LAYERS[5];
  if (f.category === 'certificate') return LAYERS[6];
  if (/strings/i.test(f.detector || '')) return LAYERS[7];
  if (/AST/i.test(f.detector || '')) return LAYERS[1];
  return LAYERS[0];
}
/* aggregate quantum exposure 0–100 (heuristic mean, quantum bump, capped) */
const SEV_NUM = { critical: 100, high: 65, medium: 35, low: 10, info: 2 };
export function exposureScore(findings) {
  if (!findings || !findings.length) return { score: 0, band: 'NO FINDINGS' };
  const avg = findings.reduce((a, f) => a + (SEV_NUM[f.severity] ?? 5), 0) / findings.length;
  const bump = Math.min(12, findings.filter(f => f.quantum).length * 0.5);
  const score = Math.round(Math.min(100, avg + bump));
  return { score, band: score >= 70 ? 'HIGH RISK' : score >= 40 ? 'MODERATE RISK' : score >= 15 ? 'LOW RISK' : 'MINIMAL' };
}
/* crypto agility 0–100: baseline 60, adjusted by real scan signals */
const DEPRECATED_ALGOS = new Set(['MD5', 'SHA1', 'DES', '3DES', 'RC4', 'Blowfish', 'ECB', 'TLS10', 'DSA']);
export function agilityScore(scan) {
  let score = 60;
  const factors = [];
  const fs = scan.findings || [];
  const pqc = fs.filter(f => f.category === 'pqc').length;
  if (pqc > 0) { score += 15; factors.push({ label: `Post-quantum algorithm already referenced (${pqc})`, delta: 15 }); }
  const files = new Set(fs.map(f => f.file)).size;
  if (fs.length > 50 && files > 10) { score -= 10; factors.push({ label: `Crypto calls scattered across many sites (${fs.length} across ${files} files)`, delta: -10 }); }
  const dep = fs.filter(f => DEPRECATED_ALGOS.has(f.algorithm)).length;
  if (dep > 0) { const d = -Math.min(15, dep); score += d; factors.push({ label: `${dep} deprecated algorithm occurrence(s) found`, delta: d }); }
  const distinct = new Set(fs.map(f => f.algorithm)).size;
  if (distinct > 10) { score -= 5; factors.push({ label: `${distinct} distinct algorithms in use (more to coordinate)`, delta: -5 }); }
  if ((scan.stats?.deps || 0) > 0) { score += 5; factors.push({ label: `${scan.stats.deps} declared dependenc(ies) found via manifest (supports coordinated upgrades)`, delta: 5 }); }
  score = Math.max(0, Math.min(100, Math.round(score)));
  return { score, factors, band: score >= 70 ? 'HIGH' : score >= 40 ? 'MODERATE' : 'LOW' };
}
/* explainable per-finding score 0–10 with user-set business context */
export function explainScore(f, sensitivity = 'Internal', criticality = 'Medium') {
  const base = { critical: 7, high: 5, medium: 3, low: 1, info: 0.5 }[f.severity] ?? 1;
  const factors = [{ label: 'Algorithm/severity baseline', delta: base }];
  const push = (label, delta) => { if (delta) factors.push({ label, delta }); };
  if (f.quantum) push('Quantum-vulnerable (Shor)', 1.5);
  if (f.category === 'secret') push('Embedded secret material', 1.5);
  if (/route|api|server|public|controller|endpoint/i.test(f.file)) push('Externally-exposed path', 0.75);
  if (/test|spec|mock|example|fixture/i.test(f.file)) push('Test/fixture path (lower weight)', -1);
  push(`Data sensitivity: ${sensitivity} (user-set context)`, { Internal: 0.25, Confidential: 1, Restricted: 1.75 }[sensitivity] ?? 0.25);
  push(`Business criticality: ${criticality} (user-set context)`, { Low: 0, Medium: 0.5, High: 1.25, Critical: 2 }[criticality] ?? 0.5);
  let score = factors.reduce((a, x) => a + x.delta, 0);
  score = Math.max(0, Math.min(10, Math.round(score * 10) / 10));
  return { score, band: score >= 7 ? 'P1' : score >= 4.5 ? 'P2' : score >= 2 ? 'P3' : 'P4', factors };
}
/* SBOM (libraries) alongside CBOM (crypto assets) — both CycloneDX-flavoured */
export function buildSbom(scan) {
  const ts = new Date().toISOString();
  const seen = new Map();
  for (const d of (scan.deps || [])) {
    const k = d.ecosystem + ':' + d.name + '@' + d.version;
    if (!seen.has(k)) seen.set(k, { 'bom-ref': 'pkg:' + k, type: 'library', name: d.name, version: d.version, scope: 'required', properties: [{ name: 'ecosystem', value: d.ecosystem }, { name: 'manifest', value: d.file }] });
  }
  return {
    bomFormat: 'CycloneDX', specVersion: '1.5', serialNumber: 'urn:uuid:cryptora-sbom-' + Date.now().toString(36),
    version: 1, metadata: { timestamp: ts, component: { type: 'application', name: scan.project || 'cryptora-scan' }, tools: [{ vendor: 'KRYPTX', name: 'CRYPTORA manifest parser', version: '1.0-browser' }] },
    components: [...seen.values()].slice(0, 2000)
  };
}

/* ---------- binary / doc scan ---------- */
export async function scanBinaryFile(path, bytes) {
  const format = detectFormat(bytes, path);
  const hash = await sha256Hex(bytes);
  const strings = printableStrings(bytes, 6, 6000);
  const joined = strings.join('\n');
  const { findings } = scanTextFile(path + ' ⟦extracted-strings⟧', joined.slice(0, 300000));
  // retag
  findings.forEach(f => { f.detector = f.detector + ' (strings)'; f.confidence = Math.max(0.4, f.confidence - 0.15); });
  const sigHits = [];
  for (const algo of ALGO_KB.slice(0, 24)) {
    for (const rx of algo.rx.slice(0, 2)) {
      const g = new RegExp(rx.source, 'i');
      if (g.test(joined)) { sigHits.push(algo.id); break; }
    }
  }
  return {
    path, format, size: bytes.length, sha256: hash,
    stringsExamined: strings.length, sigHits: [...new Set(sigHits)],
    findings: findings.slice(0, 120)
  };
}

/* ---------- risk engine ---------- */
const SEV_W = { critical: 100, high: 75, medium: 45, low: 20, info: 5 };
export function scoreFindings(findings, ctx = {}) {
  const { sensitivity = 3, criticality = 3, exposure = 3 } = ctx; // 1..5
  const mult = 1 + (sensitivity - 3) * 0.08 + (criticality - 3) * 0.08 + (exposure - 3) * 0.1;
  return findings.map(f => {
    let s = SEV_W[f.severity] || 10;
    if (f.quantum) s += 12;
    if (f.category === 'secret') s += 10;
    if (/route|api|server|public|controller|endpoint/i.test(f.file)) s += 8;
    if (/test|spec|mock|example/i.test(f.file)) s -= 15;
    s = Math.max(1, Math.min(100, Math.round(s * mult)));
    const band = s >= 85 ? 'Critical' : s >= 65 ? 'High' : s >= 40 ? 'Medium' : s >= 15 ? 'Low' : 'Info';
    return { ...f, riskScore: s, riskBand: band, layer: layerOf(f) };
  }).sort((a, b) => b.riskScore - a.riskScore);
}

/* ---------- Mosca ---------- */
export function mosca(dataLifetime = 10, migrationYears = 3, threatHorizon = 12) {
  const sum = dataLifetime + migrationYears;
  const gap = sum - threatHorizon;
  return {
    x: dataLifetime, y: migrationYears, z: threatHorizon, sum, gap,
    verdict: gap > 0 ? 'ACT NOW — data outlives quantum-safe horizon' : gap > -3 ? 'PLAN NOW — horizon approaching' : 'MONITOR — within horizon',
    urgent: gap > 0
  };
}

/* ---------- CBOM (CycloneDX-flavoured) ---------- */
export function buildCbom(scored, meta = {}) {
  const ts = new Date().toISOString();
  const components = scored.slice(0, 2000).map(f => ({
    'bom-ref': f.id,
    type: 'cryptographic-asset',
    name: `${f.algoLabel} @ ${baseOf(f.file)}:${f.line}`,
    version: f.library && f.library !== '—' ? f.library : undefined,
    evidences: { occurrences: [{ location: `${f.file}#${f.line}`, symbol: f.symbol, detector: f.detector, confidence: f.confidence }] },
    cryptoProperties: {
      assetType: f.category, algorithm: f.algorithm, quantumVulnerable: !!f.quantum,
      severity: f.severity, riskScore: f.riskScore, riskBand: f.riskBand
    },
    properties: (f.reason || []).map(r => ({ name: 'risk-reason', value: r }))
  }));
  return {
    bomFormat: 'CycloneDX', specVersion: '1.5', serialNumber: 'urn:uuid:cryptora-' + Date.now().toString(36),
    version: 1, metadata: {
      timestamp: ts, component: { type: 'application', name: meta.project || 'cryptora-scan', version: 'scan-' + ts },
      tools: [{ vendor: 'KRYPTX', name: 'CRYPTORA static scanner', version: '1.0-browser' }]
    },
    components
  };
}

/* ---------- recommendations ---------- */
export function recommendFor(finding) {
  const kb = ALGO_KB.find(a => a.id === finding.algorithm);
  if (kb) return { current: kb.label, ...kb.rec, nist: 'ML-KEM FIPS 203 · ML-DSA FIPS 204 · SLH-DSA FIPS 205' };
  if (finding.algorithm === 'X509') return { current: 'X.509 (classical)', hybrid: 'Hybrid certificates (classical + ML-DSA dual-sign)', pqc: 'PQC-ready PKI (ML-DSA-65 / SLH-DSA)', note: 'Rotate weak/expired certs first; pilot hybrid chain.', nist: 'FIPS 204/205' };
  if (finding.category === 'secret') return { current: 'Embedded secret/key', hybrid: '—', pqc: 'Vault/KMS + rotation (never embed)', note: 'Revoke exposed material, rotate, move to KMS/HSM.', nist: '—' };
  if (finding.algorithm === 'ENTROPY') return { current: 'Unknown high-entropy blob', hybrid: '—', pqc: 'Identify then classify (key/ciphertext/token)', note: 'Triage manually; if key → rotate into KMS.', nist: '—' };
  if (finding.algorithm === 'DEP') return { current: finding.library, hybrid: '—', pqc: 'Upgrade to maintained, PQC-tracked release', note: 'Pin + audit transitive crypto deps.', nist: '—' };
  return { current: finding.algoLabel, hybrid: '—', pqc: 'Review against NIST PQC standards', note: 'Manual review.', nist: 'FIPS 203/204/205' };
}

/* ---------- GitHub fetch (public repos, client-side) ---------- */
export function parseGithubUrl(url = '') {
  const m = url.trim().match(/github\.com\/([^/\s]+)\/([^/\s#?]+)/i);
  if (!m) return null;
  return { owner: m[1], repo: m[2].replace(/\.git$/i, '') };
}
export async function fetchRepoFileList(owner, repo, branch, onProgress) {
  const headers = { Accept: 'application/vnd.github+json' };
  let br = branch;
  if (!br) {
    const r = await fetch(`https://api.github.com/repos/${owner}/${repo}`, { headers });
    if (r.status === 403) throw new Error('GitHub rate limit (60 req/hr unauthenticated). Try again later or upload a ZIP.');
    if (!r.ok) throw new Error(`Repository not found or private (HTTP ${r.status}). Public repos only.`);
    const j = await r.json();
    br = j.default_branch || 'main';
  }
  onProgress && onProgress(`Listing tree @ ${br}…`);
  const t = await fetch(`https://api.github.com/repos/${owner}/${repo}/git/trees/${encodeURIComponent(br)}?recursive=1`, { headers });
  if (t.status === 403) throw new Error('GitHub rate limit reached. Try again later or upload a ZIP.');
  if (!t.ok) throw new Error(`Cannot list repo tree (HTTP ${t.status}). Check branch name.`);
  const j = await t.json();
  if (j.truncated) { /* note */ }
  const files = (j.tree || [])
    .filter(n => n.type === 'blob' && n.size < 220000)
    .filter(n => {
      const b = baseOf(n.path);
      if (isManifest(n.path) || isDockerfile(n.path)) return true;
      return CODE_EXT.has(extOf(n.path)) && !/min\.js$|\.map$|dist\/|build\/|vendor\/|node_modules\/|\.lock$/i.test(n.path);
    })
    .slice(0, 40);
  return { branch: br, files };
}
export async function fetchRepoFiles(owner, repo, branch, list, onProgress) {
  const out = [];
  let i = 0;
  for (const f of list) {
    i++;
    onProgress && onProgress(`Fetching ${i}/${list.length} ${f.path}`);
    try {
      const r = await fetch(`https://raw.githubusercontent.com/${owner}/${repo}/${encodeURIComponent(branch)}/${f.path}`);
      if (!r.ok) continue;
      const buf = await r.arrayBuffer();
      out.push({ path: f.path, bytes: new Uint8Array(buf) });
    } catch { /* skip */ }
    await new Promise(r => setTimeout(r, 60));
  }
  return out;
}

/* ---------- orchestration ---------- */
const LOCK_RX = /(package-lock\.json|yarn\.lock|pnpm-lock\.ya?ml|Gemfile\.lock|composer\.lock|Cargo\.lock|go\.sum|poetry\.lock|packages\.lock\.json)$/i;
const MIN_RX = /(\.min\.js|\.bundle\.js|\/dist\/|\/build\/|\.chunk\.js)$/i;

export async function runScan(fileEntries, meta, onProgress, opts = {}) {
  // fileEntries: [{path, bytes:Uint8Array}] · opts: {skipLockfiles, skipMinified}
  const { skipLockfiles = true, skipMinified = true } = opts || {};
  FIND_ID = 1;
  const t0 = Date.now();
  const textFiles = [];
  const binaries = [];
  const allFindings = [];
  const allDeps = [];
  const allCerts = [];
  const dockerAll = [];
  const fileEntropy = [];
  const excluded = [];
  let i = 0;
  for (const fe of fileEntries) {
    i++;
    if (skipLockfiles && LOCK_RX.test(fe.path)) { excluded.push({ path: fe.path, reason: 'lockfile skipped (integrity-hash noise)' }); continue; }
    if (skipMinified && MIN_RX.test(fe.path)) { excluded.push({ path: fe.path, reason: 'minified/build artifact skipped' }); continue; }
    onProgress && onProgress(`Scanning ${i}/${fileEntries.length} · ${fe.path}`, i / fileEntries.length);
    const bin = looksBinary(fe.bytes);
    const big = fe.bytes.length > 600000;
    if (bin || big || /\.(pdf|docx|xlsx|exe|dll|so|o|a|bin|dat|jar|apk|woff2?|ttf|png|jpe?g|gif|mp4|zip|gz|tar)$/i.test(fe.path)) {
      if (bin || big) {
        try {
          const b = await scanBinaryFile(fe.path, fe.bytes.slice(0, 1200000));
          binaries.push({ path: b.path, format: b.format, size: b.size, sha256: b.sha256, stringsExamined: b.stringsExamined, sigHits: b.sigHits });
          allFindings.push(...b.findings);
          fileEntropy.push({ path: fe.path, bytes: fe.bytes.length, entropy: byteEntropy(fe.bytes) });
        } catch { /* ignore */ }
        continue;
      }
    }
    const text = bytesToText(fe.bytes.slice(0, 600000));
    textFiles.push({ path: fe.path, size: fe.bytes.length, lines: text.split('\n').length });
    fileEntropy.push({ path: fe.path, bytes: fe.bytes.length, entropy: byteEntropy(fe.bytes) });
    try {
      const r = scanTextFile(fe.path, text);
      allFindings.push(...r.findings.slice(0, 400));
      r.deps.forEach(d => allDeps.push({ ...d, file: fe.path }));
      r.certs.forEach(c => allCerts.push(c));
      r.dockerNotes.forEach(d => dockerAll.push({ ...d, file: fe.path }));
    } catch { /* ignore */ }
    if (i % 4 === 0) await new Promise(r => setTimeout(r, 0)); // keep UI alive
  }
  onProgress && onProgress('L9 · Scoring risk + building CBOM…', 0.94);
  await new Promise(r => setTimeout(r, 30));
  const scored = scoreFindings(allFindings, meta.riskCtx);
  const cbom = buildCbom(scored, { project: meta.project });
  const ms = Date.now() - t0;
  const layers = LAYERS.map(layer => ({ layer, count: scored.filter(f => f.layer === layer).length }));
  const ranked = [...fileEntropy].sort((a, b) => b.entropy - a.entropy);
  const exp = exposureScore(scored);
  onProgress && onProgress(`Done — ${scored.length} findings · exposure ${exp.score}/100 · ${excluded.length} excluded`, 1);
  return {
    id: 'scan-' + Date.now().toString(36),
    source: meta.source, project: meta.project || 'cryptora-scan',
    startedAt: new Date(t0).toISOString(), completedAt: new Date().toISOString(), durationMs: ms,
    files: textFiles, binaries,
    findings: scored, deps: allDeps, certs: allCerts, docker: dockerAll,
    fileEntropy: ranked, excluded, layers,
    cbom,
    stats: {
      filesScanned: textFiles.length + binaries.length,
      textFiles: textFiles.length, binaryFiles: binaries.length,
      findings: scored.length,
      critical: scored.filter(f => f.severity === 'critical').length,
      high: scored.filter(f => f.severity === 'high').length,
      medium: scored.filter(f => f.severity === 'medium').length,
      low: scored.filter(f => f.severity === 'low').length,
      info: scored.filter(f => f.severity === 'info').length,
      quantum: scored.filter(f => f.quantum).length,
      secrets: scored.filter(f => f.category === 'secret').length,
      hidden: scored.filter(f => f.category === 'hidden').length,
      pqc: scored.filter(f => f.category === 'pqc').length,
      distinctAlgos: new Set(scored.map(f => f.algorithm)).size,
      excluded: excluded.length,
      peakEntropy: ranked.length ? ranked[0].entropy : 0,
      highEntropyFiles: ranked.filter(f => f.entropy >= 6.6).length,
      certs: allCerts.length, deps: allDeps.length
    }
  };
}

export function diffScans(oldS, newS) {
  const key = f => `${f.algorithm}@${f.file}:${f.line}:${(f.evidence || '').slice(0, 40)}`;
  const a = new Map((oldS?.findings || []).map(f => [key(f), f]));
  const b = new Map((newS?.findings || []).map(f => [key(f), f]));
  const added = [], removed = [], kept = [];
  for (const [k, f] of b) { if (!a.has(k)) added.push(f); else kept.push(f); }
  for (const [k, f] of a) { if (!b.has(k)) removed.push(f); }
  return { added, removed, kept };
}

export const KB_EXPLAIN = {
  RSA: 'RSA relies on integer factorisation. Shor’s algorithm breaks it on a large quantum computer. Harvest-now-decrypt-later applies to RSA-encrypted data with long secrecy lifetimes.',
  ECDSA: 'ECDSA relies on elliptic-curve discrete logs — broken by Shor. Signatures are forgeable post-quantum; migrate to ML-DSA with hybrid dual-signing.',
  ECDH: 'ECDH key exchange is Shor-broken. Session keys recorded today decrypt later. Hybrid X25519+ML-KEM-768 is the standard transition.',
  DH: 'Classic Diffie-Hellman is Shor-broken. Use hybrid KEM (ML-KEM-768) for key establishment.',
  DSA: 'DSA is legacy and quantum-broken. Retire it; use ML-DSA.',
  EdDSA: 'Ed25519 is classically excellent but still discrete-log based → Shor-broken. Dual-sign with ML-DSA during transition.',
  AES: 'AES-256 resists Grover with full margin; AES-128 drops to ~64-bit quantum strength. Use GCM/ChaCha20-Poly1305, never ECB.',
  MD5: 'MD5 is collision-broken since 2004 (chosen-prefix since 2009). Never for signatures, certs, or integrity of untrusted data.',
  SHA1: 'SHA-1 is collision-broken (SHAttered, 2017). Migrate to SHA-384/512 or SHA3.',
  TLS: 'TLS < 1.2 is deprecated. TLS 1.3 with PQC hybrid groups is the target. Verification-disabled code voids all transport security.',
  JWT: 'JWT security = algorithm + key handling. Forbid "none", pin expected algs, and plan RS/ES → PQC signature migration.',
};
