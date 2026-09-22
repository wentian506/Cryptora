import React from 'react';

export default function Landing({ onLaunch, onSignIn }) {
  return (
    <div className="landing">
      <header className="land-nav">
        <div className="land-brand"><span className="brand-mark">◉</span><b>CRYPTORA</b><small>ENCRYPT · PROTECT · TRUST</small></div>
        <nav>
          <a href="#how">How it works</a><a href="#features">Platform</a><a href="#pqc">PQC</a><a href="#trust">Trust</a><a href="#contact">Contact</a>
        </nav>
        <div>
          <button className="btn sm ghost" onClick={onSignIn}>Sign in</button>{' '}
          <button className="btn sm primary" onClick={onLaunch}>Launch App →</button>
        </div>
      </header>

      <section className="land-hero">
        <p className="kicker">CRYPTOGRAPHIC RISK &amp; MIGRATION INTELLIGENCE · TEAM KRYPTX · SIH PS-26164</p>
        <h1>Find every secret your code<br />is keeping from <span className="grad">you.</span></h1>
        <p className="lede">CRYPTORA discovers where cryptography lives in your software, proves each finding with evidence, shows what quantum computers break first, and plans a safe classical → hybrid → PQC migration.</p>
        <div className="land-cta">
          <button className="btn primary" onClick={onLaunch}>⇪ Scan your code now</button>
          <button className="btn" onClick={onSignIn}>Sign in / Create account</button>
        </div>
        <div className="land-badges mono">
          <span>✓ runs in your browser</span><span>✓ no source ever uploaded*</span><span>✓ CycloneDX CBOM</span><span>✓ FIPS 203/204/205 paths</span>
        </div>
      </section>

      <section className="land-strip mono" id="how">
        {['Discover', 'Evidence', 'CBOM', 'Risk', 'Prioritize', 'Recommend', 'Migrate', 'Validate'].map((s, i, a) => (
          <React.Fragment key={s}><span className="lstep">{i + 1}. {s}</span>{i < a.length - 1 ? <span className="arr">→</span> : null}</React.Fragment>
        ))}
      </section>

      <section className="land-grid" id="features">
        {[
          ['⌕ Crypto Discovery', '~30 algorithms, modes & protocols. Regex + AST-lite parsing, hardcoded-secret & entropy sweeps. Every hit carries file, line, detector & confidence.'],
          ['▤ Evidence + CBOM', 'CycloneDX-flavoured software bill of materials generated from real scan evidence — view, filter, export. Nothing invented.'],
          ['⎇ Dependency Graph', 'Manifest parsing across npm, PyPI, Go, Cargo, Maven & more. Crypto-relevant packages traced to capability.'],
          ['◔ Quantum + Business Risk', 'Severity × quantum exposure × secrets × path exposure, tuned by your data sensitivity & criticality. Reasons always shown.'],
          ['⚡ What Will Break?', 'Mosca-style prioritization: data lifetime + migration time vs your threat horizon. Break-first order, honestly computed.'],
          ['→ Hybrid Migration', 'Classical → hybrid → PQC roadmaps per finding, tracked Discovered → Validated, with rollback plans & rescan proof.'],
        ].map(([t, d]) => <div className="land-card" key={t}><h3>{t}</h3><p>{d}</p></div>)}
      </section>

      <section className="land-split" id="pqc">
        <div>
          <p className="kicker">NIST PQC ALIGNMENT</p>
          <h2>Standard crypto in.<br />Standard PQC out.</h2>
          <p>CRYPTORA invents no new cryptography. It maps what it finds to <b>ML-KEM (FIPS 203)</b>, <b>ML-DSA (FIPS 204)</b> and <b>SLH-DSA (FIPS 205)</b> — with hybrid stepping-stones (X25519+ML-KEM, dual signatures) for safe transition. No quantum hardware needed.</p>
        </div>
        <div className="codebox">RSA-2048        →  RSA + ML-KEM-768  →  ML-KEM-768   (FIPS 203){'\n'}ECDSA P-256     →  ECDSA + ML-DSA    →  ML-DSA-65    (FIPS 204){'\n'}ECDH / X25519   →  X25519 + ML-KEM   →  ML-KEM-768   (FIPS 203){'\n'}MD5 / SHA-1     →  SHA-384 / SHA-512 →  SHA3 / BLAKE2{'\n'}DES / RC4 / ECB  →  AES-256-GCM       →  keep (Grover-safe)</div>
      </section>

      <section className="land-split" id="trust">
        <div className="card">
          <p className="kicker">SECURITY &amp; PRIVACY</p>
          <h2>Your code stays yours.</h2>
          <ul className="mono land-list">
            <li>✓ Scanning runs locally in your browser — source never uploaded*</li>
            <li>✓ Secrets redacted in UI, never logged</li>
            <li>✓ Scanned code is never executed</li>
            <li>✓ Signed-in sync stores results in <i>your</i> backend/MySQL</li>
            <li>✓ Ownership checks on every project &amp; scan (IDOR-safe)</li>
          </ul>
          <p className="dim mono" style={{ fontSize: 11 }}>*Except direct GitHub/raw fetches you explicitly request, which go browser-to-host.</p>
        </div>
        <div className="card" id="contact">
          <p className="kicker">CONTACT · TEAM KRYPTX</p>
          <h2>Talk to the team.</h2>
          <p className="mono muted" style={{ fontSize: 12.5, lineHeight: 1.8 }}>Built for Smart India Hackathon 2026 — Problem Statement 26164.<br />Encrypt. Protect. Trust.</p>
          <div className="mono" style={{ fontSize: 12.5, lineHeight: 2 }}>
            <div>✉ <a href="mailto:team-kryptx@example.com">team-kryptx@example.com</a></div>
            <div>▣ Project repo: <span className="dim">see /docs in this workspace</span></div>
          </div>
          <button className="btn primary mt" onClick={onLaunch}>Open the live demo →</button>
        </div>
      </section>

      <footer className="land-foot mono">CRYPTORA · Encrypt. Protect. Trust. · © 2026 Team KRYPTX · Demo build: heuristic static analysis, not a substitute for full audit.</footer>
    </div>
  );
}
