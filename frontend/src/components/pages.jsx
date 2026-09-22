import React, { useEffect, useMemo, useState } from 'react';
import JSZip from 'jszip';
import { Sev, QTag, Empty, Stat, FlowStrip, Donut, HBar, Gauge, LogTerminal, download, downloadBlob, AreaChart, FactorBars, DivBar, SegTabs, MiniGauge } from './ui.jsx';
import { recommendFor, mosca, diffScans, KB_EXPLAIN, ALGO_KB, exposureScore, agilityScore, explainScore, buildSbom } from '../scanner/engine.js';

/* ================= shared ================= */
export function FindingModal({ f, onClose }) {
  if (!f) return null;
  const rec = recommendFor(f);
  return (
    <div className="modal-scrim" onClick={onClose}>
      <div className="modal" onClick={e => e.stopPropagation()}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <h3 style={{ flex: 1 }}>{f.algoLabel}</h3>
          <button className="btn sm ghost" onClick={onClose}>✕ Close</button>
        </div>
        <div className="mono dim" style={{ fontSize: 11 }}>{f.id} · {f.file}:{f.line}</div>
        <div style={{ margin: '10px 0', display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          <Sev level={f.severity} /><QTag quantum={f.quantum} />
          <span className="tag">{f.category}</span><span className="tag">{f.detector}</span>
          {f.layer ? <span className="tag">{f.layer}</span> : null}
          <span className="tag">confidence {(f.confidence * 100).toFixed(0)}%</span>
          {f.riskScore != null ? <span className="tag">risk {f.riskScore} ({f.riskBand})</span> : null}
        </div>
        <dl className="kv">
          <dt>File</dt><dd>{f.file}</dd>
          <dt>Line</dt><dd>{f.line}</dd>
          <dt>Symbol</dt><dd>{f.symbol}</dd>
          <dt>Library</dt><dd>{f.library}</dd>
        </dl>
        <div className="mono dim" style={{ fontSize: 10.5, letterSpacing: 1, margin: '10px 0 6px' }}>EVIDENCE (SECRET VALUES REDACTED)</div>
        <div className="codebox">{f.evidence}</div>
        {f.context && f.context.length > 1 ? (
          <><div className="mono dim" style={{ fontSize: 10.5, letterSpacing: 1, margin: '10px 0 6px' }}>LINE {f.line} IN CONTEXT</div>
            <div className="codebox">{f.context.map(c => `${c.hit ? '›' : ' '} ${c.n}: ${c.t}`).join('\n')}</div></>
        ) : null}
        <div className="mono dim" style={{ fontSize: 10.5, letterSpacing: 1, margin: '14px 0 6px' }}>WHY THIS RISK</div>
        <ul className="mono" style={{ fontSize: 11.5, color: '#c9d6ea', lineHeight: 1.8, margin: '0 0 0 18px', padding: 0 }}>
          {(f.reason || []).map((r, i) => <li key={i}>{r}</li>)}
        </ul>
        <div className="recbox">
          <div className="mono" style={{ fontSize: 11.5, lineHeight: 1.8 }}>
            <div><b>Current →</b> {rec.current}</div>
            <div><b>Hybrid →</b> {rec.hybrid}</div>
            <div><b>PQC target →</b> {rec.pqc}</div>
            <div className="dim">{rec.note}</div>
            <div className="dim">Standards: {rec.nist}</div>
          </div>
        </div>
      </div>
    </div>
  );
}

export function FindingTable({ rows, onOpen, compact }) {
  if (!rows.length) return <div className="card muted mono" style={{ fontSize: 12 }}>No findings match this filter. (This is computed from your scan — not an error.)</div>;
  return (
    <div className="tbl-wrap">
      <table className="tbl">
        <thead><tr>
          <th>ID</th><th>Severity</th><th>Finding</th><th>File</th><th>Detector</th><th>Risk</th>
        </tr></thead>
        <tbody>
          {rows.slice(0, compact || 500).map(f => (
            <tr key={f.id}>
              <td><button className="rowbtn" onClick={() => onOpen(f)}>{f.id}</button></td>
              <td><Sev level={f.severity} /></td>
              <td>
                <button className="rowbtn" onClick={() => onOpen(f)} style={{ color: '#f2f5fa' }}>{f.algoLabel}</button>
                <div style={{ marginTop: 3 }}><QTag quantum={f.quantum} /> <span className="tag">{f.category}</span></div>
              </td>
              <td className="mono" style={{ fontSize: 11 }}>{f.file}:{f.line}<div className="dim">{f.symbol}</div></td>
              <td><span className="tag">{f.detector}</span>{f.layer ? <div style={{ marginTop: 3 }}><span className="tag">{f.layer.split(' ')[0]}</span></div> : null}<div className="dim mono" style={{ fontSize: 10 }}>{(f.confidence * 100).toFixed(0)}%</div></td>
              <td className="mono" style={{ fontSize: 12 }}><b>{f.riskScore}</b> <span className="dim">{f.riskBand}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function topAlgos(scan, quantumOnly) {
  const c = {};
  scan.findings.filter(f => !quantumOnly || f.quantum).forEach(f => { c[f.algorithm] = (c[f.algorithm] || 0) + 1; });
  return Object.entries(c).sort((a, b) => b[1] - a[1]).slice(0, 4).map(([k, v]) => `${k} ×${v}`);
}
const GREEN = new Set(['ML-KEM', 'ML-DSA', 'SLH-DSA', 'SHA2', 'SHA3', 'BLAKE2', 'ChaCha20', 'TLS13', 'AES', 'Argon2', 'bcrypt', 'scrypt', 'HMAC', 'PBKDF2', 'NaCl', 'WebCrypto']);
const ORANGE = new Set(['RSA', 'ECDSA', 'ECDH', 'EdDSA', 'DH', 'DSA', 'JWT', 'PGP', 'SSH', 'OpenSSL']);
const RED = new Set(['MD5', 'SHA1', 'DES', '3DES', 'RC4', 'Blowfish', 'ECB', 'CBC', 'TLS10', 'Random', 'PEM-PRIVATE', 'ASSIGN-SECRET', 'AWS-KEY', 'JWT-TOKEN']);
function algoColor(a) {
  if (GREEN.has(a)) return '#22c55e';
  if (ORANGE.has(a)) return '#f97316';
  if (RED.has(a)) return '#ef4444';
  return '#7c3aed';
}
function shortAlgo(a, label) {
  const map = { ECDSA: 'ECC / ECDSA', ECDH: 'ECC / ECDH', EdDSA: 'ECC / Ed25519', TLS10: 'TLS 1.0/1.1', TLS13: 'TLS 1.2/1.3', SHA2: 'SHA-256 / SHA-', 'ML-KEM': 'Post-quantum', 'ML-DSA': 'Post-quantum', 'SLH-DSA': 'Post-quantum' };
  if (map[a]) return map[a];
  return (label || a).split('(')[0].trim().slice(0, 16);
}

/* ================= 0. Executive overview ================= */
export function OverviewPage({ scan, onUpload }) {
  const [sel, setSel] = useState(null);
  if (!scan) return (
    <>
      <p className="kicker">CRYPTORA // EXECUTIVE OVERVIEW</p>
      <div className="hero">
        <h2>Cryptographic Risk &amp; Migration Intelligence</h2>
        <p>CRYPTORA discovers where cryptography exists in your code, proves each finding with evidence, prioritizes what quantum computers will break first, and simulates a safe classical/hybrid/PQC migration path — all on today's classical computers.</p>
      </div>
      <FlowStrip />
      <Empty action={<button className="btn primary" onClick={onUpload}>⇪ Upload / Analyze</button>} />
    </>
  );
  const s = scan.stats;
  const layers = scan.layers || [];
  const exp = exposureScore(scan.findings);
  const riskCurve = [...scan.findings].sort((a, b) => b.riskScore - a.riskScore);
  const fileLoad = Object.entries(scan.findings.reduce((m, f) => { m[f.file] = (m[f.file] || 0) + 1; return m; }, {})).sort((a, b) => b[1] - a[1]).slice(0, 8);
  return (
    <>
      <p className="kicker">CRYPTORA // EXECUTIVE OVERVIEW</p>
      <div className="hero">
        <h2>Cryptographic Risk &amp; Migration Intelligence</h2>
        <p>Live results from <b style={{ color: '#c9d6ea' }}>{scan.source}</b> · scanned {new Date(scan.completedAt).toLocaleString()} · {(scan.durationMs / 1000).toFixed(1)}s · {s.filesScanned} files{s.excluded ? ` (${s.excluded} excluded: lockfiles/build)` : ''}. Every number below is computed from that scan.</p>
      </div>
      <FlowStrip />
      <div className="grid g6">
        <Stat k="Findings" v={s.findings} s={`${s.filesScanned} files`} />
        <Stat k="Critical" v={s.critical} color={s.critical ? '#ff7aa2' : undefined} />
        <Stat k="High" v={s.high} color={s.high ? '#ff9a9a' : undefined} />
        <Stat k="Quantum-vuln" v={s.quantum} s="Shor-breakable" color={s.quantum ? '#d8b4fe' : undefined} />
        <Stat k="Exposure" v={`${exp.score}/100`} s={exp.band} color={exp.score >= 70 ? '#ff7aa2' : exp.score >= 40 ? '#f59e0b' : '#86efac'} />
        <Stat k="PQC refs" v={s.pqc || 0} s="already quantum-safe" color={s.pqc ? '#86efac' : undefined} />
      </div>
      <div className="grid g2 mt">
        <div className="card">
          <div className="sec-title" style={{ marginTop: 0 }}>Risk curve <span className="n">every finding, ranked by risk score</span></div>
          <AreaChart series={[{ name: 'Risk score', color: '#8b5cf6', values: riskCurve.map(f => f.riskScore) }]} xLabels={riskCurve.map((f, i) => `#${i + 1}`)} yLabel="risk" />
          <p className="mono dim" style={{ fontSize: 11 }}>The head of this curve is your fix order — see Step 7.</p>
        </div>
        <div className="card">
          <div className="sec-title" style={{ marginTop: 0 }}>Findings by file <span className="n">top 8 — refactor hotspots</span></div>
          <FactorBars items={fileLoad.map(([f, c], i) => ({ label: f.length > 34 ? '…' + f.slice(-33) : f, value: c, color: i === 0 ? '#ff2d5e' : '#7c3aed' }))} />
        </div>
      </div>
      <div className="grid g2 mt">
        <div className="card">
          <div className="sec-title" style={{ marginTop: 0 }}>Severity distribution <span className="n">deterministic, from scan</span></div>
          <Donut parts={[
            { value: s.critical, color: '#ff2d5e', label: 'Critical' },
            { value: s.high, color: '#ef4444', label: 'High' },
            { value: s.medium, color: '#f59e0b', label: 'Medium' },
            { value: s.low, color: '#22d3ee', label: 'Low' },
            { value: s.info, color: '#64748f', label: 'Info' },
          ]} />
        </div>
        <div className="card">
          <div className="sec-title" style={{ marginTop: 0 }}>Multi-layer engine <span className="n">findings per layer — all 8 ran</span></div>
          {layers.length === 0 ? <div className="mono muted" style={{ fontSize: 12 }}>Layer data unavailable for this scan (restored archive).</div> :
            layers.map(l => (
              <div key={l.layer} className="mono" style={{ fontSize: 11, margin: '7px 0' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}><span>{l.layer}</span><b>{l.count}</b></div>
                <HBar value={l.count} max={Math.max(1, ...layers.map(x => x.count))} color={l.count ? '#7c3aed' : '#1a2334'} />
              </div>
            ))}
          <p className="mono dim" style={{ fontSize: 11, lineHeight: 1.7 }}>Top quantum drivers: {(topAlgos(scan, true).join(', ') || '—')}</p>
        </div>
      </div>
      <div className="sec-title">Highest-risk findings <span className="n">top 10 by risk score — click an ID for evidence</span></div>
      <FindingTable rows={scan.findings.slice(0, 10)} onOpen={setSel} />
      <FindingModal f={sel} onClose={() => setSel(null)} />
    </>
  );
}

/* ================= 1. Discovery ================= */
export function DiscoveryPage({ scan, scanLog = [], scanning, onUpload }) {
  const [sel, setSel] = useState(null);
  const [q, setQ] = useState('');
  const [sev, setSev] = useState('all');
  const [cat, setCat] = useState('all');
  if (!scan) return (
    <>
      <p className="kicker">STEP 1 // DISCOVERY</p>
      <h2 style={{ margin: '0 0 6px' }}>Crypto Discovery Engine</h2>
      <p className="mono muted" style={{ fontSize: 12 }}>Scans whatever you point it at — uploaded files/ZIP, a public GitHub repository, or a pasted snippet — for ~35 cryptographic algorithms, protocols, and hardcoded-secret patterns, entirely in your browser.</p>
      <div className="grid g2 mt">
        <div className="card">
          <div className="sec-title" style={{ marginTop: 0 }}>Live Scan <span className="n">{scanning ? 'running…' : 'idle'}</span></div>
          <LogTerminal lines={scanLog} height={240} />
          <div className="mt"><button className="btn primary sm" onClick={onUpload}>▶ Upload / Analyze</button> <span className="mono dim" style={{ fontSize: 11 }}>{scanning ? 'Scanning…' : ''}</span></div>
        </div>
        <div className="card"><DetectionMethods /></div>
      </div>
    </>
  );
  const rows = scan.findings.filter(f => {
    if (sev !== 'all' && f.severity !== sev) return false;
    if (cat === 'quantum' && !f.quantum) return false;
    else if (cat !== 'all' && cat !== 'quantum' && f.category !== cat) return false;
    if (q && !(f.algoLabel + f.file + f.evidence + f.symbol + f.id).toLowerCase().includes(q.toLowerCase())) return false;
    return true;
  });
  const cats = ['all', 'quantum', ...new Set(scan.findings.map(f => f.category))];
  const layers = scan.layers || [];
  return (
    <>
      <p className="kicker">STEP 1 // DISCOVERY</p>
      <h2 style={{ margin: '0 0 6px' }}>Crypto Discovery Engine</h2>
      <p className="mono muted" style={{ fontSize: 12 }}>Scans whatever you point it at — for ~35 cryptographic algorithms, protocols, and hardcoded-secret patterns, entirely in your browser.</p>
      <div className="grid g2 mt">
        <div className="card">
          <div className="sec-title" style={{ marginTop: 0 }}>Live Scan <span className="n">{scanning ? 'running…' : 'last run'}</span></div>
          <div className="mono dim" style={{ fontSize: 11, marginBottom: 8 }}>Source: {scan.source}</div>
          <LogTerminal lines={scanLog.length ? scanLog : [`✓ ${scan.stats.findings} findings in ${scan.stats.filesScanned} files`, '✓ Layers: ' + layers.map(l => `${l.layer.split(' ')[0]}=${l.count}`).join(' ')]} height={200} />
          <div className="mono" style={{ fontSize: 11, marginTop: 8, display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {layers.map(l => <span key={l.layer} className="tag">{l.layer.split(' ')[0]}: <b>{l.count}</b></span>)}
          </div>
        </div>
        <div className="card"><DetectionMethods excluded={scan.stats.excluded} /></div>
      </div>
      <div className="sec-title">Findings <span className="n">({rows.length}/{scan.findings.length}) — click an ID for evidence</span></div>
      <div className="toolbar">
        <input type="text" placeholder="Search algorithm, file, symbol, ID…" value={q} onChange={e => setQ(e.target.value)} />
        <select value={sev} onChange={e => setSev(e.target.value)}>
          <option value="all">All severities</option>
          <option value="critical">Critical</option><option value="high">High</option>
          <option value="medium">Medium</option><option value="low">Low</option><option value="info">Info</option>
        </select>
        <select value={cat} onChange={e => setCat(e.target.value)}>
          {cats.map(c => <option key={c} value={c}>{c === 'all' ? 'All categories' : c}</option>)}
        </select>
        <button className="btn sm" onClick={() => download(`cryptora-findings-${scan.id}.json`, JSON.stringify(scan.findings, null, 2))}>⬇ Findings JSON</button>
      </div>
      <FindingTable rows={rows} onOpen={setSel} />
      <FindingModal f={sel} onClose={() => setSel(null)} />
    </>
  );
}
function DetectionMethods({ excluded }) {
  const rows = [
    ['REGEX PATTERNS', '~35 rules covering RSA, ECC/ECDSA/ECDH, DH, DSA, Ed25519, AES, DES/3DES, RC4, MD5, SHA-1/2/3, BLAKE2, HMAC, KDFs, TLS/SSL versions, JWT, and NIST PQC (ML-KEM/ML-DSA/SLH-DSA).'],
    ['AST-LITE PARSING', 'Structured call + import analysis for JavaScript/TypeScript and Python — boosts confidence and symbols beyond regex.'],
    ['SECRET DETECTION', 'Flags embedded PEM private-key blocks and hardcoded API-key/secret assignments (values redacted).'],
    ['ENTROPY ANALYSIS', 'Shannon entropy per token (H ≥ 4.6) plus whole-file byte entropy — see the Hidden Encryption tab.'],
    ['MANIFESTS + CONTAINERS + CERTS + BINARIES', 'npm/PyPI/Go/Cargo/Maven/Gem/Composer parsing, Dockerfile static analysis, real ASN.1 certificate parsing, binary format/hash/string-signature inspection — never executes anything.'],
  ];
  return (
    <>
      <div className="sec-title" style={{ marginTop: 0 }}>Detection Methods <span className="n">real, running in your browser — not simulated</span></div>
      {rows.map(([k, v]) => (
        <div key={k} style={{ marginBottom: 12 }}>
          <div className="mono dim" style={{ fontSize: 10, letterSpacing: 1.5 }}>{k}</div>
          <div className="mono" style={{ fontSize: 11.5, color: '#c9d6ea', lineHeight: 1.7, marginTop: 3 }}>{v}</div>
        </div>
      ))}
      {excluded ? <div className="mono dim" style={{ fontSize: 11 }}>ⓘ {excluded} file(s) excluded by scan options (lockfiles / minified) — re-run with options off to include them.</div> : null}
    </>
  );
}

/* ================= 2. CBOM ================= */
export function CbomPage({ scan }) {
  const [q, setQ] = useState('');
  const [sev, setSev] = useState('all');
  const [cat, setCat] = useState('all');
  const [selId, setSelId] = useState(null);
  const [sens, setSens] = useState('Internal');
  const [crit, setCrit] = useState('Medium');
  if (!scan) return <Empty />;
  const rows = scan.findings.filter(f => {
    if (sev !== 'all' && f.severity !== sev) return false;
    if (cat !== 'all' && f.category !== cat) return false;
    if (q && !(f.algoLabel + f.file + f.evidence).toLowerCase().includes(q.toLowerCase())) return false;
    return true;
  });
  const sel = rows.find(f => f.id === selId) || rows[0];
  const cats = ['all', ...new Set(scan.findings.map(f => f.category))];
  const sbom = useMemo(() => buildSbom(scan), [scan]);
  return (
    <>
      <p className="kicker">STEP 2 // CBOM &amp; EVIDENCE</p>
      <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
        <h2 style={{ margin: '0 6px 6px 0', flex: 1 }}>Cryptographic Bill of Materials</h2>
        <button className="btn sm primary" onClick={() => download(`cryptora-raw-${scan.id}.json`, JSON.stringify(scan.findings, null, 2))}>⬇ Raw JSON</button>
        <button className="btn sm" onClick={() => download(`cryptora-cbom-${scan.id}.json`, JSON.stringify(scan.cbom, null, 2))}>⬇ CBOM (CycloneDX)</button>
        <button className="btn sm" onClick={() => download(`cryptora-sbom-${scan.id}.json`, JSON.stringify(sbom, null, 2))}>⬇ SBOM (CycloneDX)</button>
      </div>
      <p className="mono muted" style={{ fontSize: 12 }}>Every real match from your scan, with exact file, line, and matched text. No black box.</p>
      <div className="toolbar">
        <input type="text" placeholder="Search findings…" value={q} onChange={e => setQ(e.target.value)} style={{ flex: 1 }} />
        <select value={sev} onChange={e => setSev(e.target.value)}>
          <option value="all">All Severity</option>
          <option value="critical">Critical</option><option value="high">High</option>
          <option value="medium">Medium</option><option value="low">Low</option><option value="info">Info</option>
        </select>
        <select value={cat} onChange={e => setCat(e.target.value)}>
          {cats.map(c => <option key={c} value={c}>{c === 'all' ? 'All Categories' : c}</option>)}
        </select>
      </div>
      {rows.length === 0 ? <div className="card muted mono" style={{ fontSize: 12 }}>No findings match.</div> : (
        <div className="cbom-split">
          <div className="cbom-list">
            {rows.slice(0, 400).map(f => (
              <button key={f.id} className={`cbom-item ${sel && sel.id === f.id ? 'on' : ''}`} onClick={() => setSelId(f.id)}>
                <div style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                  <span className="mono dim" style={{ fontSize: 10.5 }}>{f.file}:{f.line}</span>
                  {f.category === 'pqc' ? <span className="tag ok">SAFE</span> : <Sev level={f.severity} />}
                </div>
                <div style={{ fontWeight: 700, fontSize: 13, margin: '4px 0' }}>{f.algoLabel}</div>
                <div className="mono dim" style={{ fontSize: 10.5 }}>{f.category} · Quantum: {f.quantum ? <b style={{ color: '#f97316' }}>HIGH</b> : f.category === 'pqc' ? <b style={{ color: '#d8b4fe' }}>SAFE</b> : <b style={{ color: '#22c55e' }}>NONE</b>}</div>
              </button>
            ))}
          </div>
          <div className="card cbom-detail">
            {sel ? <CbomDetail f={sel} sens={sens} setSens={setSens} crit={crit} setCrit={setCrit} /> : <div className="mono muted">Select a finding.</div>}
          </div>
        </div>
      )}
    </>
  );
}
function CbomDetail({ f, sens, setSens, crit, setCrit }) {
  const ex = explainScore(f, sens, crit);
  return (
    <>
      <div className="mono dim" style={{ fontSize: 11 }}>{f.file}</div>
      <h3 style={{ margin: '4px 0 10px' }}>{f.algoLabel}</h3>
      <div className="kv2">
        <div><span>Category</span><b>{f.category}</b></div>
        <div><span>Line</span><b>{f.line}</b></div>
        <div><span>Quantum risk</span><b style={{ color: f.quantum ? '#f97316' : f.category === 'pqc' ? '#d8b4fe' : '#22c55e' }}>{f.quantum ? 'HIGH' : f.category === 'pqc' ? 'SAFE' : 'NONE'}</b></div>
        <div><span>Severity</span><span><Sev level={f.severity} /></span></div>
        <div><span>Detector / Layer</span><b className="mono" style={{ fontSize: 11 }}>{f.detector}{f.layer ? ` · ${f.layer}` : ''}</b></div>
        <div><span>Confidence</span><b>{(f.confidence * 100).toFixed(0)}%</b></div>
      </div>
      <div className="mono dim" style={{ fontSize: 10.5, letterSpacing: 1, margin: '12px 0 6px' }}>MATCHED TEXT</div>
      <div className="codebox" style={{ color: '#86efac' }}>{f.evidence}</div>
      <div className="mono dim" style={{ fontSize: 10.5, letterSpacing: 1, margin: '12px 0 6px' }}>LINE {f.line} IN CONTEXT</div>
      <div className="codebox">{(f.context || []).map(c => `${c.hit ? '›' : ' '} ${c.n}: ${c.t}`).join('\n') || f.evidence}</div>
      <div className="sec-title" style={{ marginBottom: 4 }}>Explainable Risk Score <span className="n">recomputed live from this finding + context — not a fixed number</span></div>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 8 }}>
        <label className="mono dim" style={{ fontSize: 10 }}>DATA SENSITIVITY<br />
          <select value={sens} onChange={e => setSens(e.target.value)} className="mini-select">
            <option>Internal</option><option>Confidential</option><option>Restricted</option>
          </select></label>
        <label className="mono dim" style={{ fontSize: 10 }}>BUSINESS CRITICALITY<br />
          <select value={crit} onChange={e => setCrit(e.target.value)} className="mini-select">
            <option>Low</option><option>Medium</option><option>High</option><option>Critical</option>
          </select></label>
      </div>
      <div className="mono" style={{ fontSize: 26, fontWeight: 800, color: ex.score >= 7 ? '#ff7aa2' : ex.score >= 4.5 ? '#f59e0b' : '#86efac' }}>
        {ex.score.toFixed(1)}<span className="dim" style={{ fontSize: 13 }}>/10</span> <span className="tag">{ex.band}</span>
      </div>
      <div className="mono dim" style={{ fontSize: 10, letterSpacing: 1, margin: '8px 0 4px' }}>FACTOR BREAKDOWN</div>
      {ex.factors.map((x, i) => <DivBar key={i} label={x.label} delta={x.delta} maxAbs={Math.max(1, ...ex.factors.map(y => Math.abs(y.delta)))} />)}
    </>
  );
}

/* ================= 3. Dependency graph (radial) ================= */
export function DepGraphPage({ scan, onGo }) {
  const [sel, setSel] = useState(null);
  if (!scan) return <Empty />;
  const groups = {};
  scan.findings.forEach(f => {
    const g = groups[f.algorithm] || (groups[f.algorithm] = { algo: f.algorithm, label: f.algoLabel, cat: f.category, list: [] });
    g.list.push(f);
  });
  const nodes = Object.values(groups).sort((a, b) => b.list.length - a.list.length).slice(0, 14);
  const cur = nodes.find(n => n.algo === sel) || nodes[0];
  const CX = 280, CY = 200, R = 148;
  const pos = (i, n) => {
    if (n === 1) return [CX, CY - R];
    const a = -Math.PI / 2 + (i * 2 * Math.PI) / n;
    return [CX + R * Math.cos(a), CY + R * Math.sin(a)];
  };
  const filesOf = (n) => [...new Set(n.list.map(f => f.file))];
  const worstOf = (n) => {
    const ord = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    return n.list.slice().sort((a, b) => ord[b.severity] - ord[a.severity])[0].severity;
  };
  return (
    <>
      <p className="kicker">STEP 3 // DEPENDENCY GRAPH</p>
      <h2 style={{ margin: '0 0 6px' }}>Crypto Dependency Graph</h2>
      <p className="mono muted" style={{ fontSize: 12 }}>Each node is an algorithm found in your scan; click one to see exactly which files use it. Also parsed: {scan.stats.deps} manifest dependencies across {new Set(scan.deps.map(d => d.ecosystem)).size} ecosystem(s).</p>
      <div className="grid g2">
        <div className="graph-box">
          <svg viewBox="0 0 560 400" style={{ width: '100%', height: 'auto', minWidth: 420 }}>
            <defs>
              <pattern id="depgrid" width="42" height="42" patternUnits="userSpaceOnUse">
                <path d="M 42 0 L 0 0 0 42" fill="none" stroke="rgba(124,58,237,.13)" strokeWidth="1" />
              </pattern>
            </defs>
            <rect x="0" y="0" width="560" height="400" fill="url(#depgrid)" rx="8" />
            {nodes.map((n, i) => {
              const [x, y] = pos(i, nodes.length);
              return <line key={'e' + n.algo} x1={CX} y1={CY} x2={x} y2={y} stroke="#2a3550" strokeWidth="1.2" />;
            })}
            <g className="gnode"><circle cx={CX} cy={CY} r="34" fill="rgba(124,58,237,.25)" stroke="#7c3aed" strokeWidth="2" /></g>
            <text x={CX} y={CY - 2} textAnchor="middle" fill="#fff" fontSize="10" fontWeight="700" fontFamily="monospace">YOUR SCAN</text>
            <text x={CX} y={CY + 12} textAnchor="middle" fill="#9aa6bd" fontSize="9" fontFamily="monospace">{scan.stats.findings} hits</text>
            {nodes.map((n, i) => {
              const [x, y] = pos(i, nodes.length);
              const c = algoColor(n.algo);
              const on = cur && cur.algo === n.algo;
              return (
                <g key={n.algo} onClick={() => setSel(n.algo)} style={{ cursor: 'pointer' }}>
                  <circle className="gnode" cx={x} cy={y} r={on ? 37 : 33} fill="#0d1320" stroke={c} strokeWidth={on ? 3 : 2} />
                  <text x={x} y={y - 1} textAnchor="middle" fill="#f2f5fa" fontSize="9.5" fontWeight="700" fontFamily="monospace">{shortAlgo(n.algo, n.label).slice(0, 12)}</text>
                  <text x={x} y={y + 12} textAnchor="middle" fill={c} fontSize="9" fontFamily="monospace">×{n.list.length}</text>
                </g>
              );
            })}
          </svg>
        </div>
        <div className="card">
          {cur ? (
            <>
              <h3 style={{ margin: '0 0 4px' }}>Selected: {cur.label}</h3>
              <div className="mono dim" style={{ fontSize: 11 }}>{cur.list.length} occurrence(s) across {filesOf(cur).length} file(s)</div>
              <div className="kv2 mt">
                <div><span>Category</span><b>{cur.cat}</b></div>
                <div><span>Quantum risk</span><b style={{ color: cur.list.some(f => f.quantum) ? '#f97316' : '#22c55e' }}>{cur.list.some(f => f.quantum) ? 'HIGH' : 'NONE'}</b></div>
                <div><span>Worst severity found</span><span><Sev level={worstOf(cur)} /></span></div>
              </div>
              <div className="mono dim" style={{ fontSize: 10.5, letterSpacing: 1, margin: '12px 0 6px' }}>FILES</div>
              <div className="mono" style={{ fontSize: 11, lineHeight: 2, maxHeight: 220, overflowY: 'auto' }}>
                {filesOf(cur).slice(0, 40).map(f => <div key={f} style={{ borderLeft: '2px solid #2a3550', paddingLeft: 10 }}>{f}</div>)}
              </div>
              <button className="btn primary sm mt" style={{ width: '100%', justifyContent: 'center' }} onClick={() => onGo && onGo('break')}>What Will Break? →</button>
            </>
          ) : <div className="mono muted">No algorithms found.</div>}
        </div>
      </div>
    </>
  );
}

/* ================= 4. Certs & containers ================= */
export function CertsPage({ scan }) {
  if (!scan) return <Empty />;
  return (
    <>
      <p className="kicker">STEP 4 // CERTS, CONTAINERS, BINARIES</p>
      <h2 style={{ margin: '0 0 6px' }}>Certs, Containers, Bin.</h2>
      <p className="mono muted" style={{ fontSize: 12 }}>Real ASN.1 parsing (signature OID, validity, key-size heuristic) + Dockerfile static analysis. Private key bytes are never displayed.</p>
      <div className="grid g4 mt">
        <Stat k="Certificates" v={scan.certs.length} />
        <Stat k="Expired / weak" v={scan.certs.filter(c => c.expired || c.weak).length} color={scan.certs.some(c => c.expired || c.weak) ? '#ff7aa2' : undefined} />
        <Stat k="Container signals" v={scan.docker.length} />
        <Stat k="Binaries inspected" v={scan.binaries.length} />
      </div>
      <div className="sec-title">Certificates <span className="n">{scan.certs.length} parsed</span></div>
      {scan.certs.length === 0 ? <div className="card muted mono" style={{ fontSize: 12 }}>No certificate blocks found in this scan.</div> : (
        <div className="tbl-wrap"><table className="tbl">
          <thead><tr><th>File</th><th>Signature alg</th><th>Key ≈bits</th><th>Validity</th><th>Status</th></tr></thead>
          <tbody>{scan.certs.map((c, i) => (
            <tr key={i}>
              <td className="mono" style={{ fontSize: 11 }}>{c.file}</td>
              <td className="mono" style={{ fontSize: 11 }}>{c.sigAlg}{c.sigOid ? <div className="dim">{c.sigOid}</div> : null}</td>
              <td className="mono">{c.keyBits || '?'}</td>
              <td className="mono" style={{ fontSize: 11 }}>{c.notBefore || '?'} → {c.notAfter || '?'}</td>
              <td>{c.error ? <Sev level="info" /> : c.expired ? <Sev level="critical" /> : c.weak ? <Sev level="high" /> : c.expiringSoon ? <Sev level="medium" /> : <span className="tag ok">ok</span>}
                <div className="dim mono" style={{ fontSize: 10 }}>{c.expired ? 'expired' : c.weak ? 'weak sig' : c.expiringSoon ? 'expires <90d' : c.error ? c.error : ''}</div></td>
            </tr>
          ))}</tbody>
        </table></div>
      )}
      <div className="sec-title">Container signals <span className="n">{scan.docker.length} notes</span></div>
      {scan.docker.length === 0 ? <div className="card muted mono" style={{ fontSize: 12 }}>No Dockerfile/compose signals in this scan.</div> : (
        <div className="tbl-wrap"><table className="tbl">
          <thead><tr><th>File</th><th>Line</th><th>Signal</th><th>Detail</th></tr></thead>
          <tbody>{scan.docker.map((d, i) => (
            <tr key={i}><td className="mono" style={{ fontSize: 11 }}>{d.file}</td><td className="mono">{d.line}</td>
              <td><span className="tag">{d.kind}</span></td><td className="mono" style={{ fontSize: 11 }}>{d.text}</td></tr>
          ))}</tbody>
        </table></div>
      )}
      <div className="sec-title">Binaries / documents <span className="n">{scan.binaries.length} statically inspected</span></div>
      {scan.binaries.length === 0 ? <div className="card muted mono" style={{ fontSize: 12 }}>No binaries/documents in this scan.</div> : (
        <div className="tbl-wrap"><table className="tbl">
          <thead><tr><th>Path</th><th>Format</th><th>Size</th><th>SHA-256</th><th>Strings</th><th>Crypto sigs</th></tr></thead>
          <tbody>{scan.binaries.map((b, i) => (
            <tr key={i}><td className="mono" style={{ fontSize: 11 }}>{b.path}</td><td><span className="tag">{b.format}</span></td>
              <td className="mono">{(b.size / 1024).toFixed(1)} KB</td><td className="mono" style={{ fontSize: 10 }}>{b.sha256.slice(0, 32)}…</td>
              <td className="mono">{b.stringsExamined}</td><td className="mono" style={{ fontSize: 11 }}>{b.sigHits.join(', ') || '—'}</td></tr>
          ))}</tbody>
        </table></div>
      )}
    </>
  );
}

/* ================= 5. Quantum & business risk ================= */
const PRESETS = {
  Conservative: { x: 15, y: 5, z: 10 },
  Moderate: { x: 7, y: 3, z: 12 },
  Aggressive: { x: 5, y: 2, z: 15 },
};
export function RiskPage({ scan, ctx, setCtx, onGo }) {
  const [sel, setSel] = useState(null);
  const [mx, setMx] = useState(5);
  const [my, setMy] = useState(2);
  const [mz, setMz] = useState(10);
  const [zipBusy, setZipBusy] = useState(false);
  if (!scan) return <Empty />;
  const m = mosca(mx, my, mz);
  const exp = exposureScore(scan.findings);
  const qAlgos = [...new Set(scan.findings.filter(f => f.quantum).map(f => f.algorithm))];
  const qShare = scan.stats.findings ? Math.round((scan.stats.quantum / scan.stats.findings) * 100) : 0;
  const pqcShare = scan.stats.findings ? Math.round(((scan.stats.pqc || 0) / scan.stats.findings) * 100) : 0;
  const cumRisk = (() => { const tot = scan.findings.reduce((a, f) => a + f.riskScore, 0) || 1; let acc = 0; return [...scan.findings].sort((a, b) => b.riskScore - a.riskScore).map(f => { acc += f.riskScore; return Math.round((acc / tot) * 100); }); })();
  async function zipBundle() {
    setZipBusy(true);
    try {
      const zip = new JSZip();
      const s = scan.stats;
      zip.file('summary.txt', `CRYPTORA report — ${scan.id}\nSource: ${scan.source}\nScanned: ${scan.completedAt}\nFiles: ${s.filesScanned} · Findings: ${s.findings} (C:${s.critical} H:${s.high} M:${s.medium} L:${s.low})\nQuantum-vulnerable: ${s.quantum} · Secrets: ${s.secrets} · Exposure: ${exp.score}/100 (${exp.band})\nMosca: X=${mx} Y=${my} Z=${mz} → ${m.verdict}\n\nMethod: heuristic static analysis in-browser. Secrets redacted. No 100% claims.\n`);
      zip.file('findings.json', JSON.stringify(scan.findings, null, 2));
      zip.file('cbom.json', JSON.stringify(scan.cbom, null, 2));
      const blob = await zip.generateAsync({ type: 'blob' });
      downloadBlob(`cryptora-bundle-${scan.id}.zip`, blob);
    } finally { setZipBusy(false); }
  }
  return (
    <>
      <p className="kicker">STEP 5 // QUANTUM &amp; BUSINESS RISK</p>
      <h2 style={{ margin: '0 0 6px' }}>Quantum + Business Risk Scoring</h2>
      <p className="mono muted" style={{ fontSize: 12 }}>A weighted score across every real finding — not "RSA is bad", a computed aggregate of what your scan actually found.</p>
      <div className="gauge-row">
        <MiniGauge value={exp.score} label="Aggregate exposure" sub={exp.band} color={exp.score >= 70 ? '#ff2d5e' : exp.score >= 40 ? '#f97316' : '#22c55e'} />
        <MiniGauge value={qShare} label="Quantum share" sub={`${scan.stats.quantum} of ${scan.stats.findings} findings`} color="#a78bfa" />
        <MiniGauge value={scan.stats.secrets} max={Math.max(1, scan.stats.findings)} label="Secrets" sub="hardcoded + PEM blocks" color="#f59e0b" />
        <MiniGauge value={pqcShare} label="PQC-ready" sub={`${scan.stats.pqc || 0} post-quantum refs`} color="#22c55e" />
      </div>
      <div className="grid g2 mt">
        <div className="card">
          <div className="sec-title" style={{ marginTop: 0 }}>Cumulative risk <span className="n">% of total risk carried by top-N findings</span></div>
          <AreaChart series={[{ name: 'Cumulative share', color: '#22d3ee', values: cumRisk }]} xLabels={cumRisk.map((_, i) => `top ${i + 1}`)} yLabel="%" />
          <p className="mono dim" style={{ fontSize: 11 }}>Steep start = a few findings dominate — fix the head of Step 7 first.</p>
        </div>
        <div className="card">
          <div className="sec-title" style={{ marginTop: 0 }}>Real Aggregate Factors <span className="n">counted directly from this scan</span></div>
          <FactorBars items={[
            { label: 'Critical findings', value: scan.stats.critical, color: '#ff2d5e' },
            { label: 'High findings', value: scan.stats.high, color: '#ef4444' },
            { label: 'Quantum-vulnerable', value: scan.stats.quantum, color: '#a78bfa' },
            { label: 'Hardcoded secrets', value: scan.stats.secrets, color: '#f59e0b' },
            { label: 'Distinct algorithms', value: scan.stats.distinctAlgos, color: '#22d3ee' },
            { label: 'Files scanned', value: scan.stats.filesScanned, color: '#38bdf8' },
          ]} />
          <div className="mono dim" style={{ fontSize: 11, marginTop: 8 }}>Quantum algorithms: {qAlgos.join(', ') || '—'}</div>
          <div className="sec-title">Download Report</div>
          <p className="mono dim" style={{ fontSize: 11 }}>Every finding, score, and chart value above — exported for sharing.</p>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <button className="btn sm primary" onClick={() => onGo && onGo('report')}>⬇ PDF Report</button>
            <button className="btn sm" disabled={zipBusy} onClick={zipBundle}>{zipBusy ? '…' : '⬇ ZIP (summary + JSON + CBOM)'}</button>
          </div>
        </div>
      </div>
      <div className="card mt">
        <div className="sec-title" style={{ marginTop: 0 }}>Mosca's Inequality — Interactive <span className="n">adjust the assumptions for your context. If (Data Lifetime + Migration Time) &gt; Threat Horizon, migration is urgent.</span></div>
        <div className="codebox" style={{ textAlign: 'center', fontSize: 13 }}>If (Data Lifetime + Migration Time) &gt; Threat Horizon → Migration is URGENT</div>
        <div style={{ display: 'flex', gap: 8, margin: '12px 0', flexWrap: 'wrap' }}>
          {Object.entries(PRESETS).map(([k, v]) => (
            <button key={k} className="btn sm" onClick={() => { setMx(v.x); setMy(v.y); setMz(v.z); }}>{k} preset</button>
          ))}
        </div>
        <div className="grid g3">
          <div className="mosca-ctl"><label className="mono dim" style={{ fontSize: 10 }}>DATA LIFETIME (YRS)</label><input type="number" min="1" max="50" value={mx} onChange={e => setMx(+e.target.value || 0)} className="mosca-input" /><input type="range" min="1" max="50" value={mx} onChange={e => setMx(+e.target.value)} /><div className="mosca-scale"><span>1</span><span>25</span><span>50</span></div></div>
          <div className="mosca-ctl"><label className="mono dim" style={{ fontSize: 10 }}>MIGRATION TIME (YRS)</label><input type="number" min="0" max="30" value={my} onChange={e => setMy(+e.target.value || 0)} className="mosca-input" /><input type="range" min="0" max="30" value={my} onChange={e => setMy(+e.target.value)} /><div className="mosca-scale"><span>0</span><span>15</span><span>30</span></div></div>
          <div className="mosca-ctl"><label className="mono dim" style={{ fontSize: 10 }}>THREAT HORIZON (YRS)</label><input type="number" min="1" max="50" value={mz} onChange={e => setMz(+e.target.value || 0)} className="mosca-input" /><input type="range" min="1" max="50" value={mz} onChange={e => setMz(+e.target.value)} /><div className="mosca-scale"><span>1</span><span>25</span><span>50</span></div></div>
        </div>
        <div className={`verdict ${m.urgent ? 'bad' : 'good'}`}>{mx} + {my} = {m.sum} {m.gap > 0 ? '>' : '≤'} {mz} → {m.urgent ? 'MIGRATION IS URGENT' : 'MIGRATION IS NOT YET URGENT'}</div>
        <p className="mono dim" style={{ fontSize: 11, textAlign: 'center' }}>These are planning assumptions you set — not a prediction of exactly when quantum computers arrive.</p>
      </div>
      <div className="sec-title">Business context <span className="n">tunes the risk ranking below</span></div>
      <div className="grid g3">
        {[['sensitivity', 'Data sensitivity'], ['criticality', 'Business criticality'], ['exposure', 'Exposure']].map(([k, label]) => (
          <div className="card" key={k}>
            <div className="mono dim" style={{ fontSize: 10.5, letterSpacing: 1 }}>{label.toUpperCase()}: <b style={{ color: '#fff' }}>{ctx[k]}/5</b></div>
            <input type="range" min="1" max="5" value={ctx[k]} onChange={e => setCtx({ ...ctx, [k]: +e.target.value })} style={{ width: '100%' }} />
          </div>
        ))}
      </div>
      <div className="sec-title">Risk-ranked findings <span className="n">{scan.findings.length}</span></div>
      <FindingTable rows={scan.findings} onOpen={setSel} />
      <FindingModal f={sel} onClose={() => setSel(null)} />
    </>
  );
}

/* ================= 6. Agility ================= */
export function AgilityPage({ scan }) {
  if (!scan) return <Empty />;
  const ag = agilityScore(scan);
  const byFile = {};
  scan.findings.forEach(f => { byFile[f.file] = byFile[f.file] || { n: 0, q: 0, crit: 0 }; byFile[f.file].n++; if (f.quantum) byFile[f.file].q++; if (f.severity === 'critical') byFile[f.file].crit++; });
  const rows = Object.entries(byFile).sort((a, b) => b[1].n - a[1].n).slice(0, 60);
  return (
    <>
      <p className="kicker">STEP 6 // CRYPTO AGILITY</p>
      <h2 style={{ margin: '0 0 6px' }}>Crypto Agility Score</h2>
      <p className="mono muted" style={{ fontSize: 12 }}>A 0–100 measure of how easily this codebase could replace or upgrade its cryptography — based on how scattered/hardcoded the usage is, whether deprecated algorithms are present, and whether any post-quantum readiness already exists.</p>
      <div className="grid g2 mt">
        <div className="card">
          <div className="sec-title" style={{ marginTop: 0 }}>Agility Score</div>
          <Gauge value={ag.score} band={ag.band} color={ag.score >= 70 ? '#22c55e' : ag.score >= 40 ? '#f97316' : '#ff2d5e'} />
        </div>
        <div className="card">
          <div className="sec-title" style={{ marginTop: 0 }}>Contributing Factors <span className="n">each factor is a real signal from this scan, not a guess</span></div>
          {ag.factors.length === 0 ? <div className="mono muted" style={{ fontSize: 12 }}>Neutral — no strong signals either way.</div> :
            ag.factors.map((x, i) => <DivBar key={i} label={x.label} delta={x.delta} maxAbs={Math.max(1, ...ag.factors.map(y => Math.abs(y.delta)))} posGood />)}
        </div>
      </div>
      <p className="mono dim mt" style={{ fontSize: 11, lineHeight: 1.8 }}>Baseline starts at 60 (neutral); factors above adjust it up or down. This is a heuristic scoring model — treat the direction and contributing factors as more meaningful than the exact number.</p>
      <div className="sec-title">Crypto concentration by file <span className="n">refactor hotspots first</span></div>
      <div className="tbl-wrap"><table className="tbl">
        <thead><tr><th>File</th><th>Findings</th><th>Quantum</th><th>Critical</th><th>Load</th></tr></thead>
        <tbody>{rows.map(([f, v]) => (
          <tr key={f}><td className="mono" style={{ fontSize: 11 }}>{f}</td><td className="mono">{v.n}</td><td className="mono">{v.q}</td><td className="mono">{v.crit}</td>
            <td style={{ minWidth: 160 }}><HBar value={(v.n / (rows[0]?.[1].n || 1)) * 100} color={v.crit ? '#ff2d5e' : v.q ? '#7c3aed' : '#22d3ee'} /></td></tr>
        ))}</tbody>
      </table></div>
    </>
  );
}

/* ================= 7. What will break ================= */
export function BreakPage({ scan }) {
  const [z, setZ] = useState(12);
  const [sel, setSel] = useState(null);
  const [focus, setFocus] = useState(null);
  if (!scan) return <Empty />;
  const m = mosca(10, 3, z);
  const ranked = scan.findings.map(f => {
    let urgency = f.riskScore;
    if (f.quantum) urgency += Math.max(0, m.gap) * 4;
    if (f.severity === 'critical') urgency += 8;
    return { ...f, urgency: Math.round(urgency) };
  }).sort((a, b) => b.urgency - a.urgency);
  const whyOf = (f) => [f.quantum && m.urgent ? 'quantum + Mosca-urgent' : f.quantum ? 'quantum-vulnerable' : null, f.category === 'secret' ? 'exposed secret' : null, f.severity === 'critical' ? 'critical severity' : null, `risk score ${f.riskScore}`].filter(Boolean);
  return (
    <>
      <p className="kicker">STEP 7 // WHAT WILL BREAK?</p>
      <h2 style={{ margin: '0 0 6px' }}>What Will Break?</h2>
      <p className="mono muted" style={{ fontSize: 12 }}>Break-first order = risk score + Mosca gap pressure (Z={z}y, gap {m.gap > 0 ? '+' : ''}{m.gap}y) on quantum-vulnerable items. <input type="range" min="5" max="30" value={z} onChange={e => setZ(+e.target.value)} style={{ width: 160, verticalAlign: 'middle' }} /></p>
      <div className="rank-wrap mt">
        <div className="rank-list">
          {ranked.slice(0, 120).map((f, i) => {
            const on = (focus ? focus.id : (ranked[0] && ranked[0].id)) === f.id;
            return (
              <button key={f.id} className={`rank-row ${on ? 'on' : ''}`} onClick={() => setFocus(f)}>
                <span className="medal">{i + 1}</span>
                <span className="rank-main">
                  <span className="rank-name">{f.algoLabel}</span>
                  <span className="rank-sub" style={{ display: 'block' }}>{f.id} · {f.file}:{f.line}</span>
                  <span className="rank-chips"><Sev level={f.severity} />{f.quantum ? <span className="tag q">⚛ quantum</span> : null}{whyOf(f).slice(0, 2).map(w => <span key={w} className="tag">{w}</span>)}</span>
                </span>
                <span className="rank-score"><b style={{ color: i < 5 ? '#ff7aa2' : '#f2f5fa' }}>{f.urgency}</b><span className="mono dim" style={{ fontSize: 10 }}>URGENCY</span></span>
              </button>
            );
          })}
        </div>
        <div className="card why-panel">
          {(() => {
            const f = focus || ranked[0];
            if (!f) return <div className="mono muted">No findings.</div>;
            const rec = recommendFor(f);
            return (<>
              <div className="sec-title" style={{ marginTop: 0 }}>Why First <span className="n">#{ranked.findIndex(x => x.id === f.id) + 1} — {f.id}</span></div>
              <h3 style={{ margin: '0 0 4px' }}>{f.algoLabel}</h3>
              <div className="mono dim" style={{ fontSize: 11 }}>{f.file}:{f.line} · risk {f.riskScore} · urgency {f.urgency}</div>
              <div style={{ margin: '8px 0', display: 'flex', gap: 6 }}><Sev level={f.severity} /> <QTag quantum={f.quantum} /></div>
              {whyOf(f).map(w => <div key={w} className="why-line">{w}</div>)}
              <div className="mono dim" style={{ fontSize: 10.5, letterSpacing: 1, margin: '12px 0 6px' }}>EVIDENCE</div>
              <div className="codebox">{f.evidence}</div>
              <div className="mono" style={{ fontSize: 11, marginTop: 10, color: '#d8b4fe' }}>{rec.current} → {rec.hybrid !== '—' ? rec.hybrid + ' → ' : ''}{rec.pqc}</div>
              <button className="btn sm primary mt" style={{ width: '100%', justifyContent: 'center' }} onClick={() => setSel(f)}>Open full evidence</button>
            </>);
          })()}
        </div>
      </div>
      <FindingModal f={sel} onClose={() => setSel(null)} />
    </>
  );
}

/* ================= 8. Attack surface (network) ================= */
const CRYPTO_DEP_RX2 = /(crypto|ssl|tls|sodium|nacl|bcrypt|argon|jwt|jose|openssl|hash|aes|rsa|ecdsa|ssh|cert|cipher|md5|sha|pgp|password|secret)/i;
export function AttackPage({ scan }) {
  const [sel, setSel] = useState(null);
  const [modal, setModal] = useState(null);
  if (!scan) return <Empty />;
  const deps = [...scan.deps].sort((a, b) => (CRYPTO_DEP_RX2.test(b.name) ? 1 : 0) - (CRYPTO_DEP_RX2.test(a.name) ? 1 : 0)).slice(0, 12);
  const byAlgo = {};
  scan.findings.forEach(f => { (byAlgo[f.algorithm] || (byAlgo[f.algorithm] = [])).push(f); });
  const algos = Object.entries(byAlgo).sort((a, b) => b[1].length - a[1].length).slice(0, 12);
  // deterministic layout
  const W = 920, APP = { x: 460, y: 430 };
  const depPos = deps.map((d, i) => ({ ...d, x: 90 + (i * (W - 180)) / Math.max(1, deps.length - 1), y: 300 + (i % 2) * 36 }));
  const algoPos = algos.map(([a, fs], i) => ({ algo: a, fs, x: 90 + (i * (W - 180)) / Math.max(1, algos.length - 1), y: 120 - (i % 2) * 26 }));
  const depAlgoLinks = [];
  depPos.forEach(d => {
    algoPos.forEach(ap => {
      const hit = ap.fs.some(f => {
        const L = (f.library || '').toLowerCase().split(':').pop();
        const N = d.name.toLowerCase();
        return L && L !== '—' && (N.includes(L) || L.includes(N.split('/').pop()));
      });
      if (hit) depAlgoLinks.push([d, ap]);
    });
  });
  const linkedAlgos = new Set(depAlgoLinks.map(([, ap]) => ap.algo));
  const ext = scan.findings.filter(f => /route|api|server|public|controller|endpoint|handler|app\.|views?|pages?/i.test(f.file));
  const sec = scan.findings.filter(f => f.category === 'secret' || f.algorithm === 'ENTROPY');
  return (
    <>
      <p className="kicker">STEP 8 // ATTACK SURFACE</p>
      <h2 style={{ margin: '0 0 6px' }}>Attack Surface Map</h2>
      <p className="mono muted" style={{ fontSize: 12 }}>App → dependency → algorithm → file, built directly from this scan's real findings and parsed manifests. Click any node.</p>
      <div className="graph-box">
        <svg width={W} height="500" viewBox={`0 0 ${W} 500`} style={{ maxWidth: 'none' }}>
          <defs>
            <pattern id="atkgrid" width="46" height="46" patternUnits="userSpaceOnUse">
              <path d="M 46 0 L 0 0 0 46" fill="none" stroke="rgba(124,58,237,.13)" strokeWidth="1" />
            </pattern>
          </defs>
          <rect x="0" y="0" width={W} height="500" fill="url(#atkgrid)" rx="8" />
          {depPos.map(d => <path key={'a' + d.name} d={`M${APP.x},${APP.y} Q${(APP.x + d.x) / 2},${(APP.y + d.y) / 2 - 52} ${d.x},${d.y}`} stroke="#2a3550" strokeWidth="1" fill="none" />)}
          {depAlgoLinks.map(([d, ap], i) => <path key={'l' + i} d={`M${d.x},${d.y} Q${(d.x + ap.x) / 2},${(d.y + ap.y) / 2 - 26} ${ap.x},${ap.y}`} stroke="rgba(124,58,237,.5)" strokeWidth="1.3" fill="none" />)}
          {algoPos.filter(ap => !linkedAlgos.has(ap.algo)).map(ap => <path key={'d' + ap.algo} d={`M${APP.x},${APP.y} Q${(APP.x + ap.x) / 2},${(APP.y + ap.y) / 2 - 70} ${ap.x},${ap.y}`} stroke="#1e2636" strokeWidth="1" strokeDasharray="4 4" fill="none" />)}
          {algoPos.map(ap => {
            const c = algoColor(ap.algo);
            const on = sel && sel.kind === 'algo' && sel.key === ap.algo;
            return (
              <g key={ap.algo} onClick={() => setSel({ kind: 'algo', key: ap.algo })} style={{ cursor: 'pointer' }}>
                <circle className="gnode" cx={ap.x} cy={ap.y} r={on ? 30 : 26} fill="#0d1320" stroke={c} strokeWidth={on ? 3 : 2.5} />
                <text x={ap.x} y={ap.y + 44} textAnchor="middle" fill="#9aa6bd" fontSize="10.5" fontFamily="monospace">{shortAlgo(ap.algo, ap.fs[0].algoLabel)}</text>
                <text x={ap.x} y={ap.y + 5} textAnchor="middle" fill={c} fontSize="11" fontWeight="700" fontFamily="monospace">×{ap.fs.length}</text>
              </g>
            );
          })}
          {depPos.map(d => {
            const hot = CRYPTO_DEP_RX2.test(d.name);
            const on = sel && sel.kind === 'dep' && sel.key === d.name;
            return (
              <g key={d.name} onClick={() => setSel({ kind: 'dep', key: d.name })} style={{ cursor: 'pointer' }}>
                <circle className="gnode" cx={d.x} cy={d.y} r={on ? 24 : 20} fill="#0d1320" stroke={hot ? '#7c3aed' : '#38bdf8'} strokeWidth={on ? 3 : 2} />
                <text x={d.x} y={d.y + 36} textAnchor="middle" fill="#9aa6bd" fontSize="10" fontFamily="monospace">{String(d.name).slice(0, 18)}</text>
              </g>
            );
          })}
          <g onClick={() => setSel({ kind: 'app' })} style={{ cursor: 'pointer' }}>
            <circle className="gnode" cx={APP.x} cy={APP.y} r="32" fill="rgba(124,58,237,.3)" stroke="#7c3aed" strokeWidth="2.5" />
            <text x={APP.x} y={APP.y + 5} textAnchor="middle" fill="#fff" fontSize="12" fontWeight="800" fontFamily="monospace">APP</text>
          </g>
        </svg>
      </div>
      <div className="mono dim" style={{ fontSize: 11, marginTop: 8 }}>● <span style={{ color: '#38bdf8' }}>dependency</span> (purple ring = crypto-relevant) · solid line = evidence link (finding's library matches package) · dashed = direct code usage · <span style={{ color: '#22c55e' }}>green</span>=safe · <span style={{ color: '#f97316' }}>orange</span>=quantum · <span style={{ color: '#ef4444' }}>red</span>=broken/deprecated</div>
      {sel ? (
        <div className="card mt">
          {sel.kind === 'app' ? <><h3 style={{ margin: '0 0 6px' }}>APP — {scan.project}</h3><div className="mono muted" style={{ fontSize: 12 }}>{deps.length} dependencies shown · {algos.length} algorithms · {scan.stats.findings} findings · {scan.stats.filesScanned} files</div></> : null}
          {sel.kind === 'dep' ? (() => {
            const d = scan.deps.find(x => x.name === sel.key) || {};
            const linked = depAlgoLinks.filter(([x]) => x.name === sel.key).map(([, ap]) => ap.algo);
            return <><h3 style={{ margin: '0 0 6px' }}>{d.name} <span className="dim mono" style={{ fontSize: 12 }}>@{d.version} · {d.ecosystem}</span></h3>
              <div className="mono muted" style={{ fontSize: 12 }}>Manifest: {d.file} · Linked algorithms: {[...new Set(linked)].join(', ') || '— (no finding library-match; may still be reached transitively)'}</div></>;
          })() : null}
          {sel.kind === 'algo' ? (() => {
            const fs = byAlgo[sel.key] || [];
            const files = [...new Set(fs.map(f => f.file))];
            return <><h3 style={{ margin: '0 0 6px' }}>{fs[0]?.algoLabel} <QTag quantum={fs.some(f => f.quantum)} /></h3>
              <div className="mono muted" style={{ fontSize: 12 }}>{fs.length} occurrence(s) across {files.length} file(s): {files.slice(0, 8).join(', ')}{files.length > 8 ? ` … +${files.length - 8}` : ''}</div></>;
          })() : null}
        </div>
      ) : null}
      <div className="grid g2 mt">
        <div><div className="sec-title">Externally-exposed paths <span className="n">{ext.length}</span></div>
          {ext.length === 0 ? <div className="card muted mono" style={{ fontSize: 12 }}>None in this scan.</div> : <FindingTable rows={ext.slice(0, 60)} onOpen={setModal} />}</div>
        <div><div className="sec-title">Secrets &amp; hidden blobs <span className="n">{sec.length}</span></div>
          {sec.length === 0 ? <div className="card muted mono" style={{ fontSize: 12 }}>None in this scan.</div> : <FindingTable rows={sec.slice(0, 60)} onOpen={setModal} />}</div>
      </div>
      <FindingModal f={modal} onClose={() => setModal(null)} />
    </>
  );
}

/* ================= 9. Migration roadmap ================= */
const MIG_KEY = 'cryptora-mig-v1';
const STATES = ['Discovered', 'Prioritized', 'Planned', 'In Progress', 'Migrated', 'Validated'];
function migKeyOf(f) { return `${f.algorithm}@${f.file}:${f.line}`; }
export function RoadmapPage({ scan }) {
  const [sel, setSel] = useState(null);
  const [fam, setFam] = useState('All');
  const [map, setMap] = useState(() => { try { return JSON.parse(localStorage.getItem(MIG_KEY) || '{}'); } catch { return {}; } });
  useEffect(() => { try { localStorage.setItem(MIG_KEY, JSON.stringify(map)); } catch { /* ignore */ } }, [map]);
  if (!scan) return <Empty />;
  const famOf = (f) => { const p = recommendFor(f).pqc || ''; if (p.includes('ML-KEM')) return 'ML-KEM'; if (p.includes('ML-DSA')) return 'ML-DSA'; if (p.includes('SLH-DSA')) return 'SLH-DSA'; return 'Other'; };
  const pri = [...scan.findings].sort((a, b) => b.riskScore - a.riskScore).filter(f => fam === 'All' || famOf(f) === fam);
  const now = pri.filter(f => f.severity === 'critical' || (f.quantum && f.riskScore >= 65)).slice(0, 12);
  const next = pri.filter(f => !now.includes(f) && (f.severity === 'high' || f.quantum)).slice(0, 12);
  const later = pri.filter(f => !now.includes(f) && !next.includes(f)).slice(0, 12);
  const setSt = (f, st) => setMap(m => ({ ...m, [migKeyOf(f)]: st }));
  const phases = [['Phase 1 — Now (0–30 days)', now, '#ff2d5e'], ['Phase 2 — Next (1–3 months)', next, '#f59e0b'], ['Phase 3 — Later (3–12 months)', later, '#22d3ee']];
  return (
    <>
      <p className="kicker">STEP 9 // MIGRATION ROADMAP</p>
      <h2 style={{ margin: '0 0 6px' }}>Migration Roadmap</h2>
      <p className="mono muted" style={{ fontSize: 12 }}>Phases auto-generated from your risk ranking. Status persists locally per finding. Classical → Hybrid → PQC, aligned to FIPS 203/204/205.</p>
      <div className="toolbar"><SegTabs options={['All', 'ML-KEM', 'ML-DSA', 'SLH-DSA', 'Other']} value={fam} onChange={setFam} /><span className="mono dim" style={{ fontSize: 11 }}>filter phases by PQC target family</span></div>
      {phases.map(([title, rows, color]) => (
        <div className="phase" key={title} style={{ borderLeft: `3px solid ${color}` }}>
          <h4>{title} <span className="dim mono" style={{ fontWeight: 400 }}>({rows.length} items)</span></h4>
          {rows.length === 0 ? <div className="mono muted" style={{ fontSize: 11.5 }}>Nothing in this phase.</div> :
            rows.map(f => {
              const rec = recommendFor(f);
              const st = map[migKeyOf(f)] || 'Discovered';
              return (
                <div key={f.id} className="mono" style={{ fontSize: 11.5, padding: '9px 0', borderTop: '1px solid #161d2c', display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                  <button style={{ background: 'none', border: 0, color: '#fff', cursor: 'pointer', fontFamily: 'monospace', fontSize: 11.5, padding: 0 }} onClick={() => setSel(f)}>{f.id} · {f.algoLabel}</button>
                  <span className="dim">{f.file}:{f.line}</span>
                  <span style={{ color: '#d8b4fe' }}>{rec.current} → {rec.hybrid !== '—' ? rec.hybrid + ' → ' : ''}{rec.pqc}</span>
                  <select value={st} onChange={e => setSt(f, e.target.value)} style={{ marginLeft: 'auto', background: '#0a0f18', border: '1px solid #2a3550', color: '#fff', borderRadius: 6, fontFamily: 'monospace', fontSize: 10.5, padding: '5px 8px' }}>
                    {STATES.map(s => <option key={s}>{s}</option>)}
                  </select>
                </div>
              );
            })}
        </div>
      ))}
      <div className="sec-title">Status board <span className="n">all tracked findings</span></div>
      <div className="distro">
        {STATES.map((s, si) => {
          const c = scan.findings.filter(f => (map[migKeyOf(f)] || 'Discovered') === s).length;
          const pct = scan.stats.findings ? Math.round((c / scan.stats.findings) * 100) : 0;
          const cols = ['#38bdf8', '#a78bfa', '#f59e0b', '#f97316', '#22c55e', '#86efac'];
          return <div className="dcol" key={s}><div className="dk">{s}</div><div className="dv">{c}</div><HBar value={pct} color={cols[si % cols.length]} /><div className="mono dim" style={{ fontSize: 10, marginTop: 3 }}>{pct}%</div></div>;
        })}
      </div>
      <div className="kanban mt">
        {STATES.map(s => (
          <div className="kcol" key={s}><h4>{s}</h4>
            {scan.findings.filter(f => (map[migKeyOf(f)] || 'Discovered') === s).slice(0, 30).map(f => (
              <div className="kcard" key={f.id}>{f.id}<br />{f.algorithm} · {f.file.split('/').pop()}:{f.line}
                <select value={s} onChange={e => setSt(f, e.target.value)}>{STATES.map(x => <option key={x}>{x}</option>)}</select>
              </div>
            ))}
          </div>
        ))}
      </div>
      <FindingModal f={sel} onClose={() => setSel(null)} />
    </>
  );
}

/* ================= 10. Validation ================= */
export function ValidatePage({ scan, snaps }) {
  const [cmp, setCmp] = useState(null);
  if (!scan) return <Empty />;
  const latest = snaps && snaps.length ? snaps[snaps.length - 1] : null;
  const d = latest ? diffScans(latest.data, scan) : null;
  return (
    <>
      <p className="kicker">STEP 10 // VALIDATION &amp; ROLLBACK</p>
      <h2 style={{ margin: '0 0 6px' }}>Validation &amp; Rollback</h2>
      <p className="mono muted" style={{ fontSize: 12 }}>Validate migrations by rescanning and diffing. Rollback plans are generated per finding from its migration path.</p>
      <div className="card">
        <div className="mono" style={{ fontSize: 12, lineHeight: 2 }}>
          <div>Current scan: <b>{scan.id}</b> · {scan.stats.findings} findings</div>
          <div>Baseline snapshot: <b>{latest ? latest.name : '— none saved yet (see Crypto Drift) —'}</b></div>
          {d ? <div>Δ vs baseline: <b style={{ color: '#86efac' }}>{d.removed.length} resolved</b> · <b style={{ color: '#ff7aa2' }}>{d.added.length} new</b> · {d.kept.length} unchanged</div> : null}
        </div>
        {latest ? <button className="btn sm primary mt" onClick={() => setCmp(d)}>▶ Compare current vs “{latest.name}”</button> : null}
      </div>
      {cmp ? (
        <div className="grid g2 mt">
          <div><div className="sec-title">✅ Resolved ({cmp.removed.length})</div>
            {cmp.removed.length === 0 ? <div className="card muted mono" style={{ fontSize: 12 }}>Nothing resolved yet.</div> :
              <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Was</th><th>File</th></tr></thead><tbody>
                {cmp.removed.slice(0, 100).map((f, i) => <tr key={i}><td>{f.algoLabel}</td><td className="mono" style={{ fontSize: 11 }}>{f.file}:{f.line}</td></tr>)}
              </tbody></table></div>}</div>
          <div><div className="sec-title">⚠ New since baseline ({cmp.added.length})</div>
            {cmp.added.length === 0 ? <div className="card muted mono" style={{ fontSize: 12 }}>No regressions. 🎉</div> :
              <div className="tbl-wrap"><table className="tbl"><thead><tr><th>Now</th><th>File</th></tr></thead><tbody>
                {cmp.added.slice(0, 100).map((f, i) => <tr key={i}><td>{f.algoLabel}</td><td className="mono" style={{ fontSize: 11 }}>{f.file}:{f.line}</td></tr>)}
              </tbody></table></div>}</div>
        </div>
      ) : null}
      <div className="sec-title">Rollback plan generator <span className="n">top 8 risks</span></div>
      {scan.findings.slice(0, 8).map(f => {
        const rec = recommendFor(f);
        return (
          <div className="phase" key={f.id}>
            <h4 className="mono" style={{ fontSize: 12 }}>{f.id} · {f.algoLabel} · {f.file}:{f.line}</h4>
            <ol className="mono muted" style={{ fontSize: 11.5, lineHeight: 1.9, margin: '6px 0 0 18px' }}>
              <li>Snapshot: pin current {rec.current} behaviour + keys (backup, don't delete).</li>
              <li>Ship hybrid behind a feature flag{rec.hybrid !== '—' ? ` (${rec.hybrid})` : ''} — verify both paths in staging.</li>
              <li>Roll forward to {rec.pqc}; keep flag for instant rollback within one deploy.</li>
              <li>Rescan with CRYPTORA → this page proves the finding is resolved.</li>
            </ol>
          </div>
        );
      })}
    </>
  );
}

/* ================= 11. Drift ================= */
export function DriftPage({ scan, snaps, setSnaps }) {
  const [a, setA] = useState('');
  const [b, setB] = useState('');
  const [name, setName] = useState('');
  if (!scan && snaps.length === 0) return <Empty>Run a scan, then save it as a snapshot to track cryptographic drift over time.</Empty>;
  const save = () => {
    if (!scan) return;
    const n = name.trim() || `snapshot-${new Date().toLocaleString()}`;
    setSnaps([...snaps, { name: n, at: new Date().toISOString(), data: scan }]);
    setName('');
  };
  const sa = snaps.find(s => s.name === a);
  const sb = b === '__current__' ? { name: 'current scan', data: scan } : snaps.find(s => s.name === b);
  const d = sa && sb ? diffScans(sa.data, sb.data) : null;
  const trend = [...snaps.map(s => ({ label: s.name.length > 12 ? s.name.slice(0, 11) + '…' : s.name, findings: s.data.stats.findings, quantum: s.data.stats.quantum, critical: s.data.stats.critical })), ...(scan ? [{ label: 'current', findings: scan.stats.findings, quantum: scan.stats.quantum, critical: scan.stats.critical }] : [])];
  return (
    <>
      <p className="kicker">STEP 11 // CRYPTO DRIFT</p>
      <h2 style={{ margin: '0 0 6px' }}>Crypto Drift</h2>
      <p className="mono muted" style={{ fontSize: 12 }}>Snapshots persist in your browser (localStorage). Compare any two to see new / removed / changed crypto.</p>
      <div className="toolbar">
        <input type="text" placeholder="Snapshot name…" value={name} onChange={e => setName(e.target.value)} />
        <button className="btn sm primary" disabled={!scan} onClick={save}>＋ Save current scan as snapshot</button>
        {snaps.length ? <button className="btn sm ghost" onClick={() => { if (confirm('Delete all snapshots?')) setSnaps([]); }}>Clear</button> : null}
      </div>
      {snaps.length === 0 ? <div className="card muted mono" style={{ fontSize: 12 }}>No snapshots yet.</div> : (
        <>
          <div className="tbl-wrap"><table className="tbl">
            <thead><tr><th>Snapshot</th><th>Saved</th><th>Files</th><th>Findings</th><th>Quantum</th><th>Critical</th></tr></thead>
            <tbody>{snaps.map(s => (
              <tr key={s.name}><td className="mono">{s.name}</td><td className="mono" style={{ fontSize: 11 }}>{new Date(s.at).toLocaleString()}</td>
                <td className="mono">{s.data.stats.filesScanned}</td><td className="mono">{s.data.stats.findings}</td>
                <td className="mono">{s.data.stats.quantum}</td><td className="mono">{s.data.stats.critical}</td></tr>
            ))}</tbody>
          </table></div>
          <div className="card mt">
            <div className="sec-title" style={{ marginTop: 0 }}>Snapshot trend <span className="n">real history — one point per saved snapshot{scan ? ' + current scan' : ''}</span></div>
            <AreaChart series={[
              { name: 'Findings', color: '#8b5cf6', values: trend.map(p => p.findings) },
              { name: 'Quantum', color: '#f97316', values: trend.map(p => p.quantum) },
              { name: 'Critical', color: '#ff2d5e', values: trend.map(p => p.critical) },
            ]} xLabels={trend.map(p => p.label)} />
          </div>
          <div className="toolbar mt">
            <select value={a} onChange={e => setA(e.target.value)}><option value="">Baseline…</option>{snaps.map(s => <option key={s.name} value={s.name}>{s.name}</option>)}</select>
            <select value={b} onChange={e => setB(e.target.value)}><option value="">Target…</option>{snaps.map(s => <option key={s.name} value={s.name}>{s.name}</option>)}<option value="__current__">current scan</option></select>
          </div>
          {d ? (
            <div className="grid g3">
              <Stat k="New crypto" v={d.added.length} color={d.added.length ? '#ff7aa2' : undefined} />
              <Stat k="Removed" v={d.removed.length} color="#86efac" />
              <Stat k="Unchanged" v={d.kept.length} />
            </div>
          ) : null}
          {d && (d.added.length > 0 || d.removed.length > 0) ? (
            <div className="grid g2 mt">
              <div><div className="sec-title">＋ New</div><div className="tbl-wrap"><table className="tbl"><tbody>
                {d.added.slice(0, 80).map((f, i) => <tr key={i}><td>{f.algoLabel}</td><td className="mono" style={{ fontSize: 11 }}>{f.file}:{f.line}</td></tr>)}
              </tbody></table></div></div>
              <div><div className="sec-title">－ Removed</div><div className="tbl-wrap"><table className="tbl"><tbody>
                {d.removed.slice(0, 80).map((f, i) => <tr key={i}><td>{f.algoLabel}</td><td className="mono" style={{ fontSize: 11 }}>{f.file}:{f.line}</td></tr>)}
              </tbody></table></div></div>
            </div>
          ) : null}
        </>
      )}
    </>
  );
}

/* ================= 13. AI investigator ================= */
const SUGGESTIONS = [
  "What's the highest-risk finding?",
  'How many critical findings are there?',
  "What's the risk score and priority?",
  'Which algorithms are quantum-vulnerable?',
  'Any transitive npm dependencies?',
  'What should I fix first?',
];
export function AiPage({ scan }) {
  const [msgs, setMsgs] = useState([{ r: 'a', t: 'Ask about any cryptography term, or — once you\'ve scanned something — about your actual findings. Answers are generated locally, grounded in your real scan when one exists; not a hosted LLM, and not canned.' }]);
  const [inp, setInp] = useState('');
  const answer = (q) => {
    const s = q.toLowerCase();
    if (!scan) {
      for (const k of Object.keys(KB_EXPLAIN)) {
        if (s.includes(k.toLowerCase())) return `${k}: ${KB_EXPLAIN[k]}\n\n(No scan loaded — run Upload / Analyze to ground answers in your code.)`;
      }
      return 'No scan loaded yet — run Upload / Analyze first, then ask me about it. I can already explain terms like RSA, ECDSA, AES, MD5, TLS, JWT.';
    }
    const idm = s.match(/f-(\d{1,5})/);
    if (idm) {
      const f = scan.findings.find(x => x.id.toLowerCase() === ('f-' + idm[1].padStart(4, '0')).toLowerCase()) || scan.findings.find(x => x.id.endsWith(idm[1]));
      if (!f) return `I can't find ${idm[0].toUpperCase()} in this scan (${scan.findings.length} findings). Check the ID in Crypto Discovery.`;
      const rec = recommendFor(f);
      return `${f.id} — ${f.algoLabel} @ ${f.file}:${f.line}\nSeverity ${f.severity.toUpperCase()} · risk ${f.riskScore} (${f.riskBand}) · detector ${f.detector}${f.layer ? ' · ' + f.layer : ''} · confidence ${(f.confidence * 100).toFixed(0)}%\n\nWhy it matters:\n${(f.reason || []).map(r => '• ' + r).join('\n')}\n\nEvidence:\n${f.evidence}\n\nPath: ${rec.current} → ${rec.hybrid} → ${rec.pqc}\nNote: ${rec.note}`;
    }
    if (/highest-risk|highest risk|top finding/.test(s)) {
      const f = scan.findings[0];
      return f ? `Highest-risk finding: ${f.id} — ${f.algoLabel} @ ${f.file}:${f.line}\nSeverity ${f.severity.toUpperCase()} · risk ${f.riskScore} (${f.riskBand})${f.quantum ? ' · QUANTUM-VULNERABLE' : ''}\n\n${(f.reason || []).join(' | ')}` : 'No findings in this scan.';
    }
    if (/how many critical/.test(s)) {
      const st = scan.stats;
      return `Critical: ${st.critical} · High: ${st.high} · Medium: ${st.medium} · Low: ${st.low} · Info: ${st.info} (of ${st.findings} total across ${st.filesScanned} files).`;
    }
    if (/risk score and priority|risk score/.test(s)) {
      const exp = exposureScore(scan.findings);
      return `Aggregate exposure: ${exp.score}/100 (${exp.band}) — severity-weighted mean over ${scan.stats.findings} findings with a quantum bump.\nPriority: ${scan.findings.slice(0, 3).map(f => `${f.id} (${f.algoLabel}, risk ${f.riskScore})`).join(' → ') || '—'}\nSee Step 5 (Quantum & Business Risk) for the full model and Mosca planner.`;
    }
    if (/quantum-vulnerable|quantum vulnerable/.test(s)) {
      const qa = [...new Set(scan.findings.filter(f => f.quantum).map(f => f.algorithm))];
      return qa.length ? `Quantum-vulnerable algorithms in this scan (${scan.stats.quantum} findings): ${qa.join(', ')}.\nAll are Shor-breakable public-key crypto → migrate via hybrids to ML-KEM/ML-DSA (FIPS 203/204).` : 'No quantum-vulnerable findings in this scan. 🎉';
    }
    if (/transitive|npm dependencies|dependencies/.test(s)) {
      const deps = scan.deps || [];
      const eco = [...new Set(deps.map(d => d.ecosystem))];
      return `${deps.length} direct manifest dependencies parsed (${eco.join(', ') || 'none'}).\nTransitive resolution (lockfile-graph walk) is not performed in this build — direct crypto-relevant packages are flagged in Discovery and Step 3. Roadmap: full transitive closure.`;
    }
    if (/fix first|priorit|most urgent|break first/.test(s)) {
      const t = scan.findings.slice(0, 5);
      return `Fix-first order for this scan (risk-ranked):\n${t.map((f, i) => `${i + 1}. ${f.id} ${f.algoLabel} @ ${f.file}:${f.line} — ${f.severity}, risk ${f.riskScore}${f.quantum ? ' [QUANTUM]' : ''}`).join('\n')}\n\nRule: critical + exposed secrets first, then quantum items under Mosca pressure, then weak hashes/modes.`;
    }
    for (const k of Object.keys(KB_EXPLAIN)) {
      if (s.includes(k.toLowerCase())) {
        const n = scan.findings.filter(f => f.algorithm === k).length;
        return `${k}: ${KB_EXPLAIN[k]}\n\nIn THIS scan: ${n} finding(s) reference ${k}.`;
      }
    }
    if (/summar/.test(s)) {
      const st = scan.stats;
      return `Scan ${scan.id} (${scan.source}):\n• ${st.filesScanned} files, ${st.findings} findings (C:${st.critical} H:${st.high} M:${st.medium} L:${st.low})\n• Quantum-vulnerable: ${st.quantum} · Secrets: ${st.secrets} · Hidden blobs: ${st.hidden}\n• Certs parsed: ${st.certs} · Deps: ${st.deps}\n\nBiggest cluster: ${topAlgos(scan, false).join(', ') || '—'}`;
    }
    if (/pqc|quantum|hybrid|mosca/.test(s)) return `This scan's quantum posture: ${scan.stats.quantum}/${scan.stats.findings} findings are Shor-vulnerable (RSA/ECDSA/ECDH/DH/DSA/EdDSA/JWT-RS). Strategy: hybrid now (X25519+ML-KEM-768 for KEX, dual-sign ECDSA+ML-DSA), pure PQC per FIPS 203/204/205 as libs land. Tune X/Y/Z on Step 5 to apply Mosca to your data lifetimes.`;
    if (/secret|leak|key/.test(s)) {
      const secs = scan.findings.filter(f => f.category === 'secret');
      return secs.length ? `Found ${secs.length} embedded secret(s):\n${secs.slice(0, 8).map(f => `• ${f.id} ${f.algoLabel} @ ${f.file}:${f.line}`).join('\n')}\n\nAction: revoke + rotate each, purge from history, move to KMS/vault. Values are redacted in this UI by design.` : 'No embedded secrets in this scan. High-entropy blobs are still listed under Hidden Encryption for manual triage.';
    }
    return `I can answer from this scan's deterministic data only. Try a suggestion above, an ID like "${(scan.findings[0] && scan.findings[0].id) || 'F-0001'}", or "summarise this scan".`;
  };
  const send = (text) => {
    const q = (text || inp).trim();
    if (!q) return;
    setMsgs(m => [...m, { r: 'q', t: q }, { r: 'a', t: answer(q) }]);
    setInp('');
  };
  return (
    <>
      <p className="kicker">STEP 12 // AI INVESTIGATOR</p>
      <h2 style={{ margin: '0 0 6px' }}>AI Crypto Investigator</h2>
      <p className="mono muted" style={{ fontSize: 12 }}>Ask about any cryptography term, or — once you've scanned something — about your actual findings. Answers are generated locally, grounded in your real scan when one exists; not a hosted LLM, and not canned.</p>
      <div className="card">
        <div className="chips">
          {SUGGESTIONS.map(s => <button key={s} onClick={() => send(s)}>{s}</button>)}
        </div>
      </div>
      <div className="card mt">
        <div className="chatbox">
          {msgs.length <= 1 ? <div className="mono dim" style={{ textAlign: 'center', fontSize: 12 }}>Ask a question about your scan, or click a suggestion above.</div> : null}
          {msgs.map((m, i) => <div key={i} className={`chat-msg ${m.r}`}>{m.t}</div>)}
        </div>
        <div className="toolbar mt" style={{ marginBottom: 0 }}>
          <input type="text" placeholder="Ask about a term, or your scan once you've run one…" value={inp} onChange={e => setInp(e.target.value)} onKeyDown={e => e.key === 'Enter' && send()} style={{ flex: 1 }} />
          <button className="btn primary sm" onClick={() => send()}>Ask</button>
        </div>
      </div>
      <div className="card mt">
        <div className="sec-title" style={{ marginTop: 0 }}>Methodology Notes</div>
        <div className="mono" style={{ fontSize: 11.5, lineHeight: 1.9, color: '#c9d6ea' }}>
          <p><b>How does CRYPTORA classify quantum risk?</b><br />Public-key algorithms (RSA, ECC/ECDSA/ECDH, DSA, classical Diffie-Hellman) are broken by Shor's algorithm on a sufficiently large quantum computer, so they're marked HIGH. Symmetric algorithms (AES-256, ChaCha20) and hashes (SHA-2/3) only face Grover's quadratic speedup — safe at 256-bit strength. PQC algorithms (ML-KEM, ML-DSA, SLH-DSA) are marked SAFE.</p>
          <p><b>How is the risk score computed?</b><br />Severity baseline + quantum (+1.5) + secret material (+1.5) + path exposure, tuned by your business context. The exact factors are shown under every score — nothing is a black box.</p>
          <p><b>What are the limits?</b><br />Heuristic static analysis: regex + AST-lite, entropy, manifests, Dockerfile, ASN.1 certs, binary strings. It cannot see runtime behavior, obfuscated binaries' internals, or transitive dependencies beyond manifests. No 100% coverage is claimed.</p>
        </div>
      </div>
    </>
  );
}

/* ================= 14. Hidden encryption ================= */
export function HiddenPage({ scan }) {
  const [sel, setSel] = useState(null);
  if (!scan) return <Empty />;
  const fe = scan.fileEntropy || [];
  const top = fe.slice(0, 12);
  const maxE = 8;
  const rows = scan.findings.filter(f => f.category === 'hidden' || f.category === 'secret');
  return (
    <>
      <p className="kicker">STEP 13 // HIDDEN ENCRYPTION</p>
      <h2 style={{ margin: '0 0 6px' }}>Cryptography Nobody Registered</h2>
      <p className="mono muted" style={{ fontSize: 12 }}>Standard pattern matching misses crypto that's deliberately or accidentally hidden. This is a genuine Shannon-entropy calculation over every scanned file — high entropy (&gt;6.6 bits/byte) suggests encrypted, compressed, or key-like content, even with no algorithm keyword present.</p>
      <div className="grid g4">
        <Stat k="High-entropy files" v={scan.stats.highEntropyFiles || 0} color={(scan.stats.highEntropyFiles || 0) ? '#ff7aa2' : undefined} />
        <Stat k="Files analyzed" v={fe.length} color="#38bdf8" />
        <Stat k="Peak entropy (bits/byte)" v={scan.stats.peakEntropy || 0} color="#f97316" />
        <Stat k="Detection method" v="REAL" s="computed, not lookup" color="#22c55e" />
      </div>
      <div className="grid g2 mt">
        <div className="card" style={{ display: 'grid', placeItems: 'center', minHeight: 180 }}>
          {(scan.stats.highEntropyFiles || 0) === 0
            ? <div className="mono muted" style={{ fontSize: 13, textAlign: 'center' }}>No files crossed the high-entropy threshold in this scan.</div>
            : <div style={{ width: '100%' }}>{fe.filter(f => f.entropy >= 6.6).map(f => (
              <div key={f.path} className="mono" style={{ fontSize: 11.5, padding: '6px 0', borderBottom: '1px solid #161d2c' }}>
                <b style={{ color: '#ff7aa2' }}>{f.entropy.toFixed(2)}</b> · {f.path} <span className="dim">({(f.bytes / 1024).toFixed(1)} KB)</span>
              </div>))}</div>}
        </div>
        <div className="card">
          <div className="sec-title" style={{ marginTop: 0 }}>Entropy Scan <span className="n">every scanned file, ranked by Shannon entropy</span></div>
          {top.length === 0 ? <div className="mono muted" style={{ fontSize: 12 }}>No file-entropy data (restored archive).</div> : (
            <div className="entropy-bars">
              {top.map(f => (
                <div key={f.path} className="ebar" title={`${f.path} — ${f.entropy} bits/byte`}>
                  <span className="eval">{f.entropy.toFixed(2)}</span>
                  <div className="etrack"><i style={{ height: `${(f.entropy / maxE) * 100}%` }} /></div>
                  <span className="epath">…{f.path.slice(-14)}</span>
                </div>
              ))}
            </div>
          )}
          <p className="mono dim" style={{ fontSize: 11 }}>This is a real, computed measurement — not a lookup table.</p>
        </div>
      </div>
      <div className="sec-title">Token-level candidates <span className="n">{rows.length} high-entropy strings + embedded secrets</span></div>
      <FindingTable rows={rows} onOpen={setSel} />
      <FindingModal f={sel} onClose={() => setSel(null)} />
    </>
  );
}
