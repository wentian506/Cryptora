import React, { useEffect } from 'react';
import { Empty, Sev, download } from './ui.jsx';
import { recommendFor, mosca } from '../scanner/engine.js';

function csvCell(v) {
  const s = String(v ?? '');
  return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
}
export function findingsCSV(scan) {
  const head = ['id', 'severity', 'risk_score', 'risk_band', 'algorithm', 'finding', 'file', 'line', 'symbol', 'library', 'detector', 'confidence', 'quantum', 'evidence', 'reasons'];
  const lines = [head.join(',')];
  for (const f of scan.findings) {
    lines.push([f.id, f.severity, f.riskScore, f.riskBand, f.algorithm, f.algoLabel, f.file, f.line, f.symbol, f.library, f.detector, f.confidence, f.quantum ? 'yes' : 'no', f.evidence, (f.reason || []).join(' | ')].map(csvCell).join(','));
  }
  return lines.join('\n');
}

export default function ReportPage({ scan }) {
  useEffect(() => {
    document.body.classList.add('on-report');
    return () => document.body.classList.remove('on-report');
  }, []);
  if (!scan) return <Empty title="No report yet">Run a scan first — the executive report, PDF export and CSV are generated from live scan data.</Empty>;
  const s = scan.stats;
  const m = mosca(10, 3, 12);
  const top = scan.findings.slice(0, 15);
  const quant = scan.findings.filter(f => f.quantum).slice(0, 15);
  return (
    <>
      <p className="kicker no-print">STEP 14 // REPORTS</p>
      <h2 className="no-print" style={{ margin: '0 0 6px' }}>Reports</h2>
      <p className="mono muted no-print" style={{ fontSize: 12 }}>Executive report, printable PDF, and machine-readable exports — all generated from the live scan.</p>
      <div className="toolbar no-print">
        <button className="btn primary sm" onClick={() => window.print()}>🖨 Print / Download PDF</button>
        <button className="btn sm" onClick={() => download(`cryptora-report-${scan.id}.csv`, findingsCSV(scan), 'text/csv')}>⬇ Findings CSV</button>
        <button className="btn sm" onClick={() => download(`cryptora-report-${scan.id}.json`, JSON.stringify({ meta: { id: scan.id, source: scan.source, at: scan.completedAt }, stats: s, findings: scan.findings }, null, 2))}>⬇ Report JSON</button>
        <button className="btn sm" onClick={() => download(`cryptora-cbom-${scan.id}.json`, JSON.stringify(scan.cbom, null, 2))}>⬇ CBOM JSON</button>
      </div>

      <div className="report-doc">
        <div className="rep-head">
          <div><div className="rep-brand">◉ CRYPTORA</div><div className="mono dim" style={{ fontSize: 10, letterSpacing: 2 }}>CRYPTOGRAPHIC RISK &amp; MIGRATION INTELLIGENCE</div></div>
          <div className="mono" style={{ fontSize: 11, textAlign: 'right' }}>EXECUTIVE REPORT<br />{new Date(scan.completedAt).toLocaleString()}<br />{scan.id}</div>
        </div>
        <h1>Cryptographic Risk Report — {scan.project}</h1>
        <p className="mono">Source: {scan.source} · Files scanned: {s.filesScanned} · Duration: {(scan.durationMs / 1000).toFixed(1)}s · Team KRYPTX</p>

        <h2>1. Executive summary</h2>
        <table className="rep-tbl"><tbody>
          <tr><td>Total findings</td><td><b>{s.findings}</b></td><td>Critical / High</td><td><b>{s.critical} / {s.high}</b></td></tr>
          <tr><td>Quantum-vulnerable</td><td><b>{s.quantum}</b></td><td>Embedded secrets</td><td><b>{s.secrets}</b></td></tr>
          <tr><td>Hidden blobs</td><td><b>{s.hidden}</b></td><td>Certs / Deps parsed</td><td><b>{s.certs} / {s.deps}</b></td></tr>
          <tr><td>Mosca (10+3 vs Z12)</td><td colSpan="3"><b>{m.verdict}</b> (gap {m.gap > 0 ? '+' : ''}{m.gap}y)</td></tr>
        </tbody></table>

        <h2>2. Top risks (by risk score)</h2>
        <table className="rep-tbl"><thead><tr><th>#</th><th>ID</th><th>Severity</th><th>Finding</th><th>Location</th><th>Risk</th></tr></thead><tbody>
          {top.map((f, i) => <tr key={f.id}><td>{i + 1}</td><td>{f.id}</td><td>{f.severity.toUpperCase()}</td><td>{f.algoLabel}{f.quantum ? ' [Q]' : ''}</td><td>{f.file}:{f.line}</td><td>{f.riskScore} ({f.riskBand})</td></tr>)}
        </tbody></table>

        <h2>3. Quantum exposure &amp; PQC path</h2>
        {quant.length === 0 ? <p className="mono">No quantum-vulnerable findings in this scan.</p> : (
          <table className="rep-tbl"><thead><tr><th>Finding</th><th>Location</th><th>Current → Hybrid → PQC</th></tr></thead><tbody>
            {quant.map(f => { const r = recommendFor(f); return (
              <tr key={f.id}><td>{f.algoLabel} ({f.id})</td><td>{f.file}:{f.line}</td><td>{r.current} → {r.hybrid} → {r.pqc}</td></tr>); })}
          </tbody></table>)}
        <p className="mono">Standards: ML-KEM (FIPS 203) · ML-DSA (FIPS 204) · SLH-DSA (FIPS 205). CRYPTORA invents no new cryptography.</p>

        <h2>4. Method &amp; limits</h2>
        <p className="mono">Heuristic static analysis (regex + AST-lite + entropy + manifest/Dockerfile/ASN.1/binary-string inspection) computed live from the uploaded scan. Secrets redacted. Not a substitute for full AST/binary/dependency audit. No 100% coverage or accuracy claimed.</p>

        <div className="rep-foot mono">CRYPTORA · Encrypt. Protect. Trust. · Generated {new Date().toLocaleString()} · Page 1 of 1 (print view)</div>
      </div>

      <div className="sec-title no-print">Full finding list <span className="n">{scan.findings.length} — included in CSV/JSON exports</span></div>
      <div className="tbl-wrap no-print"><table className="tbl">
        <thead><tr><th>ID</th><th>Severity</th><th>Finding</th><th>File</th><th>Risk</th></tr></thead>
        <tbody>{scan.findings.slice(0, 200).map(f => (
          <tr key={f.id}><td className="mono">{f.id}</td><td><Sev level={f.severity} /></td><td>{f.algoLabel}</td><td className="mono" style={{ fontSize: 11 }}>{f.file}:{f.line}</td><td className="mono">{f.riskScore}</td></tr>
        ))}</tbody>
      </table></div>
    </>
  );
}
