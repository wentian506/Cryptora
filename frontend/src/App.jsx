import React, { useEffect, useState } from 'react';
import UploadDrawer from './components/UploadDrawer.jsx';
import Landing from './components/Landing.jsx';
import Auth from './components/Auth.jsx';
import ReportPage from './components/Report.jsx';
import CloudPanel from './components/Cloud.jsx';
import {
  OverviewPage, DiscoveryPage, CbomPage, DepGraphPage, CertsPage, RiskPage,
  AgilityPage, BreakPage, AttackPage, RoadmapPage, ValidatePage, DriftPage,
  AiPage, HiddenPage
} from './components/pages.jsx';
import { clearSession, getSessionUser } from './lib/api.js';

/* Sidebar order matches the reference screenshots top-to-bottom, plus Reports. */
const NAV = [
  { id: 'overview', step: null, label: 'Executive Overview', icon: '▦', title: 'Executive Overview', sub: 'Live results from your scan' },
  { id: 'discovery', step: 1, label: 'Crypto Discovery', icon: '⌕', title: 'Crypto Discovery', sub: 'Scan real files, a GitHub repo, or pasted code' },
  { id: 'cbom', step: 2, label: 'CBOM & Evidence', icon: '▤', title: 'CBOM & Evidence', sub: 'Every real finding, with file/line evidence' },
  { id: 'deps', step: 3, label: 'Dependency Graph', icon: '⎇', title: 'Crypto Dependency Graph', sub: 'Which files use which algorithm' },
  { id: 'certs', step: 4, label: 'Certs, Containers, Bin.', icon: '▣', title: 'Certs, Containers, Bin.', sub: 'X.509 · Dockerfile · binaries' },
  { id: 'risk', step: 5, label: 'Quantum & Business Risk', icon: '◔', title: 'Quantum & Business Risk', sub: 'Computed from your actual findings' },
  { id: 'agility', step: 6, label: 'Crypto Agility', icon: '↯', title: 'Crypto Agility', sub: '0–100 score: how easily this codebase can migrate' },
  { id: 'break', step: 7, label: 'What Will Break?', icon: '⚡', title: 'What Will Break?', sub: 'Break-first ordering' },
  { id: 'attack', step: 8, label: 'Attack Surface', icon: '✛', title: 'Attack Surface', sub: 'App → dependency → algorithm → file, mapped from real data' },
  { id: 'roadmap', step: 9, label: 'Migration Roadmap', icon: '→', title: 'Migration Roadmap', sub: 'Classical → Hybrid → PQC' },
  { id: 'validate', step: 10, label: 'Validation & Rollback', icon: '✔', title: 'Validation & Rollback', sub: 'Rescan proof + rollback' },
  { id: 'drift', step: 11, label: 'Crypto Drift', icon: '∿', title: 'Crypto Drift', sub: 'Snapshot comparison' },
  { id: 'ai', step: 12, label: 'AI Crypto Investigator', icon: '☀', title: 'AI Crypto Investigator', sub: 'Grounded Q&A over your real findings' },
  { id: 'hidden', step: 13, label: 'Hidden Encryption', icon: '◈', title: 'Hidden Encryption', sub: 'Real Shannon-entropy scan of your files' },
  { id: 'report', step: 14, label: 'Reports', icon: '⎙', title: 'Reports', sub: 'Executive report · PDF · CSV' },
];

const SNAP_KEY = 'cryptora-snaps-v1';

function initialPage() {
  const h = (location.hash || '').replace('#/', '').replace('#', '');
  if (NAV.some(n => n.id === h)) return h;
  if (h === 'auth') return 'auth';
  if (h === 'landing') return 'landing';
  return 'overview';
}

export default function App() {
  const [page, setPage] = useState(initialPage);
  const [scan, setScan] = useState(null);
  const [uploadOpen, setUploadOpen] = useState(false);
  const [clock, setClock] = useState('');
  const [riskCtx, setRiskCtx] = useState({ sensitivity: 3, criticality: 3, exposure: 3 });
  const [user, setUser] = useState(() => getSessionUser());
  const [demoSession, setDemoSession] = useState(() => {
    try { return localStorage.getItem('cryptora-demo') === '1'; } catch { return false; }
  });
  const [scanning, setScanning] = useState(false);
  const [scanLog, setScanLog] = useState([]);
  const [sideOpen, setSideOpen] = useState(false);
  const [snaps, setSnaps] = useState(() => {
    try { return JSON.parse(localStorage.getItem(SNAP_KEY) || '[]'); } catch { return []; }
  });

  useEffect(() => {
    const t = () => setClock(new Date().toLocaleTimeString('en-GB', { hour12: false }));
    t();
    const id = setInterval(t, 1000);
    return () => clearInterval(id);
  }, []);
  useEffect(() => {
    try { localStorage.setItem(SNAP_KEY, JSON.stringify(snaps.slice(-8))); } catch { /* quota */ }
  }, [snaps]);

  useEffect(() => {
    const apply = () => {
      const h = (location.hash || '').replace('#/', '').replace('#', '');
      if (NAV.some(n => n.id === h)) setPage(h);
      else if (h === 'auth') setPage('auth');
      else if (h === 'landing') setPage('landing');
      else setPage('overview');
    };
    window.addEventListener('hashchange', apply);
    return () => window.removeEventListener('hashchange', apply);
  }, []);

  const enter = (id) => {
    setPage(id);
    setSideOpen(false);
    location.hash = '#/' + id;
  };
  const goLanding = () => { setPage('landing'); setSideOpen(false); location.hash = '#/landing'; };
  const signOut = () => {
    clearSession();
    try { localStorage.removeItem('cryptora-demo'); } catch { /* ignore */ }
    setUser(null);
    setDemoSession(false);
  };
  const handleScanState = (ev) => {
    if (ev.reset) setScanLog([]);
    if (ev.append) setScanLog(prev => [...prev.slice(-400), ev.append]);
    if (ev.active !== undefined) setScanning(ev.active);
  };

  if (page === 'landing') {
    return <Landing onLaunch={() => enter('overview')} onSignIn={() => { setPage('auth'); location.hash = '#/auth'; }} />;
  }
  if (page === 'auth') {
    return <Auth
      onBack={() => enter('overview')}
      onDemo={() => { try { localStorage.setItem('cryptora-demo', '1'); } catch { /* ignore */ } setDemoSession(true); enter('overview'); }}
      onAuth={(u) => { setUser(u); setDemoSession(false); enter('overview'); }}
    />;
  }

  const cur = NAV.find(n => n.id === page) || NAV[0];
  const signedIn = !!(user || demoSession);

  return (
    <div className="app">
      <div className={`side-scrim ${sideOpen ? 'show' : ''}`} onClick={() => setSideOpen(false)} />
      <aside className={`sidebar ${sideOpen ? 'open' : ''}`}>
        <div className="brand brand-click" onClick={goLanding} title="Back to site">
          <div className="brand-mark">◉</div>
          <div><b>CRYPTORA</b><small>CRYPTO INTELLIGENCE</small></div>
          <button className="side-close" aria-label="Close navigation" onClick={(e) => { e.stopPropagation(); setSideOpen(false); }}>✕</button>
        </div>
        <nav className="nav">
          {NAV.map(n => (
            <button key={n.id} className={page === n.id ? 'active' : ''} onClick={() => enter(n.id)}>
              {n.step ? <span className="step-pill">{n.step}</span> : <span className="ic">{n.icon}</span>}
              <span className="lbl">{n.label}</span>
              {scan && n.id === 'cbom' ? <span className="count-badge">{scan.stats.findings}</span> : null}
            </button>
          ))}
        </nav>
        <div className="side-foot"><span className="dot">●</span> ESTATE MONITORED · LIVE</div>
      </aside>

      <div className="main">
        <div className="topbar">
          <button className="hamburger" onClick={() => setSideOpen(true)} aria-label="Open navigation">☰</button>
          <div className="tb-title"><h1>{cur.title}</h1><p>{cur.sub}</p></div>
          <div className="top-right">
            <button className="btn sm" onClick={() => setUploadOpen(true)}>⇪ <span className="tb-btn-txt">Upload / Analyze</span></button>
            {scanning ? (
              <span className="pill-badge scanning"><span className="dot pulse">●</span>SCANNING…</span>
            ) : scan ? (
              <span className="pill-badge scanned"><span className="dot">●</span>{String(scan.source).slice(0, 28)}</span>
            ) : (
              <span className="pill-badge"><span className="dot">●</span>NO SCAN YET</span>
            )}
            {signedIn ? (
              <span className="pill-badge scanned user-pill" title={user ? `Account: ${user.email || user.phone}` : 'Local demo session'}>
                <span className="dot">●</span>{user ? (user.name || user.email || user.phone || 'USER').toString().slice(0, 12).toUpperCase() : 'DEMO'}
                {' · '}<a href="#/" onClick={(e) => { e.preventDefault(); signOut(); }} style={{ color: '#8fe6f5' }}>OUT</a>
              </span>
            ) : (
              <button className="btn sm ghost" onClick={() => { setPage('auth'); location.hash = '#/auth'; }}>Sign in</button>
            )}
            <span className="clock">{clock}</span>
          </div>
        </div>
        <div className="content">
          {page === 'overview' && user && <CloudPanel scan={scan} user={user} onLoadScan={(s) => { setScan(s); }} />}
          {page === 'overview' && <OverviewPage scan={scan} onUpload={() => setUploadOpen(true)} />}
          {page === 'discovery' && <DiscoveryPage scan={scan} scanLog={scanLog} scanning={scanning} onUpload={() => setUploadOpen(true)} />}
          {page === 'cbom' && <CbomPage scan={scan} />}
          {page === 'deps' && <DepGraphPage scan={scan} onGo={enter} />}
          {page === 'certs' && <CertsPage scan={scan} />}
          {page === 'risk' && <RiskPage scan={scan} ctx={riskCtx} setCtx={setRiskCtx} onGo={enter} />}
          {page === 'agility' && <AgilityPage scan={scan} />}
          {page === 'break' && <BreakPage scan={scan} />}
          {page === 'attack' && <AttackPage scan={scan} />}
          {page === 'roadmap' && <RoadmapPage scan={scan} />}
          {page === 'validate' && <ValidatePage scan={scan} snaps={snaps} setSnaps={setSnaps} />}
          {page === 'drift' && <DriftPage scan={scan} snaps={snaps} setSnaps={setSnaps} />}
          {page === 'report' && <ReportPage scan={scan} />}
          {page === 'ai' && <AiPage scan={scan} />}
          {page === 'hidden' && <HiddenPage scan={scan} />}

          <div className="disclaimer">
            CRYPTORA does not invent new cryptography — it applies NIST-standardized PQC (ML-KEM / FIPS 203, ML-DSA / FIPS 204, SLH-DSA / FIPS 205) around what it finds. No quantum hardware is required to run this platform. This build is a heuristic, regex + AST-lite static scanner running entirely in your browser — not a substitute for a full AST/binary/dependency analysis pipeline. Team KRYPTX · SIH PS-26164 · Encrypt. Protect. Trust.
          </div>
        </div>
      </div>

      <UploadDrawer
        open={uploadOpen}
        onClose={() => setUploadOpen(false)}
        onScanState={handleScanState}
        onScanStart={() => { setUploadOpen(false); enter('discovery'); }}
        onDone={(s) => { setScan(s); setUploadOpen(false); enter('discovery'); }}
      />
    </div>
  );
}
