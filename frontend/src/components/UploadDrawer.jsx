import React, { useRef, useState } from 'react';
import JSZip from 'jszip';
import { runScan, fetchRepoFileList, fetchRepoFiles, parseGithubUrl } from '../scanner/engine.js';
import { LogTerminal } from './ui.jsx';

const TABS = [
  { id: 'files', label: 'Files / ZIP' },
  { id: 'folder', label: 'Folder' },
  { id: 'repo', label: 'Repository URL' },
  { id: 'paste', label: 'Paste Code' },
  { id: 'link', label: 'Link / URL' },
  { id: 'certs', label: 'Certificates' },
  { id: 'dockerfile', label: 'Dockerfile' },
  { id: 'containers', label: 'Containers' },
  { id: 'binaries', label: 'Binaries / Docs' },
];

const MAX_FILE = 1_200_000;
const MAX_FILES = 120;

export default function UploadDrawer({ open, onClose, onDone, onScanState, onScanStart }) {
  const [tab, setTab] = useState('repo');
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState('');
  const [pct, setPct] = useState(0);
  const [err, setErr] = useState('');
  const [picked, setPicked] = useState([]);
  const [log, setLog] = useState([]);
  const [skipLock, setSkipLock] = useState(true);
  const [skipMin, setSkipMin] = useState(true);
  const [repoUrl, setRepoUrl] = useState('');
  const [branch, setBranch] = useState('');
  const [pasteName, setPasteName] = useState('snippet.js');
  const [pasteCode, setPasteCode] = useState('');
  const [linkUrl, setLinkUrl] = useState('');
  const [certPaste, setCertPaste] = useState('');
  const [dockerPaste, setDockerPaste] = useState('');
  const [composePaste, setComposePaste] = useState('');
  const dropRef = useRef(null);

  if (!open) return null;

  function reset() { setErr(''); setMsg(''); setPct(0); }
  function say(line) {
    setLog(prev => [...prev.slice(-300), line]);
    if (onScanState) onScanState({ append: line });
  }
  function scanBegin(label) {
    reset(); setBusy(true); setLog([]);
    if (onScanState) onScanState({ active: true, reset: true });
    say(`▸ Source: ${label}`);
    say('▸ Engine layers: L1 Regex · L2 AST-lite · L3 Secrets · L4 Entropy · L5 Manifests · L6 Containers · L7 ASN.1 certs · L8 Binary strings');
    if (skipLock) say('▸ Skipping dependency lockfiles (*-lock.json, *.lock, go.sum) — integrity-hash noise');
    if (skipMin) say('▸ Skipping minified / build artifacts (*.min.js, dist/, build/)');
  }
  function scanEnd(ok) {
    setBusy(false);
    if (onScanState) onScanState({ active: false });
    if (!ok) say('✕ Scan failed — see error above.');
  }

  async function filesToEntries(files) {
    const entries = [];
    for (const f of [...files].slice(0, MAX_FILES)) {
      const name = f.webkitRelativePath || f.name;
      if (/\.zip$/i.test(f.name)) {
        setMsg(`Unpacking ZIP ${f.name}…`);
        say(`… unpacking ZIP ${f.name}`);
        try {
          const zip = await JSZip.loadAsync(f);
          const zfiles = Object.values(zip.files).filter(z => !z.dir).slice(0, MAX_FILES);
          for (const z of zfiles) {
            try {
              const buf = await z.async('uint8array');
              entries.push({ path: z.name.slice(0, 220), bytes: buf.slice(0, MAX_FILE) });
            } catch { /* skip */ }
          }
          say(`… ${zfiles.length} file(s) inside archive`);
        } catch {
          throw new Error(`Cannot unpack ${f.name}: not a valid ZIP.`);
        }
      } else {
        const buf = new Uint8Array(await f.arrayBuffer());
        entries.push({ path: name.slice(0, 220), bytes: buf.slice(0, MAX_FILE) });
      }
    }
    return entries;
  }

  async function start(entries, sourceLabel) {
    if (!entries.length) { setErr('Nothing to scan — add at least one file / snippet / URL.'); return; }
    reset(); setBusy(true);
    if (onScanStart) onScanStart(); // jump straight to the live scan dashboard
    if (onScanState) onScanState({ active: true });
    try {
      const scan = await runScan(
        entries.slice(0, MAX_FILES),
        { source: sourceLabel, project: 'cryptora-scan', riskCtx: { sensitivity: 3, criticality: 3, exposure: 3 } },
        (m, p) => { setMsg(m); say('… ' + m); if (p != null) setPct(p); },
        { skipLockfiles: skipLock, skipMinified: skipMin }
      );
      say(`✓ Done — ${scan.stats.findings} findings in ${scan.stats.filesScanned} files (${(scan.durationMs / 1000).toFixed(1)}s), ${scan.stats.excluded} excluded`);
      say('✓ Layers: ' + scan.layers.map(l => `${l.layer.split(' ')[0]}=${l.count}`).join(' '));
      setMsg(`Done — ${scan.stats.findings} findings in ${scan.stats.filesScanned} files (${(scan.durationMs / 1000).toFixed(1)}s)`);
      setPct(1);
      if (onScanState) onScanState({ active: false });
      setTimeout(() => { onDone(scan); }, 450);
    } catch (e) {
      setErr(String(e && e.message || e));
      scanEnd(false);
    }
  }

  async function handlePickedFiles(files, label) {
    scanBegin(label);
    try {
      setMsg('Reading files…');
      say('… reading local files');
      const entries = await filesToEntries(files);
      setPicked(entries.map(e => e.path));
      say(`… ${entries.length} file(s) queued`);
      await start(entries, label);
    } catch (e) { setErr(String(e && e.message || e)); scanEnd(false); }
  }

  async function handleRepo() {
    const p = parseGithubUrl(repoUrl);
    if (!p) { setErr('Enter a public GitHub URL like https://github.com/owner/repo'); return; }
    scanBegin(`GitHub ${p.owner}/${p.repo}`);
    try {
      const prog = (m) => { setMsg(m); say('… ' + m); };
      const { branch: br, files } = await fetchRepoFileList(p.owner, p.repo, branch.trim() || '', prog);
      if (!files.length) throw new Error('No scannable code files found in this repo (or tree too large).');
      say(`… ${files.length} scannable file(s) selected (cap 40, <220 KB each)`);
      const entries = await fetchRepoFiles(p.owner, p.repo, br, files, prog);
      if (!entries.length) throw new Error('Fetched 0 file bodies (network/CORS blocked?). Try ZIP upload instead.');
      setMsg('Scanning fetched files…');
      await start(entries, `GitHub ${p.owner}/${p.repo}@${br}`);
    } catch (e) { setErr(String(e && e.message || e)); scanEnd(false); }
  }

  async function handlePaste() {
    if (!pasteCode.trim()) { setErr('Paste some code first.'); return; }
    scanBegin('Pasted code');
    const bytes = new TextEncoder().encode(pasteCode);
    start([{ path: (pasteName.trim() || 'snippet.txt'), bytes }], 'Pasted code');
  }

  async function handleLink() {
    if (!/^https?:\/\//i.test(linkUrl.trim())) { setErr('Enter a full https:// URL (raw file, gist, pastebin raw, etc.).'); return; }
    scanBegin('URL ' + linkUrl.trim());
    try {
      setMsg('Fetching URL…');
      say('… fetching remote file');
      const r = await fetch(linkUrl.trim());
      if (!r.ok) throw new Error(`Fetch failed (HTTP ${r.status}). The host may block CORS — use Paste Code instead.`);
      const buf = new Uint8Array(await r.arrayBuffer());
      const name = linkUrl.trim().split('/').pop().split('?')[0].slice(0, 120) || 'remote-file.txt';
      await start([{ path: 'url/' + name, bytes: buf.slice(0, MAX_FILE) }], 'URL ' + linkUrl.trim());
    } catch (e) { setErr(String(e && e.message || e)); scanEnd(false); }
  }

  async function handleCertPaste() {
    if (!certPaste.includes('BEGIN')) { setErr('Paste a PEM block (-----BEGIN …-----).'); return; }
    scanBegin('Certificate paste');
    start([{ path: 'certs/pasted.pem', bytes: new TextEncoder().encode(certPaste) }], 'Certificate paste');
  }
  async function handleDockerPaste() {
    if (!dockerPaste.trim() && !composePaste.trim()) { setErr('Paste a Dockerfile or compose file first.'); return; }
    scanBegin('Container paste');
    const entries = [];
    if (dockerPaste.trim()) entries.push({ path: 'Dockerfile', bytes: new TextEncoder().encode(dockerPaste) });
    if (composePaste.trim()) entries.push({ path: 'docker-compose.yml', bytes: new TextEncoder().encode(composePaste) });
    start(entries, 'Container paste');
  }

  return (
    <>
      <div className="scrim" onClick={() => !busy && onClose()} />
      <div className="drawer">
        <button className="x" onClick={() => !busy && onClose()}>✕</button>
        <h2>Upload &amp; Analyze</h2>
        <p className="sub">Scan real files, a public GitHub repo, a pasted snippet, certificates, Dockerfiles, containers, or binaries/documents — live, in your browser. <b style={{ color: '#c9d6ea' }}>Nothing leaves your machine</b> except direct GitHub/raw fetches you request.</p>

        <div className="tabs">
          {TABS.map(t => <button key={t.id} className={tab === t.id ? 'on' : ''} onClick={() => { setTab(t.id); reset(); }}>{t.label}</button>)}
        </div>

        <div className="scan-opts">
          <label><input type="checkbox" checked={skipLock} onChange={e => setSkipLock(e.target.checked)} /> Skip lockfiles <span className="dim">(recommended — kills integrity-hash noise)</span></label>
          <label><input type="checkbox" checked={skipMin} onChange={e => setSkipMin(e.target.checked)} /> Skip minified / build output</label>
        </div>

        {tab === 'files' && (
          <div className="field">
            <label>Files or .zip archive (up to {MAX_FILES} files)</label>
            <div
              className="drop" ref={dropRef}
              onClick={() => document.getElementById('f-input').click()}
              onDragOver={e => { e.preventDefault(); e.currentTarget.classList.add('over'); }}
              onDragLeave={e => e.currentTarget.classList.remove('over')}
              onDrop={e => { e.preventDefault(); e.currentTarget.classList.remove('over'); handlePickedFiles(e.dataTransfer.files, 'File upload'); }}
            >
              <input id="f-input" type="file" multiple onChange={e => handlePickedFiles(e.target.files, 'File upload')} />
              <div style={{ fontSize: 22 }}>⇪</div>
              <div>Drag &amp; drop files here, or click to browse</div>
              <div className="dim" style={{ marginTop: 6, fontSize: 10.5 }}>Code, manifests, .pem/.crt, Dockerfile, docs, binaries, .zip</div>
            </div>
          </div>
        )}

        {tab === 'folder' && (
          <div className="field">
            <label>Whole folder (Chrome / Edge — uses webkitdirectory)</label>
            <div className="drop" onClick={() => document.getElementById('d-input').click()}>
              <input id="d-input" type="file" multiple onChange={e => handlePickedFiles(e.target.files, 'Folder upload')}
                ref={el => { if (el) el.setAttribute('webkitdirectory', ''); }} />
              <div style={{ fontSize: 22 }}>▤</div>
              <div>Click to select a project folder</div>
              <div className="dim" style={{ marginTop: 6, fontSize: 10.5 }}>Relative paths preserved (src/auth/login.js …)</div>
            </div>
          </div>
        )}

        {tab === 'repo' && (
          <div className="field">
            <label>Public GitHub repository URL</label>
            <input type="text" placeholder="https://github.com/owner/repo" value={repoUrl} onChange={e => setRepoUrl(e.target.value)} />
            <label>Branch (optional — defaults to the repo's default branch)</label>
            <input type="text" placeholder="main" value={branch} onChange={e => setBranch(e.target.value)} />
            <p className="sub" style={{ marginTop: 10 }}>Fetched directly from GitHub's public REST API and raw.githubusercontent.com — nothing passes through a CRYPTORA server. Public repos only, up to 40 files, subject to GitHub's unauthenticated rate limit (60 requests/hour/IP).</p>
            <button className="btn primary" disabled={busy} onClick={handleRepo} style={{ width: '100%', justifyContent: 'center', marginTop: 6 }}>▶ Start Analysis</button>
          </div>
        )}

        {tab === 'paste' && (
          <div className="field">
            <label>Filename (sets language detection, e.g. auth.py / login.js / config.yaml)</label>
            <input type="text" value={pasteName} onChange={e => setPasteName(e.target.value)} />
            <label>Paste code</label>
            <textarea placeholder={'import hashlib\nhashlib.md5(password.encode()).hexdigest()'} value={pasteCode} onChange={e => setPasteCode(e.target.value)} />
            <button className="btn primary" disabled={busy} onClick={handlePaste} style={{ width: '100%', justifyContent: 'center', marginTop: 12 }}>▶ Scan Pasted Code</button>
          </div>
        )}

        {tab === 'link' && (
          <div className="field">
            <label>Direct file URL (raw gist, raw github, pastebin raw, public snippet…)</label>
            <input type="text" placeholder="https://gist.githubusercontent.com/…/raw/…/file.js" value={linkUrl} onChange={e => setLinkUrl(e.target.value)} />
            <p className="sub" style={{ marginTop: 10 }}>Fetched with a plain browser request. If the host blocks cross-origin reads, you'll get a CORS error — then just use <b style={{ color: '#c9d6ea' }}>Paste Code</b> instead.</p>
            <button className="btn primary" disabled={busy} onClick={handleLink} style={{ width: '100%', justifyContent: 'center', marginTop: 6 }}>▶ Fetch &amp; Scan</button>
          </div>
        )}

        {tab === 'certs' && (
          <div className="field">
            <label>Certificate files (.pem / .crt / .cer / .key)</label>
            <div className="drop" onClick={() => document.getElementById('c-input').click()}>
              <input id="c-input" type="file" multiple accept=".pem,.crt,.cer,.key,.pub" onChange={e => handlePickedFiles(e.target.files, 'Certificate upload')} />
              <div>Click to browse certificate files</div>
            </div>
            <label>…or paste PEM</label>
            <textarea placeholder="-----BEGIN CERTIFICATE-----&#10;…&#10;-----END CERTIFICATE-----" value={certPaste} onChange={e => setCertPaste(e.target.value)} style={{ minHeight: 100 }} />
            <button className="btn primary" disabled={busy} onClick={handleCertPaste} style={{ width: '100%', justifyContent: 'center', marginTop: 12 }}>▶ Scan Certificate</button>
          </div>
        )}

        {tab === 'dockerfile' && (
          <div className="field">
            <label>Dockerfile upload</label>
            <div className="drop" onClick={() => document.getElementById('k-input').click()}>
              <input id="k-input" type="file" multiple onChange={e => handlePickedFiles(e.target.files, 'Dockerfile upload')} />
              <div>Click to browse (Dockerfile, *.dockerfile)</div>
            </div>
            <label>…or paste Dockerfile</label>
            <textarea placeholder={'FROM node:18&#10;RUN apt-get update && apt-get install -y openssl&#10;COPY server.key /app/'} value={dockerPaste} onChange={e => setDockerPaste(e.target.value)} style={{ minHeight: 110 }} />
            <button className="btn primary" disabled={busy} onClick={handleDockerPaste} style={{ width: '100%', justifyContent: 'center', marginTop: 12 }}>▶ Scan Dockerfile</button>
          </div>
        )}

        {tab === 'containers' && (
          <div className="field">
            <label>Container files (Dockerfile, compose, .env)</label>
            <div className="drop" onClick={() => document.getElementById('n-input').click()}>
              <input id="n-input" type="file" multiple onChange={e => handlePickedFiles(e.target.files, 'Container upload')} />
              <div>Click to browse container files</div>
            </div>
            <label>…or paste docker-compose.yml</label>
            <textarea placeholder={'services:&#10;  api:&#10;    image: myapp:latest&#10;    environment:&#10;      - API_KEY=hardcoded-secret'} value={composePaste} onChange={e => setComposePaste(e.target.value)} style={{ minHeight: 100 }} />
            <button className="btn primary" disabled={busy} onClick={handleDockerPaste} style={{ width: '100%', justifyContent: 'center', marginTop: 12 }}>▶ Scan Container Config</button>
          </div>
        )}

        {tab === 'binaries' && (
          <div className="field">
            <label>Binaries / documents (.exe, .so, .pdf, .docx, .jar …)</label>
            <div className="drop" onClick={() => document.getElementById('b-input').click()}>
              <input id="b-input" type="file" multiple onChange={e => handlePickedFiles(e.target.files, 'Binary/doc upload')} />
              <div style={{ fontSize: 22 }}>⬢</div>
              <div>Click to browse binaries or documents</div>
              <div className="dim" style={{ marginTop: 6, fontSize: 10.5 }}>Static inspection only: format, SHA-256, extracted-string signature matching — never executes anything</div>
            </div>
          </div>
        )}

        {(busy || msg) && (
          <div className="progress">
            <div className="msg">{busy ? '◉ ' : '✓ '}{msg || 'Working…'}</div>
            <div className="bar"><i style={{ width: Math.round(pct * 100) + '%' }} /></div>
            {busy && onScanStart ? <button className="btn sm ghost mt" onClick={onScanStart} style={{ width: '100%', justifyContent: 'center' }}>Watch live on Discovery →</button> : null}
          </div>
        )}
        {log.length > 0 && (
          <div className="mt">
            <div className="mono dim" style={{ fontSize: 10, letterSpacing: 1.5, marginBottom: 6 }}>LIVE SCAN LOG</div>
            <LogTerminal lines={log} height={170} />
          </div>
        )}
        {picked.length > 0 && tab !== 'repo' && (
          <p className="sub" style={{ marginTop: 10 }}>Queued: {picked.slice(0, 6).join(', ')}{picked.length > 6 ? ` … +${picked.length - 6} more` : ''}</p>
        )}
        {err && <div className="err">⚠ {err}</div>}

        <div style={{ marginTop: 18 }}>
          <div style={{ fontSize: 13, fontWeight: 700, marginBottom: 8 }}>What this scan actually does</div>
          <div className="checkline">☑ <span><b>L1+L2:</b> regex for ~35 crypto algorithms &amp; protocols, plus real <b>AST-lite parsing</b> for JavaScript &amp; Python</span></div>
          <div className="checkline">☑ <span><b>L3:</b> hardcoded key / secret / PEM-block detection (values redacted)</span></div>
          <div className="checkline">☑ <span><b>L4:</b> Shannon entropy scan — token-level + whole-file bytes</span></div>
          <div className="checkline">☑ <span><b>L5–L8:</b> manifest parsing, Dockerfile analysis, real <b>ASN.1 certificate parsing</b>, binary/document static inspection — never executes anything</span></div>
        </div>
      </div>
    </>
  );
}
