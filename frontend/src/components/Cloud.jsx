import React, { useEffect, useState } from 'react';
import { DataAPI } from '../lib/api.js';

/* Signed-in persistence: save current scan to backend project + reload saved scans. */
export default function CloudPanel({ scan, user, onLoadScan }) {
  const [projects, setProjects] = useState([]);
  const [pid, setPid] = useState('');
  const [name, setName] = useState('');
  const [scans, setScans] = useState([]);
  const [msg, setMsg] = useState('');
  const [err, setErr] = useState('');
  const [busy, setBusy] = useState(false);

  async function refresh(pidOverride) {
    try {
      const ps = await DataAPI.projects();
      setProjects(ps);
      const id = pidOverride || pid || (ps[0] && ps[0].id);
      if (id) { setPid(id); setScans(await DataAPI.listScans(id)); }
    } catch (e) { setErr(e.message); }
  }
  useEffect(() => { if (user) refresh(); }, [user]);

  async function create(e) {
    e.preventDefault(); setErr(''); setMsg(''); setBusy(true);
    try {
      const p = await DataAPI.createProject(name.trim() || 'My project');
      setName(''); setMsg(`Project “${p.name}” created.`);
      await refresh(p.id);
    } catch (ex) { setErr(ex.message); } finally { setBusy(false); }
  }
  async function save() {
    setErr(''); setMsg(''); setBusy(true);
    try {
      let id = pid;
      if (!id) { const p = await DataAPI.createProject('My project'); id = p.id; await refresh(id); }
      const r = await DataAPI.saveScan(id, scan);
      setMsg(`✓ Scan saved to account (server id ${r.id}, ${r.findings} findings).`);
      setScans(await DataAPI.listScans(id));
    } catch (ex) { setErr(ex.message); } finally { setBusy(false); }
  }
  async function load(sid) {
    setErr(''); setBusy(true);
    try {
      const full = await DataAPI.getScan(sid);
      const f = full.payload?.findings || [];
      // rebuild minimal live-scan shape from stored payload
      const st = full.payload?.stats || {};
      onLoadScan({
        id: `cloud-${sid}`, source: full.source + ' (from account)', project: 'cryptora-scan',
        startedAt: full.created_at, completedAt: full.created_at, durationMs: 0,
        files: [], binaries: [], deps: [], certs: [], docker: [],
        findings: f.map((x, i) => ({ id: `F-${String(i + 1).padStart(4, '0')}`, ...x, riskBand: x.riskBand || bandOf(x.riskScore), reason: x.reason || ['Restored from account archive'] })),
        cbom: { bomFormat: 'CycloneDX', specVersion: '1.5', components: [] },
        stats: { filesScanned: full.files_scanned, findings: f.length, critical: st.critical || 0, high: st.high || 0, medium: st.medium || 0, low: st.low || 0, info: st.info || 0, quantum: st.quantum || 0, secrets: st.secrets || 0, hidden: st.hidden || 0, certs: st.certs || 0, deps: st.deps || 0 },
      });
      setMsg('Scan restored from account.');
    } catch (ex) { setErr(ex.message); } finally { setBusy(false); }
  }
  async function del(sid) {
    if (!confirm('Delete this saved scan from your account?')) return;
    try { await DataAPI.deleteScan(sid); setScans(await DataAPI.listScans(pid)); }
    catch (ex) { setErr(ex.message); }
  }

  if (!user) return null;
  return (
    <div className="card" style={{ borderColor: '#164e63', marginBottom: 14 }}>
      <div className="sec-title" style={{ marginTop: 0 }}>☁ Account sync <span className="n">signed in as {user.email || user.phone || user.name || 'user'} · stored in your backend/MySQL</span></div>
      <div className="toolbar">
        <select value={pid} onChange={async e => { setPid(e.target.value); setScans(await DataAPI.listScans(e.target.value)); }}>
          {projects.map(p => <option key={p.id} value={p.id}>{p.name} ({p.scans})</option>)}
        </select>
        <button className="btn sm primary" disabled={busy || !scan} onClick={save}>⇪ Save current scan</button>
        <form onSubmit={create} style={{ display: 'flex', gap: 6 }}>
          <input type="text" placeholder="New project name…" value={name} onChange={e => setName(e.target.value)} />
          <button className="btn sm" disabled={busy}>＋</button>
        </form>
      </div>
      {scans.length > 0 ? (
        <div className="tbl-wrap"><table className="tbl">
          <thead><tr><th>ID</th><th>Source</th><th>Findings</th><th>C/H/Q</th><th>Saved</th><th></th></tr></thead>
          <tbody>{scans.map(s => (
            <tr key={s.id}><td className="mono">{s.id}</td><td className="mono" style={{ fontSize: 11 }}>{s.source}</td>
              <td className="mono">{s.findings}</td><td className="mono">{s.critical}/{s.high}/{s.quantum}</td>
              <td className="mono" style={{ fontSize: 11 }}>{s.created_at ? new Date(s.created_at).toLocaleString() : ''}</td>
              <td><button className="btn sm" onClick={() => load(s.id)}>Restore</button> <button className="btn sm ghost" onClick={() => del(s.id)}>Delete</button></td></tr>
          ))}</tbody>
        </table></div>
      ) : <div className="mono muted" style={{ fontSize: 12 }}>No saved scans in this project yet — save the current scan to keep it in your account.</div>}
      {msg ? <div className="progress"><div className="msg">{msg}</div></div> : null}
      {err ? <div className="err">⚠ {err}</div> : null}
    </div>
  );
}
function bandOf(s = 0) { return s >= 85 ? 'Critical' : s >= 65 ? 'High' : s >= 40 ? 'Medium' : s >= 15 ? 'Low' : 'Info'; }
