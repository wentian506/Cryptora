/* CRYPTORA backend client. Base URL auto-detected per environment,
   overridable on the Sign-in page (stored in localStorage). */

export function getApiBase() {
  try {
    const saved = localStorage.getItem('cryptora-api-base');
    if (saved) return saved;
  } catch { /* ignore */ }
  try {
    const { hostname, port, protocol, origin } = window.location;
    const m = hostname.match(/^5173-(.+)$/);
    if (m) return `${protocol}//8000-${m[1]}`; // sandbox preview: derive API preview URL
    if ((hostname === 'localhost' || hostname === '127.0.0.1') && port === '5173') return 'http://localhost:8000';
    if (port === '' || port === '80' || port === '443' || port === '8080') return origin; // prod: nginx proxies /api same-origin
    return 'http://localhost:8000';
  } catch { return 'http://localhost:8000'; }
}
export function setApiBase(v) {
  try { localStorage.setItem('cryptora-api-base', v); } catch { /* ignore */ }
}
function token() {
  try { return localStorage.getItem('cryptora-token') || ''; } catch { return ''; }
}
export function setSession(tok, user) {
  try {
    if (tok) localStorage.setItem('cryptora-token', tok); else localStorage.removeItem('cryptora-token');
    if (user) localStorage.setItem('cryptora-user', JSON.stringify(user)); else localStorage.removeItem('cryptora-user');
  } catch { /* ignore */ }
}
export function getSessionUser() {
  try { return JSON.parse(localStorage.getItem('cryptora-user') || 'null'); } catch { return null; }
}
export function clearSession() { setSession('', null); }

export async function api(path, opts = {}) {
  const base = getApiBase().replace(/\/$/, '');
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  const t = token();
  if (t) headers.Authorization = 'Bearer ' + t;
  let r;
  try {
    r = await fetch(base + path, { ...opts, headers });
  } catch {
    throw new Error(`Backend unreachable at ${base} — is the API running? (local demo works without it)`);
  }
  let body = null;
  try { body = await r.json(); } catch { /* ignore */ }
  if (!r.ok) throw new Error((body && body.detail) || `Request failed (HTTP ${r.status})`);
  return body;
}

export const AuthAPI = {
  config: () => api('/api/config'),
  signup: (email, password, name) => api('/api/auth/signup', { method: 'POST', body: JSON.stringify({ email, password, name }) }),
  login: (email, password) => api('/api/auth/login', { method: 'POST', body: JSON.stringify({ email, password }) }),
  google: (id_token) => api('/api/auth/google', { method: 'POST', body: JSON.stringify({ id_token }) }),
  otpRequest: (phone) => api('/api/auth/otp/request', { method: 'POST', body: JSON.stringify({ phone }) }),
  otpVerify: (phone, code) => api('/api/auth/otp/verify', { method: 'POST', body: JSON.stringify({ phone, code }) }),
  me: () => api('/api/me'),
};
export const DataAPI = {
  projects: () => api('/api/projects'),
  createProject: (name) => api('/api/projects', { method: 'POST', body: JSON.stringify({ name }) }),
  deleteProject: (id) => api(`/api/projects/${id}`, { method: 'DELETE' }),
  saveScan: (pid, scan) => api(`/api/projects/${pid}/scans`, {
    method: 'POST',
    body: JSON.stringify({
      client_id: scan.id, source: scan.source, files_scanned: scan.stats.filesScanned,
      findings: (scan.findings || []).map(f => ({
        algorithm: f.algorithm, algoLabel: f.algoLabel, file: f.file, line: f.line,
        severity: f.severity, quantum: f.quantum, riskScore: f.riskScore, evidence: f.evidence,
      })),
      stats: scan.stats, cbom_components: (scan.cbom?.components || []).length,
    }),
  }),
  listScans: (pid) => api(`/api/projects/${pid}/scans`),
  getScan: (sid) => api(`/api/scans/${sid}`),
  deleteScan: (sid) => api(`/api/scans/${sid}`, { method: 'DELETE' }),
  audit: () => api('/api/audit-logs'),
};
