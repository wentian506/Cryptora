import React, { useEffect, useState } from 'react';
import { AuthAPI, getApiBase, setApiBase, setSession } from '../lib/api.js';

/* Google Identity Services loader (only used when backend has GOOGLE_CLIENT_ID) */
function loadGIS() {
  return new Promise((resolve) => {
    if (window.google?.accounts?.id) return resolve(true);
    const s = document.createElement('script');
    s.src = 'https://accounts.google.com/gsi/client';
    s.onload = () => resolve(!!window.google?.accounts?.id);
    s.onerror = () => resolve(false);
    document.head.appendChild(s);
  });
}

export default function Auth({ onAuth, onBack, onDemo }) {
  const [tab, setTab] = useState('email');
  const [mode, setMode] = useState('signin'); // signin|signup
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [phone, setPhone] = useState('');
  const [code, setCode] = useState('');
  const [otpStep, setOtpStep] = useState('request'); // request|verify
  const [devCode, setDevCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState('');
  const [cfg, setCfg] = useState(null);
  const [apiBase, setApi] = useState(getApiBase());

  useEffect(() => {
    AuthAPI.config().then(setCfg).catch(() => setCfg({ unreachable: true }));
  }, []);
  useEffect(() => { setApiBase(apiBase); }, [apiBase]);

  function done(d) {
    setSession(d.token, d.user);
    onAuth(d.user, d.token);
  }
  async function emailSubmit(e) {
    e.preventDefault(); setErr(''); setBusy(true);
    try {
      const d = mode === 'signup'
        ? await AuthAPI.signup(email.trim(), password, name.trim())
        : await AuthAPI.login(email.trim(), password);
      done(d);
    } catch (ex) { setErr(ex.message); } finally { setBusy(false); }
  }
  async function googleGo() {
    setErr(''); setBusy(true);
    try {
      if (!cfg?.google_configured) throw new Error('Google sign-in is not configured on this server. Set GOOGLE_CLIENT_ID (see deploy/.env.example).');
      const ok = await loadGIS();
      if (!ok) throw new Error('Could not load Google Identity Services (network blocked?).');
      window.google.accounts.id.initialize({
        client_id: cfg.google_client_id, callback: async (resp) => {
          try { done(await AuthAPI.google(resp.credential)); }
          catch (ex) { setErr(ex.message); setBusy(false); }
        },
      });
      window.google.accounts.id.prompt((n) => {
        if (n.isNotDisplayed() || n.isSkippedMoment()) {
          // fallback: render button
          const el = document.getElementById('gis-btn');
          if (el) { el.innerHTML = ''; window.google.accounts.id.renderButton(el, { theme: 'filled_black', size: 'large', width: 320 }); }
          setBusy(false);
        }
      });
    } catch (ex) { setErr(ex.message); setBusy(false); }
  }
  async function otpSend(e) {
    e?.preventDefault(); setErr(''); setBusy(true); setDevCode('');
    try {
      const r = await AuthAPI.otpRequest(phone.trim());
      if (r.dev_code) setDevCode(r.dev_code);
      setOtpStep('verify');
    } catch (ex) { setErr(ex.message); } finally { setBusy(false); }
  }
  async function otpGo(e) {
    e.preventDefault(); setErr(''); setBusy(true);
    try { done(await AuthAPI.otpVerify(phone.trim(), code.trim())); }
    catch (ex) { setErr(ex.message); } finally { setBusy(false); }
  }

  return (
    <div className="auth-wrap">
      <div className="auth-card">
        <button className="btn sm ghost" onClick={onBack}>← Back</button>
        <div className="brand" style={{ padding: '14px 0 4px' }}>
          <div className="brand-mark">◉</div>
          <div><b>CRYPTORA</b><small>ACCOUNT ACCESS</small></div>
        </div>
        {cfg?.unreachable ? (
          <div className="err">⚠ Backend unreachable at <b>{apiBase}</b>. Start it (<span className="mono">uvicorn app.main:app</span> in <span className="mono">backend/</span>) or continue with a local demo session — scanning works fully offline.</div>
        ) : null}
        <div className="tabs" style={{ marginTop: 12 }}>
          {['email', 'google', 'phone'].map(t => (
            <button key={t} className={tab === t ? 'on' : ''} onClick={() => { setTab(t); setErr(''); }}>{t === 'email' ? 'Email' : t === 'google' ? 'Google' : 'Phone OTP'}</button>
          ))}
        </div>

        {tab === 'email' && (
          <form onSubmit={emailSubmit} className="field">
            <div className="tabs" style={{ marginBottom: 4 }}>
              <button type="button" className={mode === 'signin' ? 'on' : ''} onClick={() => setMode('signin')}>Sign in</button>
              <button type="button" className={mode === 'signup' ? 'on' : ''} onClick={() => setMode('signup')}>Create account</button>
            </div>
            {mode === 'signup' && (<><label>Display name</label><input type="text" value={name} onChange={e => setName(e.target.value)} placeholder="Ada Analyst" /></>)}
            <label>Email</label>
            <input type="text" value={email} onChange={e => setEmail(e.target.value)} placeholder="you@company.com" autoComplete="email" />
            <label>Password {mode === 'signup' ? '(min 8 chars, PBKDF2-hashed server-side)' : ''}</label>
            <input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="••••••••" autoComplete={mode === 'signup' ? 'new-password' : 'current-password'} style={{ width: '100%', background: '#0a0f18', border: '1px solid #2a3550', color: '#fff', borderRadius: 8, padding: '10px 12px', fontFamily: 'monospace', fontSize: 12 }} />
            <button className="btn primary" disabled={busy} style={{ width: '100%', justifyContent: 'center', marginTop: 14 }}>{busy ? '…' : mode === 'signup' ? 'Create account' : 'Sign in'}</button>
          </form>
        )}

        {tab === 'google' && (
          <div className="field">
            <p className="sub">Server-verified Google ID tokens (tokeninfo + audience check). Never stores Google passwords.</p>
            <button className="btn primary" disabled={busy} onClick={googleGo} style={{ width: '100%', justifyContent: 'center' }}>{busy ? '…' : '◍ Continue with Google'}</button>
            <div id="gis-btn" style={{ marginTop: 12, display: 'flex', justifyContent: 'center' }} />
            {!cfg?.google_configured && !cfg?.unreachable ? <div className="err">⚠ Not configured — set GOOGLE_CLIENT_ID on the backend (deploy/.env.example).</div> : null}
          </div>
        )}

        {tab === 'phone' && (
          <div className="field">
            {otpStep === 'request' ? (
              <form onSubmit={otpSend}>
                <label>Phone number (E.164, e.g. +919876543210)</label>
                <input type="text" value={phone} onChange={e => setPhone(e.target.value)} placeholder="+91…" />
                <button className="btn primary" disabled={busy} style={{ width: '100%', justifyContent: 'center', marginTop: 14 }}>{busy ? '…' : 'Send code'}</button>
              </form>
            ) : (
              <form onSubmit={otpGo}>
                <label>6-digit code sent to {phone} <button type="button" className="rowbtn" style={{ background: 'none', border: 0, color: '#22d3ee', cursor: 'pointer', fontFamily: 'monospace' }} onClick={() => setOtpStep('request')}>(change)</button></label>
                <input type="text" value={code} onChange={e => setCode(e.target.value)} placeholder="123456" inputMode="numeric" />
                {devCode ? <div className="progress"><div className="msg">DEV_MODE: your test code is {devCode} (no SMS provider configured)</div></div> : null}
                <button className="btn primary" disabled={busy} style={{ width: '100%', justifyContent: 'center', marginTop: 14 }}>{busy ? '…' : 'Verify & sign in'}</button>
              </form>
            )}
            <p className="sub" style={{ marginTop: 10 }}>Codes are hashed + expire in 10 min, max 5 requests/hour. Raw codes are never stored or logged.</p>
          </div>
        )}

        {err ? <div className="err">⚠ {err}</div> : null}

        <div className="field">
          <label>Backend URL (API base)</label>
          <input type="text" value={apiBase} onChange={e => setApi(e.target.value)} />
        </div>
        <div style={{ borderTop: '1px solid #1e2636', marginTop: 16, paddingTop: 14, textAlign: 'center' }}>
          <button className="btn ghost sm" onClick={onDemo}>Continue without account (local demo session)</button>
        </div>
      </div>
    </div>
  );
}
