import React, { useEffect, useId, useRef } from 'react';

export function Sev({ level }) {
  const l = String(level || 'info').toLowerCase();
  return <span className={`sev ${l}`}>{l}</span>;
}
export function QTag({ quantum }) {
  if (!quantum) return null;
  return <span className="tag q">⚛ quantum-vulnerable</span>;
}
export function Empty({ title = 'No scan yet', children, action }) {
  return (
    <div className="empty">
      <h3>{title}</h3>
      <p>{children || <>Upload real files, a public GitHub repo, or paste code via Upload / Analyze.<br />Every stat, chart, and finding on this page is computed from that scan — nothing here is sample data.</>}</p>
      {action}
    </div>
  );
}
export function Stat({ k, v, s, color }) {
  return (
    <div className="stat">
      <div className="k">{k}</div>
      <div className="v" style={color ? { color } : undefined}>{v}</div>
      {s ? <div className="s">{s}</div> : null}
    </div>
  );
}
export function FlowStrip() {
  const steps = ['Discover', 'Evidence + CBOM', 'Dependency Graph', 'Quantum + Business Risk', 'Impact', 'Hybrid Migration', 'Validate + Rollback', 'Hidden Encryption'];
  return (
    <div className="flow">
      {steps.map((s, i) => (
        <React.Fragment key={s}>
          <span className="step">{s}</span>
          {i < steps.length - 1 ? <span className="arr">→</span> : null}
        </React.Fragment>
      ))}
    </div>
  );
}
export function Donut({ parts, size = 150 }) {
  const total = parts.reduce((a, p) => a + p.value, 0) || 1;
  let acc = 0;
  const R = 54, C = 2 * Math.PI * R;
  const segs = parts.map(p => {
    const frac = p.value / total;
    const s = { ...p, dash: frac * C, off: acc * C };
    acc += frac;
    return s;
  });
  return (
    <div className="donut-wrap">
      <svg width={size} height={size} viewBox="0 0 130 130">
        <circle cx="65" cy="65" r={R} fill="none" stroke="#1a2334" strokeWidth="16" />
        {segs.map((s, i) => (
          s.value > 0 ? <circle key={i} cx="65" cy="65" r={R} fill="none" stroke={s.color} strokeWidth="16"
            strokeDasharray={`${s.dash} ${C - s.dash}`} strokeDashoffset={-s.off + C * 0.25} strokeLinecap="butt" /> : null
        ))}
        <text x="65" y="62" textAnchor="middle" fill="#f2f5fa" fontSize="22" fontWeight="700" fontFamily="monospace">{total}</text>
        <text x="65" y="80" textAnchor="middle" fill="#64748f" fontSize="9" fontFamily="monospace">FINDINGS</text>
      </svg>
      <div className="legend">
        {parts.map((p, i) => (
          <div key={i}><i style={{ background: p.color }} />{p.label}: <b style={{ color: '#f2f5fa' }}>{p.value}</b></div>
        ))}
      </div>
    </div>
  );
}
export function HBar({ value, max = 100, color = '#7c3aed' }) {
  return <div className="hbar"><i style={{ width: Math.min(100, (value / max) * 100) + '%', background: color }} /></div>;
}
/* semicircular gauge (prototype-style exposure / agility dials) */
export function Gauge({ value = 0, max = 100, band = '', color = '#f97316', size = 200 }) {
  const frac = Math.max(0, Math.min(1, value / max));
  const cx = 100, cy = 96, r = 74;
  const th = Math.PI * (1 - frac);
  const ex = cx + r * Math.cos(th), ey = cy - r * Math.sin(th);
  return (
    <div style={{ textAlign: 'center' }}>
      <svg width={size} height={size * 0.62} viewBox="0 0 200 124" style={{ maxWidth: '100%', height: 'auto' }}>
        <path d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`} fill="none" stroke="#1a2334" strokeWidth="15" strokeLinecap="round" />
        {frac > 0.005 ? <path d={`M ${cx - r} ${cy} A ${r} ${r} 0 ${frac > 0.5 ? 1 : 0} 1 ${ex.toFixed(1)} ${ey.toFixed(1)}`} fill="none" stroke={color} strokeWidth="15" strokeLinecap="round" /> : null}
        <text x={cx} y={cy - 6} textAnchor="middle" fill={color} fontSize="30" fontWeight="800" fontFamily="monospace">{value}</text>
        <text x={cx + 34} y={cy - 6} textAnchor="start" fill="#64748f" fontSize="12" fontFamily="monospace">/{max}</text>
      </svg>
      {band ? <div><span className="tag" style={{ color, borderColor: color }}>{band}</span></div> : null}
    </div>
  );
}
/* live terminal log (auto-scrolls) */
export function LogTerminal({ lines = [], height = 220 }) {
  const ref = useRef(null);
  useEffect(() => {
    const el = ref.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [lines.length]);
  return (
    <div className="terminal" ref={ref} style={{ maxHeight: height }}>
      {lines.length === 0 ? <div className="dim">— idle —</div> : lines.map((l, i) => <div key={i}>{l}</div>)}
    </div>
  );
}
export function download(name, text, mime = 'application/json') {
  const blob = new Blob([text], { type: mime });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
}
export function downloadBlob(name, blob) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
}

/* Multi-series SVG area/line chart. series=[{name,color,values:[n..]}]. Pure SVG, responsive. */
export function AreaChart({ series = [], height = 230, xLabels = [], yLabel = '', area = true }) {
  const uid = useId().replace(/[^a-zA-Z0-9]/g, '');
  const W = 620, H = 250, PL = 44, PR = 14, PT = 14, PB = 30;
  const all = series.flatMap(s => s.values);
  const max = Math.max(1, ...all);
  const n = Math.max(1, ...series.map(s => s.values.length));
  const X = (i) => PL + (n === 1 ? (W - PL - PR) / 2 : (i * (W - PL - PR)) / (n - 1));
  const Y = (v) => PT + (H - PT - PB) * (1 - v / (max * 1.12));
  const line = (vals) => vals.map((v, i) => `${i === 0 ? 'M' : 'L'}${X(i).toFixed(1)},${Y(v).toFixed(1)}`).join(' ');
  const ticks = [0, 0.25, 0.5, 0.75, 1].map(f => Math.round(max * 1.12 * f));
  const labEvery = Math.max(1, Math.ceil(n / 7));
  return (
    <div className="area-wrap">
      <svg viewBox={`0 0 ${W} ${H}`} style={{ width: '100%', height, display: 'block' }}>
        <defs>
          {series.map((s, si) => (
            <linearGradient key={si} id={`ag${uid}${si}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={s.color} stopOpacity="0.45" />
              <stop offset="100%" stopColor={s.color} stopOpacity="0.02" />
            </linearGradient>
          ))}
        </defs>
        {ticks.map((tk, i) => (
          <g key={i}>
            <line x1={PL} y1={Y(tk)} x2={W - PR} y2={Y(tk)} stroke="#1a2334" strokeWidth="1" />
            <text x={PL - 7} y={Y(tk) + 4} textAnchor="end" fill="#64748f" fontSize="10" fontFamily="monospace">{tk}</text>
          </g>
        ))}
        {yLabel ? <text x="10" y={PT + 4} fill="#64748f" fontSize="10" fontFamily="monospace">{yLabel}</text> : null}
        {series.map((s, si) => (
          <g key={si}>
            {area && s.values.length > 1 ? <path d={`${line(s.values)} L${X(s.values.length - 1).toFixed(1)},${Y(0).toFixed(1)} L${X(0).toFixed(1)},${Y(0).toFixed(1)} Z`} fill={`url(#ag${uid}${si})`} /> : null}
            {s.values.length > 1 ? <path d={line(s.values)} fill="none" stroke={s.color} strokeWidth="2.2" strokeLinejoin="round" /> : null}
            {s.values.map((v, i) => <circle key={i} cx={X(i)} cy={Y(v)} r="2.6" fill={s.color} />)}
          </g>
        ))}
        {xLabels.map((lb, i) => (
          i % labEvery === 0 || i === n - 1 ? <text key={i} x={X(i)} y={H - 8} textAnchor="middle" fill="#64748f" fontSize="9.5" fontFamily="monospace">{String(lb).slice(0, 14)}</text> : null
        ))}
      </svg>
      {series.length > 1 || (series[0] && series[0].name) ? (
        <div className="chart-legend">
          {series.map((s, i) => <span key={i}><i style={{ background: s.color }} />{s.name}</span>)}
        </div>
      ) : null}
    </div>
  );
}
/* labeled horizontal bars, 0..max scale (mockup "Real Aggregate Factors" style) */
export function FactorBars({ items = [], suffix = '' }) {
  const max = Math.max(1, ...items.map(x => x.value));
  return (
    <div className="factor-list">
      {items.map((x, i) => (
        <div key={i} className="factor-row">
          <div className="factor-top"><span>{x.label}</span><b style={x.color ? { color: x.color } : undefined}>{x.display != null ? x.display : x.value}{suffix}</b></div>
          <HBar value={x.value} max={max} color={x.color || '#7c3aed'} />
        </div>
      ))}
    </div>
  );
}
/* diverging +/- bar for explainability factors (center-zero) */
export function DivBar({ label, delta, maxAbs, posGood }) {
  const m = Math.max(1, maxAbs);
  const w = Math.min(50, (Math.abs(delta) / m) * 50);
  const pos = delta >= 0;
  const good = delta === 0 ? null : (posGood ? pos : !pos);
  const barCls = (side) => {
    const active = side === 'right' ? pos : !pos;
    if (!active || delta === 0) return '';
    const goodBar = posGood ? side === 'right' : side === 'left';
    return goodBar ? 'neg' : 'pos';
  };
  return (
    <div className="factor-row">
      <div className="factor-top"><span>{label}</span><b style={{ color: good === null ? '#f2f5fa' : good ? '#86efac' : '#ff9a9a' }}>{delta > 0 ? '+' : ''}{delta}</b></div>
      <div className="divtrack">
        <div className="divhalf left"><i className={barCls('left')} style={{ width: !pos && delta !== 0 ? w + '%' : 0 }} /></div>
        <div className="divmid" />
        <div className="divhalf right"><i className={barCls('right')} style={{ width: pos && delta !== 0 ? w + '%' : 0 }} /></div>
      </div>
    </div>
  );
}
/* segmented tab bar (mockup "ML-KEM | ML-DSA | SLH-DSA" style) */
export function SegTabs({ options = [], value, onChange }) {
  return (
    <div className="seg" role="tablist">
      {options.map(o => {
        const id = typeof o === 'string' ? o : o.id;
        const label = typeof o === 'string' ? o : o.label;
        return <button key={id} role="tab" className={value === id ? 'on' : ''} onClick={() => onChange(id)}>{label}</button>;
      })}
    </div>
  );
}
/* small gauge inside a card (mockup gauge-row style) */
export function MiniGauge({ value = 0, max = 100, label = '', sub = '', color = '#22d3ee' }) {
  return (
    <div className="card gauge-card">
      <div className="mono dim gk">{label}</div>
      <Gauge value={value} max={max} color={color} size={148} />
      {sub ? <div className="mono dim gk-sub">{sub}</div> : null}
    </div>
  );
}
