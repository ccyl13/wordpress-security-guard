import type { SecurityHeader } from '@/types/wordpress-audit';
import { ShieldCheck, ShieldAlert, AlertTriangle, Shield } from 'lucide-react';

const ST = {
  secure:     { Icon: ShieldCheck,  color: '#34d399', dot: 'dot-green',  label: 'OK'   },
  warning:    { Icon: AlertTriangle,color: '#fbbf24', dot: 'dot-yellow', label: 'Warn' },
  vulnerable: { Icon: ShieldAlert,  color: '#f87171', dot: 'dot-red',    label: 'Fail' },
  info:       { Icon: Shield,       color: '#60a5fa', dot: 'dot-blue',   label: 'Info' },
};

export function SecurityHeadersCard({ headers }: { headers: SecurityHeader[] }) {
  const counts = { ok: headers.filter(h=>h.status==='secure').length, warn: headers.filter(h=>h.status==='warning').length, fail: headers.filter(h=>h.status==='vulnerable').length };
  return (
    <div className="result-card">
      <div className="card-header">
        <span className="card-title"><Shield size={14} style={{ color:'#a78bfa' }}/> Cabeceras HTTP</span>
        <div style={{ display:'flex', gap:'10px' }}>
          {[['#34d399',counts.ok,'ok'],['#fbbf24',counts.warn,'warn'],['#f87171',counts.fail,'fail']].map(([c,n,l])=>(
            <span key={String(l)} className="mono" style={{ fontSize:'10px', color:String(c) }}>{n} {l}</span>
          ))}
        </div>
      </div>
      <div style={{ padding:'4px 0' }}>
        {headers.map(h => {
          const s = ST[h.status] || ST.info;
          return (
            <div key={h.name} style={{ display:'flex', alignItems:'center', gap:'10px', padding:'9px 20px', borderBottom:'1px solid rgba(255,255,255,0.03)', transition:'background .15s' }}
              onMouseEnter={e=>(e.currentTarget.style.background='rgba(255,255,255,0.025)')}
              onMouseLeave={e=>(e.currentTarget.style.background='transparent')}>
              <div className={'dot '+s.dot} style={{ flexShrink:0 }}/>
              <div style={{ flex:1, minWidth:0 }}>
                <div style={{ display:'flex', alignItems:'center', gap:'8px', flexWrap:'wrap' }}>
                  <code style={{ fontSize:'12px', fontFamily:'JetBrains Mono,monospace', color:'rgba(255,255,255,0.85)', fontWeight:500 }}>{h.name}</code>
                  <span style={{ fontSize:'9px', padding:'1px 6px', borderRadius:'4px', background:s.color+'15', color:s.color, border:'1px solid '+s.color+'25', fontFamily:'JetBrains Mono,monospace', fontWeight:700, letterSpacing:'.5px' }}>{s.label}</span>
                  {h.reference?.cvss && <span style={{ fontSize:'9px', color:'rgba(255,255,255,0.2)', fontFamily:'JetBrains Mono,monospace' }}>CVSS {h.reference.cvss.score.toFixed(1)}</span>}
                </div>
                <div style={{ fontSize:'11px', color:'rgba(255,255,255,0.3)', marginTop:'1px', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{h.description}</div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
