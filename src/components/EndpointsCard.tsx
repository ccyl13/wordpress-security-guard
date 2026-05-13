import type { EndpointCheck } from '@/types/wordpress-audit';
import { ShieldAlert, ShieldCheck, Loader2, Globe } from 'lucide-react';

const RISK: Record<string, { color: string; bg: string; border: string }> = {
  critical: { color:'#ef4444', bg:'rgba(239,68,68,0.1)',   border:'rgba(239,68,68,0.3)' },
  high:     { color:'#f97316', bg:'rgba(249,115,22,0.1)',  border:'rgba(249,115,22,0.3)' },
  medium:   { color:'#f59e0b', bg:'rgba(245,158,11,0.1)', border:'rgba(245,158,11,0.3)' },
  low:      { color:'#3b82f6', bg:'rgba(59,130,246,0.1)', border:'rgba(59,130,246,0.3)' },
  info:     { color:'rgba(255,255,255,0.3)', bg:'rgba(255,255,255,0.05)', border:'rgba(255,255,255,0.1)' },
};

export function EndpointsCard({ endpoints }: { endpoints: EndpointCheck[] }) {
  const exposed = endpoints.filter(e=>e.status==='accessible').length;
  return (
    <div className="result-card overflow-hidden">
      <div className="card-header">
        <div className="flex items-center gap-2">
          <Globe size={13} style={{ color: '#3b82f6' }}/>
          <span className="card-title">Endpoints sensibles</span>
        </div>
        <span className="mono px-2 py-0.5 rounded-full" style={{ fontSize: 10, color: exposed > 0 ? '#ef4444' : '#10b981', background: exposed > 0 ? 'rgba(239,68,68,0.1)' : 'rgba(16,185,129,0.1)' }}>
          {exposed} expuesto{exposed !== 1 ? 's' : ''}
        </span>
      </div>
      <div>
        {endpoints.map(ep => {
          const r = RISK[ep.risk] || RISK.info;
          const ok = ep.status !== 'accessible';
          const checking = ep.status === 'checking';
          return (
            <div key={ep.url} className="flex items-start gap-3 px-4 py-3 border-b border-white/4 last:border-0 transition-colors hover:bg-white/2" style={!ok && !checking ? {} : { background: 'rgba(239,68,68,0.03)' }}>
              <div style={{ marginTop: 2, flexShrink: 0 }}>
                {checking ? <Loader2 size={13} className="animate-spin text-white/20"/> : ok ? <ShieldCheck size={13} style={{ color: '#10b981' }}/> : <ShieldAlert size={13} style={{ color: '#ef4444' }}/>}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <code className="mono font-medium text-white/70" style={{ fontSize: 11 }}>{ep.name}</code>
                  <span className="mono px-1.5 py-0.5 rounded uppercase" style={{ fontSize: 9, color: r.color, background: r.bg, border: '1px solid ' + r.border, letterSpacing: '0.5px' }}>{ep.risk}</span>
                  {ep.statusCode && <span className="mono text-white/20" style={{ fontSize: 9 }}>HTTP {ep.statusCode}</span>}
                </div>
                <p className="text-white/30 mt-0.5" style={{ fontSize: 11 }}>{ep.description}</p>
              </div>
              <span className="mono shrink-0 px-2 py-0.5 rounded" style={{ fontSize: 9, color: ok ? '#10b981' : '#ef4444', background: ok ? 'rgba(16,185,129,0.08)' : 'rgba(239,68,68,0.08)' }}>
                {checking ? '···' : ok ? 'OK' : 'EXPOSED'}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
