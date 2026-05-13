import type { EndpointCheck } from '@/types/wordpress-audit';
import { ShieldAlert, ShieldCheck, Loader2, Globe } from 'lucide-react';

const RISK: Record<string,string> = {
  critical: 'text-red-400 bg-red-400/10 border-red-400/25',
  high:     'text-orange-400 bg-orange-400/10 border-orange-400/25',
  medium:   'text-amber-400 bg-amber-400/10 border-amber-400/25',
  low:      'text-blue-400 bg-blue-400/10 border-blue-400/25',
  info:     'text-white/30 bg-white/[0.04] border-white/10',
};

export function EndpointsCard({ endpoints }: { endpoints: EndpointCheck[] }) {
  const exposed = endpoints.filter(e=>e.status==='accessible').length;
  return (
    <div className="glass rounded-2xl overflow-hidden">
      <div className="px-5 py-4 border-b border-white/[0.06] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Globe size={15} className="text-purple" />
          <span className="font-bold text-sm">Endpoints sensibles</span>
        </div>
        <span className={`mono text-[10px] px-2.5 py-0.5 rounded-full ${exposed>0?'text-red-400 bg-red-400/10':'text-emerald-400 bg-emerald-400/10'}`}>
          {exposed} expuesto{exposed!==1?'s':''}
        </span>
      </div>
      <div className="divide-y divide-white/[0.04]">
        {endpoints.map(ep => {
          const isOk = ep.status!=='accessible'; const isChecking = ep.status==='checking';
          return (
            <div key={ep.url} className={`px-5 py-3 flex items-start gap-3 hover:bg-white/[0.02] transition-colors ${!isOk&&!isChecking?'bg-red-500/[0.04]':''}`}>
              <div className="mt-0.5 shrink-0">
                {isChecking ? <Loader2 size={14} className="text-white/30 animate-spin"/> : isOk ? <ShieldCheck size={14} className="text-emerald-400"/> : <ShieldAlert size={14} className="text-red-400"/>}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <code className="mono text-[11px] font-semibold text-white/90">{ep.name}</code>
                  <span className={`mono text-[8px] px-1.5 py-0.5 rounded border uppercase font-bold ${RISK[ep.risk]||RISK.info}`}>{ep.risk}</span>
                  {ep.statusCode && <span className="mono text-[9px] text-white/20">HTTP {ep.statusCode}</span>}
                </div>
                <p className="text-[11px] text-white/40 mt-0.5">{ep.description}</p>
                <code className="mono text-[9px] text-white/20">{ep.url.replace(/^https?:\/\/[^/]+/,'')}</code>
              </div>
              <div className={`mono text-[9px] px-2 py-0.5 rounded font-bold shrink-0 ${!isOk&&!isChecking?'text-red-400 bg-red-400/10':'text-emerald-400 bg-emerald-400/10'}`}>
                {isChecking?'···':!isOk&&!isChecking?'EXPOSED':'OK'}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
