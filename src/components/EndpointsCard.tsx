import type { EndpointCheck } from '@/types/wordpress-audit';
import { ShieldAlert, ShieldCheck, Loader2, Globe } from 'lucide-react';

const RISK:{[k:string]:string}={critical:'pill-red',high:'pill-orange',medium:'pill-yellow',low:'pill-blue',info:'pill-gray'};

export function EndpointsCard({endpoints}:{endpoints:EndpointCheck[]}){
  const exposed=endpoints.filter(e=>e.status==='accessible').length;
  return(
    <div className="result-card">
      <div className="card-header">
        <div className="flex items-center gap-2">
          <Globe size={15} className="text-blue-400"/>
          <span className="text-sm font-bold">Endpoints sensibles</span>
        </div>
        <span className={'pill '+(exposed>0?'pill-red':'pill-green')}>
          {exposed} expuesto{exposed!==1?'s':''}
        </span>
      </div>
      <div className="divide-y divide-white/[0.04]">
        {endpoints.map(ep=>{
          const acc=ep.status==='accessible'; const chk=ep.status==='checking';
          return(
            <div key={ep.url} className={'flex items-start gap-3 px-5 py-3 transition-colors hover:bg-white/[0.02] '+(acc?'bg-red-950/10':'')}>
              <div className="mt-0.5 shrink-0">
                {chk?<Loader2 size={14} className="text-white/30 animate-spin"/>
                  :acc?<ShieldAlert size={14} className="text-red-400"/>
                  :<ShieldCheck size={14} className="text-emerald-400"/>}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <code className="text-[11px] font-mono font-semibold text-white/80">{ep.name}</code>
                  <span className={'pill uppercase '+(RISK[ep.risk]||'pill-gray')}>{ep.risk}</span>
                  {ep.statusCode&&<span className="font-mono text-[9px] text-white/25">HTTP {ep.statusCode}</span>}
                </div>
                <p className="text-[10px] text-white/35 mt-0.5">{ep.description}</p>
                <code className="text-[9px] text-white/15 font-mono">{ep.url.replace(/^https?:\/\/[^/]+/,'')}</code>
              </div>
              <span className={'pill shrink-0 '+(acc?'pill-red':'pill-green')}>
                {chk?'···':acc?'EXPOSED':'OK'}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
