import type { SecurityHeader } from '@/types/wordpress-audit';
import { CheckCircle2, XCircle, AlertTriangle, ShieldCheck } from 'lucide-react';

const ST: Record<string,{icon:any;dot:string;pill:string;label:string}> = {
  secure:     {icon:CheckCircle2, dot:'dot-green',  pill:'pill-green',  label:'OK'},
  warning:    {icon:AlertTriangle,dot:'dot-yellow', pill:'pill-yellow', label:'WARN'},
  vulnerable: {icon:XCircle,     dot:'dot-red',    pill:'pill-red',    label:'FAIL'},
  info:       {icon:ShieldCheck, dot:'dot-blue',   pill:'pill-blue',   label:'INFO'},
};

export function SecurityHeadersCard({headers}:{headers:SecurityHeader[]}){
  const counts={ok:headers.filter(h=>h.status==='secure').length,warn:headers.filter(h=>h.status==='warning').length,fail:headers.filter(h=>h.status==='vulnerable').length};
  return(
    <div className="result-card">
      <div className="card-header">
        <div className="flex items-center gap-2">
          <ShieldCheck size={15} className="text-violet-400"/>
          <span className="text-sm font-bold">Cabeceras HTTP</span>
        </div>
        <div className="flex items-center gap-2 font-mono text-[10px]">
          <span className="text-emerald-400">{counts.ok} ok</span>
          <span className="text-white/15">·</span>
          <span className="text-amber-400">{counts.warn} warn</span>
          <span className="text-white/15">·</span>
          <span className="text-red-400">{counts.fail} fail</span>
        </div>
      </div>
      <div className="divide-y divide-white/[0.04]">
        {headers.map(h=>{
          const s=ST[h.status]||ST.info; const Icon=s.icon;
          return(
            <div key={h.name} className="flex items-start gap-3 px-5 py-3 hover:bg-white/[0.02] transition-colors">
              <Icon size={14} className={'mt-0.5 shrink-0 '+(h.status==='secure'?'text-emerald-400':h.status==='warning'?'text-amber-400':h.status==='vulnerable'?'text-red-400':'text-blue-400')}/>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <code className="text-[11px] font-mono font-semibold text-white/80">{h.name}</code>
                  <span className={'pill '+s.pill}>{s.label}</span>
                  {h.reference?.cvss&&<span className="font-mono text-[9px] text-white/25">CVSS {h.reference.cvss.score.toFixed(1)}</span>}
                </div>
                <p className="text-[10px] text-white/35 mt-0.5 truncate">{h.description}</p>
                {h.reference?.owasp&&<p className="font-mono text-[9px] text-white/15 mt-0.5">{h.reference.owasp}</p>}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
