import type { EndpointCheck } from '@/types/wordpress-audit';
import { Globe, ShieldAlert, ShieldCheck, Loader2 } from 'lucide-react';

const RISK: Record<string,{dot:string;color:string;bg:string}> = {
  critical: {dot:'dot-red',   color:'#f87171',bg:'rgba(239,68,68,0.08)'},
  high:     {dot:'dot-orange',color:'#fb923c',bg:'rgba(249,115,22,0.08)'},
  medium:   {dot:'dot-yellow',color:'#fbbf24',bg:'rgba(234,179,8,0.08)'},
  low:      {dot:'dot-blue',  color:'#60a5fa',bg:'rgba(59,130,246,0.08)'},
  info:     {dot:'dot-gray',  color:'rgba(255,255,255,0.3)',bg:'rgba(255,255,255,0.04)'},
};

export function EndpointsCard({ endpoints }: { endpoints: EndpointCheck[] }) {
  const exposed = endpoints.filter(e=>e.status==='accessible').length;
  return (
    <div className="result-card">
      <div className="card-header">
        <span className="card-title"><Globe size={14} style={{color:'#60a5fa'}}/> Endpoints sensibles</span>
        <span className="mono" style={{fontSize:'10px',color:exposed>0?'#f87171':'#34d399'}}>{exposed} expuesto{exposed!==1?'s':''}</span>
      </div>
      <div>
        {endpoints.map(ep=>{
          const r=RISK[ep.risk]||RISK.info;
          const isAcc=ep.status==='accessible';
          const isChk=ep.status==='checking';
          const path=ep.url.replace(/^https?:\/\/[^/]+/,'');
          return (
            <div key={ep.url} style={{display:'flex',alignItems:'center',gap:'10px',padding:'9px 20px',borderBottom:'1px solid rgba(255,255,255,0.03)',background:isAcc?'rgba(239,68,68,0.04)':'transparent',transition:'background .15s'}}
              onMouseEnter={e=>(e.currentTarget.style.background=isAcc?'rgba(239,68,68,0.07)':'rgba(255,255,255,0.02)')}
              onMouseLeave={e=>(e.currentTarget.style.background=isAcc?'rgba(239,68,68,0.04)':'transparent')}>
              {isChk?<Loader2 size={14} style={{color:'rgba(255,255,255,0.3)',animation:'spin 1s linear infinite',flexShrink:0}}/>
                :isAcc?<ShieldAlert size={14} style={{color:'#f87171',flexShrink:0}}/>
                :<ShieldCheck size={14} style={{color:'#34d399',flexShrink:0}}/>}
              <div style={{flex:1,minWidth:0}}>
                <div style={{display:'flex',alignItems:'center',gap:'8px',flexWrap:'wrap'}}>
                  <code style={{fontSize:'12px',fontFamily:'JetBrains Mono,monospace',color:'rgba(255,255,255,0.85)',fontWeight:500}}>{ep.name}</code>
                  <span style={{fontSize:'9px',padding:'1px 6px',borderRadius:'4px',background:r.bg,color:r.color,border:'1px solid '+r.color+'30',fontFamily:'JetBrains Mono,monospace',fontWeight:700,letterSpacing:'.5px',textTransform:'uppercase'}}>{ep.risk}</span>
                </div>
                <code style={{fontSize:'10px',fontFamily:'JetBrains Mono,monospace',color:'rgba(255,255,255,0.2)'}}>{path}</code>
              </div>
              <span className="mono" style={{fontSize:'9px',padding:'2px 7px',borderRadius:'5px',background:isAcc?'rgba(239,68,68,0.12)':'rgba(16,185,129,0.1)',color:isAcc?'#f87171':'#34d399',fontWeight:700,letterSpacing:'.5px',flexShrink:0}}>
                {isChk?'···':isAcc?'EXPOSED':'SAFE'}
              </span>
            </div>
          );
        })}
      </div>
      <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
    </div>
  );
}