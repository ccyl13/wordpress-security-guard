import type { AuditResult } from '@/types/wordpress-audit';
import { CheckCircle2, Lightbulb } from 'lucide-react';

interface Rec { priority:'critical'|'high'|'medium'|'low'; title:string; detail:string; code?:string; }
const PRI = {
  critical: { label:'Crítico', color:'#f87171', bg:'rgba(239,68,68,0.08)',  border:'rgba(239,68,68,0.2)',  dot:'#ef4444' },
  high:     { label:'Alto',    color:'#fb923c', bg:'rgba(249,115,22,0.08)', border:'rgba(249,115,22,0.2)', dot:'#f97316' },
  medium:   { label:'Medio',   color:'#fbbf24', bg:'rgba(234,179,8,0.08)',  border:'rgba(234,179,8,0.2)',  dot:'#eab308' },
  low:      { label:'Bajo',    color:'#60a5fa', bg:'rgba(59,130,246,0.08)', border:'rgba(59,130,246,0.2)', dot:'#3b82f6' },
};

function buildRecs(result: AuditResult): Rec[] {
  const r: Rec[] = [];
  if (result.endpoints.find(e=>e.url.includes('xmlrpc')&&e.status==='accessible'))
    r.push({priority:'critical',title:'Deshabilitar XML-RPC',detail:'XML-RPC está expuesto y puede usarse para ataques de fuerza bruta y DDoS amplificados.',code:"add_filter('xmlrpc_enabled', '__return_false');"});
  if (result.endpoints.find(e=>e.url.includes('readme')&&e.status==='accessible'))
    r.push({priority:'medium',title:'Eliminar readme.html',detail:'El archivo readme.html revela la versión de WordPress facilitando ataques dirigidos.',code:'rm /var/www/html/readme.html'});
  const missing=result.securityHeaders.filter(h=>h.status==='vulnerable'&&['Content-Security-Policy','Strict-Transport-Security','X-Frame-Options','X-Content-Type-Options'].includes(h.name));
  if (missing.length>0)
    r.push({priority:'high',title:'Configurar cabeceras de seguridad críticas',detail:'Faltan: '+missing.map(h=>h.name).join(', ')+'.',code:'Header always set X-Frame-Options "SAMEORIGIN"\nHeader always set X-Content-Type-Options "nosniff"\nHeader always set Strict-Transport-Security "max-age=31536000"'});
  if (result.userEnumeration.found)
    r.push({priority:'high',title:'Proteger enumeración de usuarios',detail:'Los usuarios son accesibles públicamente a través de la REST API.',code:"add_filter('rest_endpoints',function($e){unset($e['/wp/v2/users']);return $e;});"});
  if (result.wordpressInfo.version)
    r.push({priority:'medium',title:'Ocultar versión de WordPress',detail:'La versión '+result.wordpressInfo.version+' es visible públicamente.',code:"remove_action('wp_head','wp_generator');"});
  return r.sort((a,b)=>(['critical','high','medium','low'].indexOf(a.priority))-(['critical','high','medium','low'].indexOf(b.priority)));
}

export function Recommendations({ result }: { result: AuditResult }) {
  const recs = buildRecs(result);
  if (!recs.length) return (
    <div className="result-card" style={{padding:'24px',display:'flex',alignItems:'center',gap:'14px',borderColor:'rgba(16,185,129,0.2)'}}>
      <CheckCircle2 size={22} style={{color:'#34d399',flexShrink:0}}/>
      <div><div style={{fontWeight:600,color:'#34d399',marginBottom:'2px'}}>Sin recomendaciones críticas</div><div style={{fontSize:'13px',color:'rgba(255,255,255,0.35)'}}>El sitio supera los controles de seguridad básicos.</div></div>
    </div>
  );
  return (
    <div className="result-card">
      <div className="card-header">
        <span className="card-title"><Lightbulb size={14} style={{color:'#fbbf24'}}/> Recomendaciones</span>
        <span className="mono" style={{fontSize:'10px',color:'rgba(255,255,255,0.3)'}}>{recs.length} hallazgo{recs.length!==1?'s':''}</span>
      </div>
      <div>
        {recs.map((rec,i)=>{
          const p=PRI[rec.priority];
          return (
            <div key={i} style={{padding:'18px 20px',borderBottom:'1px solid rgba(255,255,255,0.03)',display:'flex',gap:'14px',alignItems:'flex-start'}}>
              <div style={{width:'6px',height:'6px',borderRadius:'50%',background:p.dot,boxShadow:'0 0 8px '+p.dot+'80',flexShrink:0,marginTop:'6px'}}/>
              <div style={{flex:1}}>
                <div style={{display:'flex',alignItems:'center',gap:'8px',marginBottom:'6px',flexWrap:'wrap'}}>
                  <span style={{fontSize:'14px',fontWeight:600,color:'rgba(255,255,255,0.85)'}}>{rec.title}</span>
                  <span style={{fontSize:'9px',padding:'2px 8px',borderRadius:'99px',background:p.bg,color:p.color,border:'1px solid '+p.border,fontWeight:700,letterSpacing:'.5px'}}>{p.label}</span>
                </div>
                <p style={{fontSize:'12px',color:'rgba(255,255,255,0.4)',lineHeight:1.7,marginBottom:rec.code?'10px':'0'}}>{rec.detail}</p>
                {rec.code&&<pre style={{fontSize:'11px',fontFamily:'JetBrains Mono,monospace',background:'rgba(255,255,255,0.03)',border:'1px solid rgba(255,255,255,0.06)',borderRadius:'8px',padding:'12px 14px',color:'#a78bfa',overflowX:'auto',lineHeight:1.6,whiteSpace:'pre-wrap'}}>{rec.code}</pre>}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}