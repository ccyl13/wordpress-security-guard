import type { AuditResult } from '@/types/wordpress-audit';
import { CheckCircle2, Lightbulb } from 'lucide-react';

const PRI = {
  critical: { color:'#ef4444', bg:'rgba(239,68,68,0.08)',   border:'rgba(239,68,68,0.2)',   dot:'#ef4444', label:'Critico' },
  high:     { color:'#f97316', bg:'rgba(249,115,22,0.08)',  border:'rgba(249,115,22,0.2)',  dot:'#f97316', label:'Alto' },
  medium:   { color:'#f59e0b', bg:'rgba(245,158,11,0.08)', border:'rgba(245,158,11,0.2)', dot:'#f59e0b', label:'Medio' },
  low:      { color:'#3b82f6', bg:'rgba(59,130,246,0.08)', border:'rgba(59,130,246,0.2)', dot:'#3b82f6', label:'Bajo' },
};

type Priority = keyof typeof PRI;
interface Rec { priority: Priority; title: string; detail: string; code?: string; }

function buildRecs(r: AuditResult): Rec[] {
  const recs: Rec[] = [];
  if (r.endpoints.find(e => e.url.includes('xmlrpc') && e.status === 'accessible'))
    recs.push({ priority:'critical', title:'Deshabilitar XML-RPC', detail:'Puede usarse para fuerza bruta y DDoS. Desactivalo si no lo necesitas.', code:"add_filter('xmlrpc_enabled', '__return_false');" });
  if (r.endpoints.find(e => e.url.includes('readme') && e.status === 'accessible'))
    recs.push({ priority:'medium', title:'Eliminar readme.html', detail:'Revela la version de WordPress.', code:'rm /var/www/html/readme.html' });
  const missCrit = r.securityHeaders.filter(h => h.status === 'vulnerable' && ['Content-Security-Policy','Strict-Transport-Security','X-Frame-Options','X-Content-Type-Options'].includes(h.name));
  if (missCrit.length)
    recs.push({ priority:'high', title:'Cabeceras de seguridad criticas ausentes', detail:'Faltan: ' + missCrit.map(h=>h.name).join(', ') + '. Configuralas en tu servidor.', code:'Header always set X-Frame-Options "SAMEORIGIN"\nHeader always set Strict-Transport-Security "max-age=31536000"' });
  if (r.userEnumeration.found)
    recs.push({ priority:'high', title:'Usuarios enumerables publicamente', detail:'La API REST o archive expone nombres de usuario validos.', code:"add_filter('rest_endpoints',fn($e){unset($e['/wp/v2/users']);return $e;});" });
  if (r.wordpressInfo.version)
    recs.push({ priority:'medium', title:'Version de WordPress expuesta', detail:'La version ' + r.wordpressInfo.version + ' es visible. Ocultala.', code:"remove_action('wp_head','wp_generator');" });
  return recs.sort((a,b)=>Object.keys(PRI).indexOf(a.priority)-Object.keys(PRI).indexOf(b.priority));
}

export function Recommendations({ result }: { result: AuditResult }) {
  const recs = buildRecs(result);
  if (!recs.length) return (
    <div className='result-card p-6 flex items-center gap-4'>
      <CheckCircle2 size={20} style={{ color:'#10b981', flexShrink:0 }}/>
      <div>
        <p className='font-semibold' style={{ color:'#10b981' }}>Sin hallazgos criticos</p>
        <p className='text-white/30 mt-0.5' style={{ fontSize:13 }}>El sitio supera los controles de seguridad basicos.</p>
      </div>
    </div>
  );
  return (
    <div className='result-card overflow-hidden'>
      <div className='card-header'>
        <div className='flex items-center gap-2'><Lightbulb size={13} style={{ color:'#8b5cf6' }}/><span className='card-title'>Recomendaciones</span></div>
        <span className='mono text-white/20' style={{ fontSize:10 }}>{recs.length} hallazgo{recs.length!==1?'s':''}</span>
      </div>
      {recs.map((rec,i) => {
        const p = PRI[rec.priority];
        return (
          <div key={i} className='px-5 py-4 border-b border-white/4 last:border-0 hover:bg-white/1 transition-colors'>
            <div className='flex items-start gap-3'>
              <div style={{ width:6, height:6, borderRadius:'50%', background:p.dot, boxShadow:'0 0 6px '+p.dot+'80', flexShrink:0, marginTop:6 }}/>
              <div className='flex-1 min-w-0'>
                <div className='flex items-center gap-2 flex-wrap mb-1'>
                  <span className='font-semibold text-white/80' style={{ fontSize:13 }}>{rec.title}</span>
                  <span className='mono px-2 py-0.5 rounded' style={{ fontSize:9, color:p.color, background:p.bg, border:'1px solid '+p.border, letterSpacing:'0.5px' }}>{p.label}</span>
                </div>
                <p className='text-white/35 leading-relaxed mb-2' style={{ fontSize:12 }}>{rec.detail}</p>
                {rec.code && (
                  <pre className='mono rounded-xl px-4 py-3 overflow-x-auto leading-relaxed' style={{ fontSize:10, color:'#a78bfa', background:'rgba(139,92,246,0.06)', border:'1px solid rgba(139,92,246,0.15)', whiteSpace:'pre-wrap' }}>{rec.code}</pre>
                )}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}