import type { AuditResult } from '@/types/wordpress-audit';
import { CheckCircle2, Lightbulb } from 'lucide-react';

interface Rec { priority:'critical'|'high'|'medium'|'low'; title:string; detail:string; code?:string; }
const PRI = {
  critical:{ dot:'bg-red-400',    pill:'bg-red-400/10 text-red-400 border-red-400/25',    label:'Crítico' },
  high:    { dot:'bg-orange-400', pill:'bg-orange-400/10 text-orange-400 border-orange-400/25', label:'Alto' },
  medium:  { dot:'bg-amber-400',  pill:'bg-amber-400/10 text-amber-400 border-amber-400/25',   label:'Medio' },
  low:     { dot:'bg-blue-400',   pill:'bg-blue-400/10 text-blue-400 border-blue-400/25',       label:'Bajo' },
};
function buildRecs(r: AuditResult): Rec[] {
  const recs: Rec[] = [];
  if (r.endpoints.find(e=>e.url.includes('xmlrpc')&&e.status==='accessible'))
    recs.push({ priority:'critical', title:'Deshabilitar XML-RPC', detail:'Puede usarse para ataques de fuerza bruta y DDoS amplificados.', code:"add_filter('xmlrpc_enabled', '__return_false');" });
  if (r.endpoints.find(e=>e.url.includes('readme')&&e.status==='accessible'))
    recs.push({ priority:'medium', title:'Eliminar readme.html', detail:'Revela la versión de WordPress al atacante.', code:'rm /var/www/html/readme.html' });
  const missing = r.securityHeaders.filter(h=>h.status==='vulnerable'&&['Content-Security-Policy','Strict-Transport-Security','X-Frame-Options','X-Content-Type-Options'].includes(h.name));
  if (missing.length)
    recs.push({ priority:'high', title:'Configurar cabeceras de seguridad', detail:'Faltan: '+missing.map(h=>h.name).join(', '), code:'Header always set X-Frame-Options "SAMEORIGIN"\nHeader always set X-Content-Type-Options "nosniff"' });
  if (r.userEnumeration.found)
    recs.push({ priority:'high', title:'Proteger enumeración de usuarios', detail:'Los nombres de usuario son accesibles públicamente via REST API.', code:"add_filter('rest_endpoints',function($e){unset($e['/wp/v2/users']);return $e;});" });
  if (r.wordpressInfo.version)
    recs.push({ priority:'medium', title:'Ocultar versión de WordPress', detail:'La versión '+r.wordpressInfo.version+' es visible públicamente.', code:"remove_action('wp_head','wp_generator');" });
  if (r.wordpressInfo.generator)
    recs.push({ priority:'low', title:'Eliminar cabecera Generator', detail:'Revela que el sitio usa WordPress. Elimínala desde functions.php.' });
  return recs.sort((a,b)=>({critical:0,high:1,medium:2,low:3}[a.priority]-{critical:0,high:1,medium:2,low:3}[b.priority]));
}

export function Recommendations({ result }: { result:AuditResult }) {
  const recs = buildRecs(result);
  if (!recs.length) return (
    <div className="glass rounded-2xl p-6 flex items-center gap-4 border-emerald-500/15">
      <CheckCircle2 size={22} className="text-emerald-400 shrink-0"/>
      <div>
        <p className="font-bold text-emerald-400">Sin recomendaciones críticas</p>
        <p className="text-sm text-white/40 mt-0.5">El sitio supera los controles básicos de seguridad.</p>
      </div>
    </div>
  );
  return (
    <div className="glass rounded-2xl overflow-hidden">
      <div className="px-5 py-4 border-b border-white/[0.06] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Lightbulb size={15} className="text-purple"/>
          <span className="font-bold text-sm">Recomendaciones</span>
        </div>
        <span className="mono text-[10px] text-white/30">{recs.length} hallazgo{recs.length!==1?'s':''}</span>
      </div>
      <div className="divide-y divide-white/[0.04]">
        {recs.map((rec,i) => {
          const p = PRI[rec.priority];
          return (
            <div key={i} className="px-5 py-4 hover:bg-white/[0.02] transition-colors">
              <div className="flex items-start gap-3">
                <div className={`w-2 h-2 rounded-full mt-2 shrink-0 ${p.dot}`}/>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <p className="font-bold text-sm">{rec.title}</p>
                    <span className={`mono text-[8px] px-2 py-0.5 rounded-full border font-bold tracking-wide ${p.pill}`}>{p.label}</span>
                  </div>
                  <p className="text-[11px] text-white/40 leading-relaxed">{rec.detail}</p>
                  {rec.code && (
                    <pre className="mt-2 mono text-[10px] bg-white/[0.04] border border-white/[0.06] rounded-lg px-3 py-2.5 overflow-x-auto text-emerald-300 whitespace-pre-wrap leading-relaxed">{rec.code}</pre>
                  )}
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
