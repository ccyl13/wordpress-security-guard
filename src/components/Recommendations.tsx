import type { AuditResult } from '@/types/wordpress-audit';
import { CheckCircle2, Lightbulb } from 'lucide-react';

interface Rec { priority: 'critical'|'high'|'medium'|'low'; title: string; detail: string; code?: string; }

const P: Record<string,{label:string;dot:string;pill:string}> = {
  critical: { label:'Crítico',  dot:'dot-red',    pill:'pill-red' },
  high:     { label:'Alto',     dot:'dot-orange',  pill:'pill-orange' },
  medium:   { label:'Medio',   dot:'dot-yellow',  pill:'pill-yellow' },
  low:      { label:'Bajo',    dot:'dot-blue',    pill:'pill-blue' },
};

function buildRecs(r: AuditResult): Rec[] {
  const recs: Rec[] = [];
  if (r.endpoints.find(e => e.url.includes('xmlrpc') && e.status === 'accessible'))
    recs.push({ priority:'critical', title:'Deshabilitar XML-RPC',
      detail:'XML-RPC está expuesto. Puede usarse para ataques de fuerza bruta y DDoS.',
      code: "add_filter('xmlrpc_enabled', '__return_false');" });
  if (r.endpoints.find(e => e.url.includes('readme') && e.status === 'accessible'))
    recs.push({ priority:'medium', title:'Eliminar readme.html',
      detail:'Revela la versión de WordPress. Elimínalo del servidor.',
      code: 'rm /var/www/html/readme.html' });
  const missingCritical = r.securityHeaders.filter(h => h.status === 'vulnerable' &&
    ['Content-Security-Policy','Strict-Transport-Security','X-Frame-Options','X-Content-Type-Options'].includes(h.name));
  if (missingCritical.length > 0)
    recs.push({ priority:'high', title:'Configurar cabeceras de seguridad críticas',
      detail:'Faltan: ' + missingCritical.map(h => h.name).join(', '),
      code: 'Header always set X-Frame-Options "SAMEORIGIN"\nHeader always set X-Content-Type-Options "nosniff"\nHeader always set Strict-Transport-Security "max-age=31536000; includeSubDomains"' });
  if (r.userEnumeration.found)
    recs.push({ priority:'high', title:'Proteger enumeración de usuarios',
      detail:'Los usernames son accesibles vía REST API o author archives.',
      code: "add_filter('rest_endpoints', function($e){ unset($e['/wp/v2/users']); return $e; });" });
  if (r.wordpressInfo.version)
    recs.push({ priority:'medium', title:'Ocultar versión de WordPress',
      detail:'La versión ' + r.wordpressInfo.version + ' es visible públicamente.',
      code: "remove_action('wp_head', 'wp_generator');" });
  if (r.wordpressInfo.generator)
    recs.push({ priority:'low', title:'Eliminar meta Generator',
      detail:'La etiqueta Generator revela que el sitio usa WordPress.' });
  return recs.sort((a,b) => ({critical:0,high:1,medium:2,low:3}[a.priority]-{critical:0,high:1,medium:2,low:3}[b.priority]));
}

export function Recommendations({ result }: { result: AuditResult }) {
  const recs = buildRecs(result);
  if (recs.length === 0) return (
    <div className="result-card p-6 flex items-center gap-4">
      <CheckCircle2 size={24} className="text-emerald-400 shrink-0"/>
      <div>
        <p className="font-bold text-emerald-400">Sin hallazgos críticos</p>
        <p className="text-sm text-white/40 mt-0.5">El sitio supera los controles de seguridad básicos.</p>
      </div>
    </div>
  );
  return (
    <div className="result-card">
      <div className="card-header">
        <div className="flex items-center gap-2">
          <Lightbulb size={15} className="text-violet-400"/>
          <span className="text-sm font-bold">Recomendaciones</span>
        </div>
        <span className="mono-label">{recs.length} hallazgo{recs.length !== 1 ? 's' : ''}</span>
      </div>
      <div className="divide-y divide-white/[0.04]">
        {recs.map((rec, i) => {
          const p = P[rec.priority];
          return (
            <div key={i} className="px-5 py-4 hover:bg-white/[0.02] transition-colors">
              <div className="flex items-start gap-3">
                <div className={'dot mt-2 shrink-0 ' + p.dot}/>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap mb-1">
                    <span className="font-semibold text-sm text-white/90">{rec.title}</span>
                    <span className={'pill ' + p.pill}>{p.label}</span>
                  </div>
                  <p className="text-[11px] text-white/40 leading-relaxed">{rec.detail}</p>
                  {rec.code && (
                    <pre className="mt-2 font-mono text-[10px] bg-black/40 border border-white/[0.06] rounded-lg px-4 py-3 text-emerald-300/80 overflow-x-auto whitespace-pre-wrap leading-relaxed">{rec.code}</pre>
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
