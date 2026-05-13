import type { AuditResult } from '@/types/wordpress-audit';
import { AlertTriangle, CheckCircle2, ChevronRight, Lightbulb } from 'lucide-react';

interface RecommendationsProps {
  result: AuditResult;
}

interface Rec {
  priority: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  detail: string;
  code?: string;
}

const PRIORITY_CONFIG = {
  critical: { label: 'Critico', color: 'text-red-400', bg: 'bg-red-950/20', border: 'border-red-400/30', dot: 'bg-red-400' },
  high:     { label: 'Alto',    color: 'text-orange-400', bg: 'bg-orange-950/20', border: 'border-orange-400/30', dot: 'bg-orange-400' },
  medium:   { label: 'Medio',   color: 'text-yellow-400', bg: 'bg-yellow-950/20', border: 'border-yellow-400/30', dot: 'bg-yellow-400' },
  low:      { label: 'Bajo',    color: 'text-blue-400', bg: 'bg-blue-950/20', border: 'border-blue-400/30', dot: 'bg-blue-400' },
};

function buildRecs(result: AuditResult): Rec[] {
  const recs: Rec[] = [];

  // Endpoints
  const xmlrpc = result.endpoints.find(e => e.url.includes('xmlrpc') && e.status === 'accessible');
  if (xmlrpc) recs.push({
    priority: 'critical', title: 'Deshabilitar XML-RPC',
    detail: 'XML-RPC esta expuesto y puede usarse para ataques de fuerza bruta o DDoS. Desactivalo si no lo necesitas.',
    code: 'add_filter("xmlrpc_enabled", "__return_false");'
  });

  const readme = result.endpoints.find(e => e.url.includes('readme') && e.status === 'accessible');
  if (readme) recs.push({
    priority: 'medium', title: 'Eliminar readme.html',
    detail: 'El archivo readme.html revela la version de WordPress. Eliminalo del servidor.',
    code: 'rm /var/www/html/readme.html'
  });

  // Headers
  const missingCritical = result.securityHeaders.filter(h => h.status === 'vulnerable' && ['Content-Security-Policy','Strict-Transport-Security','X-Frame-Options','X-Content-Type-Options'].includes(h.name));
  if (missingCritical.length > 0) recs.push({
    priority: 'high', title: 'Configurar cabeceras de seguridad criticas',
    detail: 'Faltan cabeceras esenciales: ' + missingCritical.map(h => h.name).join(', ') + '. Configuralas en tu servidor o .htaccess.',
    code: 'Header always set X-Frame-Options "SAMEORIGIN"\nHeader always set X-Content-Type-Options "nosniff"\nHeader always set Strict-Transport-Security "max-age=31536000; includeSubDomains"'
  });

  // User enum
  if (result.userEnumeration.found) recs.push({
    priority: 'high', title: 'Proteger enumeracion de usuarios',
    detail: 'Los nombres de usuario son accesibles publicamente. Instala un plugin de seguridad que bloquee la REST API o usa un plugin de proteccion de login.',
    code: 'add_filter("rest_endpoints", function($e) { unset($e["/wp/v2/users"]); return $e; });'
  });

  // WP version exposed
  if (result.wordpressInfo.version) recs.push({
    priority: 'medium', title: 'Ocultar version de WordPress',
    detail: 'La version ' + result.wordpressInfo.version + ' es visible publicamente. Eliminala del HTML y del feed RSS.',
    code: 'remove_action("wp_head", "wp_generator");'
  });

  // Generator header
  if (result.wordpressInfo.generator) recs.push({
    priority: 'low', title: 'Eliminar cabecera Generator',
    detail: 'La meta etiqueta Generator revela que el sitio usa WordPress. Eliminala desde functions.php.'
  });

  return recs.sort((a, b) => {
    const order = { critical: 0, high: 1, medium: 2, low: 3 };
    return order[a.priority] - order[b.priority];
  });
}

export function Recommendations({ result }: RecommendationsProps) {
  const recs = buildRecs(result);

  if (recs.length === 0) {
    return (
      <div className="rounded-xl bg-card border border-emerald-400/20 p-6 flex items-center gap-4">
        <CheckCircle2 className="w-6 h-6 text-emerald-400 shrink-0" />
        <div>
          <p className="font-semibold text-emerald-400">Sin recomendaciones criticas</p>
          <p className="text-sm text-muted-foreground mt-0.5">El sitio supera los controles de seguridad basicos.</p>
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-xl bg-card border border-border overflow-hidden">
      <div className="px-5 py-4 border-b border-border flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Lightbulb className="w-4 h-4 text-primary" />
          <h3 className="font-semibold text-sm">Recomendaciones</h3>
        </div>
        <span className="text-xs font-mono text-muted-foreground">{recs.length} hallazgo{recs.length !== 1 ? 's' : ''}</span>
      </div>
      <div className="divide-y divide-border">
        {recs.map((rec, i) => {
          const cfg = PRIORITY_CONFIG[rec.priority];
          return (
            <div key={i} className="px-5 py-4 hover:bg-secondary/20 transition-colors">
              <div className="flex items-start gap-3">
                <div className={"w-2 h-2 rounded-full mt-2 shrink-0 " + cfg.dot} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <p className="font-semibold text-sm">{rec.title}</p>
                    <span className={"text-xs px-2 py-0.5 rounded border font-mono " + cfg.color + " " + cfg.bg + " " + cfg.border}>
                      {cfg.label}
                    </span>
                  </div>
                  <p className="text-xs text-muted-foreground leading-relaxed">{rec.detail}</p>
                  {rec.code && (
                    <pre className="mt-2 text-xs font-mono bg-secondary/80 border border-border rounded-lg px-3 py-2 overflow-x-auto text-emerald-300 whitespace-pre-wrap">{rec.code}</pre>
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
