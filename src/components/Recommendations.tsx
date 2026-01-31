import { AlertTriangle, CheckCircle2, Info, Shield } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import type { AuditResult } from '@/types/wordpress-audit';
import { cn } from '@/lib/utils';

interface RecommendationsProps {
  result: AuditResult;
}

interface Recommendation {
  type: 'critical' | 'warning' | 'info';
  title: string;
  description: string;
}

function generateRecommendations(result: AuditResult): Recommendation[] {
  const recommendations: Recommendation[] = [];

  // Check critical endpoints
  const criticalEndpoints = result.endpoints.filter(
    (e) => e.status === 'accessible' && e.risk === 'critical'
  );
  
  if (criticalEndpoints.some((e) => e.name === 'XML-RPC')) {
    recommendations.push({
      type: 'critical',
      title: 'Desactivar XML-RPC',
      description: 'XML-RPC está activo y puede ser usado para ataques de fuerza bruta. Añade esto a .htaccess: <Files xmlrpc.php> Order Deny,Allow Deny from all </Files>',
    });
  }

  if (criticalEndpoints.some((e) => e.name === 'Debug Log')) {
    recommendations.push({
      type: 'critical',
      title: 'Eliminar debug.log',
      description: 'El archivo debug.log está expuesto públicamente y contiene información sensible. Elimínalo o restringe el acceso.',
    });
  }

  if (criticalEndpoints.some((e) => e.name === 'Git Exposed')) {
    recommendations.push({
      type: 'critical',
      title: 'Ocultar directorio .git',
      description: 'El repositorio Git está expuesto. Esto puede revelar código fuente y credenciales. Añade una regla para bloquearlo.',
    });
  }

  // Check security headers
  const missingCriticalHeaders = result.securityHeaders.filter(
    (h) => h.status === 'vulnerable' && ['Content-Security-Policy', 'X-Frame-Options', 'Strict-Transport-Security'].includes(h.name)
  );

  if (missingCriticalHeaders.length > 0) {
    recommendations.push({
      type: 'warning',
      title: 'Configurar cabeceras de seguridad',
      description: `Faltan cabeceras críticas: ${missingCriticalHeaders.map(h => h.name).join(', ')}. Configúralas en tu servidor web o usando un plugin de seguridad.`,
    });
  }

  // Check user enumeration
  if (result.userEnumeration.found) {
    recommendations.push({
      type: 'warning',
      title: 'Bloquear enumeración de usuarios',
      description: `Se encontraron ${result.userEnumeration.users.length} usuarios expuestos via ${result.userEnumeration.method}. Usa un plugin como "Disable REST API" o configura tu tema.`,
    });
  }

  // Check version disclosure
  if (result.wordpressInfo.generator) {
    recommendations.push({
      type: 'info',
      title: 'Ocultar versión de WordPress',
      description: 'La versión de WordPress está expuesta en el código fuente. Añade remove_action("wp_head", "wp_generator") a functions.php.',
    });
  }

  // Good practices
  if (recommendations.length === 0) {
    recommendations.push({
      type: 'info',
      title: '¡Buen trabajo!',
      description: 'No se encontraron problemas críticos. Mantén WordPress y plugins actualizados.',
    });
  }

  return recommendations;
}

const iconMap = {
  critical: AlertTriangle,
  warning: Shield,
  info: Info,
};

const colorMap = {
  critical: 'text-red-500 bg-red-500/10 border-red-500/30',
  warning: 'text-yellow-500 bg-yellow-500/10 border-yellow-500/30',
  info: 'text-blue-500 bg-blue-500/10 border-blue-500/30',
};

export function Recommendations({ result }: RecommendationsProps) {
  const recommendations = generateRecommendations(result);

  return (
    <Card className="bg-card border-border md:col-span-2">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-3 text-lg">
          <div className="p-2 rounded-lg bg-primary/10">
            <CheckCircle2 className="w-5 h-5 text-primary" />
          </div>
          Recomendaciones
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        {recommendations.map((rec, index) => {
          const Icon = iconMap[rec.type];
          return (
            <div
              key={index}
              className={cn(
                'p-4 rounded-lg border transition-all hover:scale-[1.01]',
                colorMap[rec.type]
              )}
            >
              <div className="flex items-start gap-3">
                <Icon className="w-5 h-5 mt-0.5 flex-shrink-0" />
                <div>
                  <h4 className="font-semibold mb-1">{rec.title}</h4>
                  <p className="text-sm opacity-90">{rec.description}</p>
                </div>
              </div>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}
