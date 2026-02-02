import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Globe, Check, AlertTriangle, ExternalLink } from 'lucide-react';
import { Badge } from '@/components/ui/badge';
import { cn } from '@/lib/utils';
import type { EndpointCheck } from '@/types/wordpress-audit';
import { SecurityReferenceBadges } from './SecurityReferenceBadges';

interface EndpointsCardProps {
  endpoints: EndpointCheck[];
}

export function EndpointsCard({ endpoints }: EndpointsCardProps) {
  const getRiskBadge = (risk: EndpointCheck['risk'], accessible: boolean) => {
    if (!accessible) return null;
    
    const colors = {
      critical: 'bg-red-500/20 text-red-400 border-red-500/30',
      high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
      medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
      low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
      info: 'bg-muted text-muted-foreground border-muted',
    };
    
    return (
      <Badge variant="outline" className={cn("text-xs", colors[risk])}>
        {risk.toUpperCase()}
      </Badge>
    );
  };

  const accessibleEndpoints = endpoints.filter(e => e.status === 'accessible');
  const blockedEndpoints = endpoints.filter(e => e.status === 'blocked');

  return (
    <Card className="bg-card border-border">
      <CardHeader className="pb-4">
        <CardTitle className="flex items-center gap-3 text-xl">
          <Globe className="w-6 h-6 text-primary" />
          Endpoints WordPress
          <div className="flex gap-2 ml-auto text-sm font-normal">
            <span className="text-red-400">{accessibleEndpoints.length} expuestos</span>
            <span className="text-green-400">{blockedEndpoints.length} bloqueados</span>
          </div>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        {endpoints.map((endpoint) => (
          <div
            key={endpoint.url}
            className={cn(
              "flex flex-col p-3 rounded-lg border transition-colors",
              endpoint.status === 'accessible' 
                ? 'bg-red-500/5 border-red-500/20' 
                : 'bg-green-500/5 border-green-500/20'
            )}
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                {endpoint.status === 'accessible' ? (
                  <AlertTriangle className="w-5 h-5 text-red-400" />
                ) : (
                  <Check className="w-5 h-5 text-green-400" />
                )}
                <div>
                  <span className="font-semibold text-sm">{endpoint.name}</span>
                  <p className="text-xs text-muted-foreground">{endpoint.description}</p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {getRiskBadge(endpoint.risk, endpoint.status === 'accessible')}
                {endpoint.statusCode > 0 && (
                  <code className="text-xs text-muted-foreground">{endpoint.statusCode}</code>
                )}
                {endpoint.status === 'accessible' && (
                  <a 
                    href={endpoint.url} 
                    target="_blank" 
                    rel="noopener noreferrer"
                    className="text-muted-foreground hover:text-foreground"
                  >
                    <ExternalLink className="w-4 h-4" />
                  </a>
                )}
              </div>
            </div>
            {endpoint.status === 'accessible' && endpoint.reference && (
              <div className="ml-8">
                <SecurityReferenceBadges reference={endpoint.reference} compact />
              </div>
            )}
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
