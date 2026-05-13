import type { EndpointCheck } from '@/types/wordpress-audit';
import { ShieldAlert, ShieldCheck, Loader2, Globe } from 'lucide-react';

interface EndpointsCardProps {
  endpoints: EndpointCheck[];
}

const RISK_CONFIG: Record<string, { color: string; bg: string; border: string }> = {
  critical: { color: 'text-red-400',    bg: 'bg-red-400/10',    border: 'border-red-400/30' },
  high:     { color: 'text-orange-400', bg: 'bg-orange-400/10', border: 'border-orange-400/30' },
  medium:   { color: 'text-yellow-400', bg: 'bg-yellow-400/10', border: 'border-yellow-400/30' },
  low:      { color: 'text-blue-400',   bg: 'bg-blue-400/10',   border: 'border-blue-400/30' },
  info:     { color: 'text-muted-foreground', bg: 'bg-secondary/50', border: 'border-border' },
};

export function EndpointsCard({ endpoints }: EndpointsCardProps) {
  const exposed = endpoints.filter(e => e.status === 'accessible').length;

  return (
    <div className="rounded-xl bg-card border border-border overflow-hidden">
      <div className="px-5 py-4 border-b border-border flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Globe className="w-4 h-4 text-primary" />
          <h3 className="font-semibold text-sm">Endpoints sensibles</h3>
        </div>
        <span className={
          'text-xs font-mono px-2 py-0.5 rounded ' +
          (exposed > 0 ? 'text-red-400 bg-red-400/10' : 'text-emerald-400 bg-emerald-400/10')
        }>
          {exposed} expuesto{exposed !== 1 ? 's' : ''}
        </span>
      </div>
      <div className="divide-y divide-border">
        {endpoints.map((ep) => {
          const risk = RISK_CONFIG[ep.risk] || RISK_CONFIG.info;
          const isAccessible = ep.status === 'accessible';
          const isChecking  = ep.status === 'checking';
          const path = ep.url.replace(/^https?:\/\/[^/]+/, '');
          return (
            <div
              key={ep.url}
              className={'px-5 py-3 flex items-start gap-3 hover:bg-secondary/30 transition-colors ' + (isAccessible ? 'bg-red-950/10' : '')}
            >
              <div className="mt-0.5 shrink-0">
                {isChecking
                  ? <Loader2 className="w-4 h-4 text-muted-foreground animate-spin" />
                  : isAccessible
                    ? <ShieldAlert className="w-4 h-4 text-red-400" />
                    : <ShieldCheck className="w-4 h-4 text-emerald-400" />}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <code className="text-xs font-mono font-semibold text-foreground">{ep.name}</code>
                  <span className={'text-xs px-1.5 py-0.5 rounded font-mono border uppercase ' + risk.color + ' ' + risk.bg + ' ' + risk.border}>
                    {ep.risk}
                  </span>
                  {ep.statusCode && (
                    <span className="text-xs font-mono text-muted-foreground/50">HTTP {ep.statusCode}</span>
                  )}
                </div>
                <p className="text-xs text-muted-foreground mt-0.5">{ep.description}</p>
                <code className="text-xs text-muted-foreground/40 font-mono">{path}</code>
              </div>
              <div className={
                'text-xs font-mono px-2 py-0.5 rounded shrink-0 ' +
                (isAccessible ? 'text-red-400 bg-red-400/10' : 'text-emerald-400 bg-emerald-400/10')
              }>
                {isChecking ? '...' : isAccessible ? 'EXPOSED' : 'OK'}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
