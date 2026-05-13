import type { SecurityHeader } from '@/types/wordpress-audit';
import { CheckCircle2, XCircle, AlertTriangle, Shield, ExternalLink } from 'lucide-react';

interface SecurityHeadersCardProps {
  headers: SecurityHeader[];
}

const STATUS_CONFIG = {
  secure:     { icon: CheckCircle2, color: 'text-emerald-400', bg: 'bg-emerald-400/10', border: 'border-emerald-400/20', label: 'OK' },
  warning:    { icon: AlertTriangle, color: 'text-yellow-400', bg: 'bg-yellow-400/10', border: 'border-yellow-400/20', label: 'Warn' },
  vulnerable: { icon: XCircle, color: 'text-red-400', bg: 'bg-red-400/10', border: 'border-red-400/20', label: 'Fail' },
  info:       { icon: Shield, color: 'text-blue-400', bg: 'bg-blue-400/10', border: 'border-blue-400/20', label: 'Info' },
};

export function SecurityHeadersCard({ headers }: SecurityHeadersCardProps) {
  const counts = {
    secure: headers.filter(h => h.status === 'secure').length,
    warning: headers.filter(h => h.status === 'warning').length,
    vulnerable: headers.filter(h => h.status === 'vulnerable').length,
  };

  return (
    <div className="rounded-xl bg-card border border-border overflow-hidden">
      <div className="px-5 py-4 border-b border-border flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-primary" />
          <h3 className="font-semibold text-sm">Cabeceras HTTP</h3>
        </div>
        <div className="flex items-center gap-2 text-xs font-mono">
          <span className="text-emerald-400">{counts.secure} ok</span>
          <span className="text-muted-foreground/40">|</span>
          <span className="text-yellow-400">{counts.warning} warn</span>
          <span className="text-muted-foreground/40">|</span>
          <span className="text-red-400">{counts.vulnerable} fail</span>
        </div>
      </div>
      <div className="divide-y divide-border">
        {headers.map((header) => {
          const cfg = STATUS_CONFIG[header.status] || STATUS_CONFIG.info;
          const Icon = cfg.icon;
          return (
            <div key={header.name} className="px-5 py-3 flex items-start gap-3 hover:bg-secondary/30 transition-colors">
              <Icon className={"w-4 h-4 mt-0.5 shrink-0 " + cfg.color} />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <code className="text-xs font-mono font-semibold text-foreground">{header.name}</code>
                  <span className={"text-xs px-1.5 py-0.5 rounded font-mono border " + cfg.bg + " " + cfg.color + " " + cfg.border}>
                    {cfg.label}
                  </span>
                  {header.reference?.cvss && (
                    <span className="text-xs text-muted-foreground font-mono">
                      CVSS {header.reference.cvss.score.toFixed(1)}
                    </span>
                  )}
                </div>
                <p className="text-xs text-muted-foreground mt-0.5 truncate">{header.description}</p>
                {header.value && header.status !== 'vulnerable' && (
                  <p className="text-xs font-mono text-muted-foreground/50 mt-0.5 truncate">{header.value.substring(0, 60)}{header.value.length > 60 ? '...' : ''}</p>
                )}
                {header.reference?.owasp && (
                  <p className="text-xs text-muted-foreground/40 font-mono mt-0.5">{header.reference.owasp}</p>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
