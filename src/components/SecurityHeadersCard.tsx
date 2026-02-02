import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Shield, ShieldCheck, ShieldAlert, ShieldX, Info } from 'lucide-react';
import { cn } from '@/lib/utils';
import type { SecurityHeader } from '@/types/wordpress-audit';
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from '@/components/ui/tooltip';
import { SecurityReferenceBadges } from './SecurityReferenceBadges';

interface SecurityHeadersCardProps {
  headers: SecurityHeader[];
}

export function SecurityHeadersCard({ headers }: SecurityHeadersCardProps) {
  const getStatusIcon = (status: SecurityHeader['status']) => {
    switch (status) {
      case 'secure':
        return <ShieldCheck className="w-5 h-5 text-green-400" />;
      case 'warning':
        return <ShieldAlert className="w-5 h-5 text-yellow-400" />;
      case 'vulnerable':
        return <ShieldX className="w-5 h-5 text-red-400" />;
      default:
        return <Shield className="w-5 h-5 text-muted-foreground" />;
    }
  };

  const getStatusBg = (status: SecurityHeader['status']) => {
    switch (status) {
      case 'secure':
        return 'bg-green-500/10 border-green-500/20';
      case 'warning':
        return 'bg-yellow-500/10 border-yellow-500/20';
      case 'vulnerable':
        return 'bg-red-500/10 border-red-500/20';
      default:
        return 'bg-muted/50 border-muted';
    }
  };

  const secureCount = headers.filter(h => h.status === 'secure').length;
  const warningCount = headers.filter(h => h.status === 'warning').length;
  const vulnerableCount = headers.filter(h => h.status === 'vulnerable').length;

  return (
    <Card className="bg-card border-border">
      <CardHeader className="pb-4">
        <CardTitle className="flex items-center gap-3 text-xl">
          <Shield className="w-6 h-6 text-primary" />
          Cabeceras de Seguridad
          <div className="flex gap-2 ml-auto text-sm font-normal">
            <span className="text-green-400">{secureCount} ✓</span>
            <span className="text-yellow-400">{warningCount} ⚠</span>
            <span className="text-red-400">{vulnerableCount} ✗</span>
          </div>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        {headers.map((header) => (
          <div
            key={header.name}
            className={cn(
              "flex flex-col p-3 rounded-lg border transition-colors",
              getStatusBg(header.status)
            )}
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                {getStatusIcon(header.status)}
                <span className="font-mono text-sm">{header.name}</span>
                <Tooltip>
                  <TooltipTrigger>
                    <Info className="w-4 h-4 text-muted-foreground hover:text-foreground" />
                  </TooltipTrigger>
                  <TooltipContent className="max-w-xs">
                    <p>{header.description}</p>
                  </TooltipContent>
                </Tooltip>
              </div>
              <div className="text-right">
                {header.value ? (
                  <code className="text-xs text-muted-foreground bg-background/50 px-2 py-1 rounded max-w-[200px] truncate block">
                    {header.value.length > 40 ? header.value.slice(0, 40) + '...' : header.value}
                  </code>
                ) : (
                  <span className="text-xs text-red-400">No configurada</span>
                )}
              </div>
            </div>
            {header.reference && (
              <div className="ml-8">
                <SecurityReferenceBadges reference={header.reference} compact />
              </div>
            )}
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
