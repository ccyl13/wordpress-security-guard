import { Badge } from '@/components/ui/badge';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import type { SecurityReference, CvssScore } from '@/types/wordpress-audit';
import { getCvssColor } from '@/types/wordpress-audit';
import { cn } from '@/lib/utils';

interface SecurityReferenceBadgesProps {
  reference?: SecurityReference;
  compact?: boolean;
}

export function SecurityReferenceBadges({ reference, compact = false }: SecurityReferenceBadgesProps) {
  if (!reference) return null;

  return (
    <TooltipProvider>
      <div className={cn("flex flex-wrap gap-1", compact ? "mt-1" : "mt-2")}>
        {reference.owasp && (
          <Tooltip>
            <TooltipTrigger asChild>
              <Badge 
                variant="outline" 
                className={cn(
                  "text-[10px] font-mono cursor-help",
                  compact ? "px-1 py-0" : "px-1.5 py-0.5"
                )}
              >
                {compact ? reference.owasp.split('-')[0] : reference.owasp.split('-')[0]}
              </Badge>
            </TooltipTrigger>
            <TooltipContent side="top" className="max-w-xs">
              <p className="font-semibold">{reference.owasp}</p>
              <p className="text-xs text-muted-foreground mt-1">OWASP Top 10 2021</p>
            </TooltipContent>
          </Tooltip>
        )}
        
        {reference.cwe && (
          <Tooltip>
            <TooltipTrigger asChild>
              <Badge 
                variant="outline" 
                className={cn(
                  "text-[10px] font-mono cursor-help",
                  compact ? "px-1 py-0" : "px-1.5 py-0.5"
                )}
              >
                {reference.cwe}
              </Badge>
            </TooltipTrigger>
            <TooltipContent side="top">
              <p className="font-semibold">{reference.cwe}</p>
              <p className="text-xs text-muted-foreground mt-1">Common Weakness Enumeration</p>
            </TooltipContent>
          </Tooltip>
        )}
        
        {reference.cvss && (
          <CvssBadge cvss={reference.cvss} compact={compact} />
        )}
      </div>
    </TooltipProvider>
  );
}

interface CvssBadgeProps {
  cvss: CvssScore;
  compact?: boolean;
}

export function CvssBadge({ cvss, compact = false }: CvssBadgeProps) {
  return (
    <TooltipProvider>
      <Tooltip>
        <TooltipTrigger asChild>
          <Badge 
            className={cn(
              "text-[10px] font-mono cursor-help border-0",
              getCvssColor(cvss.severity),
              compact ? "px-1 py-0" : "px-1.5 py-0.5"
            )}
          >
            CVSS {cvss.score.toFixed(1)}
          </Badge>
        </TooltipTrigger>
        <TooltipContent side="top" className="max-w-sm">
          <div className="space-y-1">
            <p className="font-semibold">CVSS 3.1 Base Score: {cvss.score.toFixed(1)}</p>
            <p className={cn("text-sm font-medium", getCvssColor(cvss.severity).split(' ')[0])}>
              Severidad: {cvss.severity}
            </p>
            <p className="text-xs text-muted-foreground font-mono break-all">
              {cvss.vector}
            </p>
          </div>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}

interface OverallCvssCardProps {
  cvss: CvssScore;
}

export function OverallCvssCard({ cvss }: OverallCvssCardProps) {
  return (
    <div className={cn(
      "rounded-lg p-4 text-center",
      getCvssColor(cvss.severity)
    )}>
      <p className="text-xs font-medium uppercase tracking-wider opacity-80">CVSS Overall</p>
      <p className="text-3xl font-black mt-1">{cvss.score.toFixed(1)}</p>
      <p className="text-sm font-semibold">{cvss.severity}</p>
    </div>
  );
}
