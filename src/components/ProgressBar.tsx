import type { AuditProgress } from '@/lib/wordpress-auditor';
import { Terminal } from 'lucide-react';

interface ProgressBarProps {
  progress: AuditProgress;
}

export function ProgressBar({ progress }: ProgressBarProps) {
  return (
    <div className="mt-8 max-w-xl mx-auto rounded-xl bg-card border border-primary/20 p-5 font-mono text-sm">
      <div className="flex items-center gap-2 mb-4 text-primary">
        <Terminal className="w-4 h-4" />
        <span className="text-xs uppercase tracking-widest">wpsentry scan</span>
      </div>
      <div className="flex items-center justify-between mb-2">
        <span className="text-muted-foreground text-xs">{progress.step}</span>
        <span className="text-primary text-xs">{progress.percentage}%</span>
      </div>
      <div className="h-1.5 w-full rounded-full bg-secondary overflow-hidden">
        <div
          className="h-full rounded-full bg-primary transition-all duration-500 ease-out"
          style={{ width: progress.percentage + '%', boxShadow: '0 0 10px hsl(var(--primary) / 0.6)' }}
        />
      </div>
      <div className="flex justify-between mt-3">
        {Array.from({ length: progress.total }, (_, i) => (
          <div
            key={i}
            className={"flex-1 text-center text-xs " + (i < progress.current ? 'text-primary' : 'text-muted-foreground/30')}
          >
            {i < progress.current ? '[OK]' : '[--]'}
          </div>
        ))}
      </div>
    </div>
  );
}
