import { Progress } from '@/components/ui/progress';
import type { AuditProgress } from '@/lib/wordpress-auditor';

interface ProgressBarProps {
  progress: AuditProgress;
}

export function ProgressBar({ progress }: ProgressBarProps) {
  return (
    <div className="w-full max-w-md mx-auto mt-6 space-y-2 animate-fade-in">
      <div className="flex justify-between text-sm">
        <span className="text-muted-foreground">{progress.step}</span>
        <span className="text-primary font-mono">{progress.percentage}%</span>
      </div>
      <Progress value={progress.percentage} className="h-2" />
      <p className="text-xs text-center text-muted-foreground">
        Paso {progress.current} de {progress.total}
      </p>
    </div>
  );
}
