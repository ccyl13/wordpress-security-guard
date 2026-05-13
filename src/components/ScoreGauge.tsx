import type { CvssScore } from '@/types/wordpress-audit';

interface ScoreGaugeProps {
  score: number;
  cvss?: CvssScore;
}

function getScoreColor(score: number) {
  if (score >= 80) return { text: 'text-emerald-400', stroke: '#34d399', label: 'Seguro', bg: 'bg-emerald-400/10 border-emerald-400/20' };
  if (score >= 60) return { text: 'text-yellow-400', stroke: '#facc15', label: 'Moderado', bg: 'bg-yellow-400/10 border-yellow-400/20' };
  if (score >= 40) return { text: 'text-orange-400', stroke: '#fb923c', label: 'Vulnerable', bg: 'bg-orange-400/10 border-orange-400/20' };
  return { text: 'text-red-400', stroke: '#f87171', label: 'Critico', bg: 'bg-red-400/10 border-red-400/20' };
}

function getCvssColor(severity: string) {
  const map: Record<string, string> = {
    None: 'text-emerald-400', Low: 'text-yellow-300',
    Medium: 'text-orange-400', High: 'text-red-400', Critical: 'text-red-600',
  };
  return map[severity] || 'text-muted-foreground';
}

export function ScoreGauge({ score, cvss }: ScoreGaugeProps) {
  const { text, stroke, label, bg } = getScoreColor(score);
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className="rounded-xl bg-card border border-border p-6 flex flex-col items-center h-full justify-center gap-4">
      <p className="text-xs font-mono text-muted-foreground uppercase tracking-wider">Puntuacion de seguridad</p>

      <div className="relative w-40 h-40">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 120 120">
          <circle cx="60" cy="60" r={radius} fill="none" stroke="hsl(var(--border))" strokeWidth="10" />
          <circle
            cx="60" cy="60" r={radius}
            fill="none"
            stroke={stroke}
            strokeWidth="10"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            style={{ transition: 'stroke-dashoffset 1s cubic-bezier(.4,0,.2,1)', filter: 'drop-shadow(0 0 8px ' + stroke + '66)' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={"text-4xl font-black tabular-nums " + text}>{score}</span>
          <span className="text-xs text-muted-foreground font-mono">/100</span>
        </div>
      </div>

      <div className={"px-4 py-1.5 rounded-full border text-sm font-semibold " + bg + " " + text}>
        {label}
      </div>

      {cvss && (
        <div className="w-full rounded-lg bg-secondary/50 border border-border p-3 text-center">
          <p className="text-xs text-muted-foreground font-mono mb-1">CVSS 3.1</p>
          <p className={"text-2xl font-black tabular-nums " + getCvssColor(cvss.severity)}>{cvss.score.toFixed(1)}</p>
          <p className={"text-xs font-semibold " + getCvssColor(cvss.severity)}>{cvss.severity}</p>
          {cvss.vector && (
            <p className="text-xs text-muted-foreground/60 font-mono mt-1 break-all leading-tight">{cvss.vector.replace('CVSS:3.1/', '')}</p>
          )}
        </div>
      )}
    </div>
  );
}
