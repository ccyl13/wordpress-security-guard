import { cn } from '@/lib/utils';

interface ScoreGaugeProps {
  score: number;
}

export function ScoreGauge({ score }: ScoreGaugeProps) {
  const getScoreColor = () => {
    if (score >= 80) return 'text-green-400';
    if (score >= 60) return 'text-yellow-400';
    if (score >= 40) return 'text-orange-400';
    return 'text-red-400';
  };

  const getScoreLabel = () => {
    if (score >= 80) return 'Seguro';
    if (score >= 60) return 'Aceptable';
    if (score >= 40) return 'Mejorable';
    return 'Crítico';
  };

  const getScoreBg = () => {
    if (score >= 80) return 'from-green-500/20 to-green-500/5';
    if (score >= 60) return 'from-yellow-500/20 to-yellow-500/5';
    if (score >= 40) return 'from-orange-500/20 to-orange-500/5';
    return 'from-red-500/20 to-red-500/5';
  };

  const circumference = 2 * Math.PI * 45;
  const strokeDashoffset = circumference - (score / 100) * circumference;

  return (
    <div className={cn("relative p-8 rounded-2xl bg-gradient-to-br", getScoreBg())}>
      <div className="flex items-center justify-center">
        <svg className="w-40 h-40 transform -rotate-90">
          <circle
            cx="80"
            cy="80"
            r="45"
            stroke="currentColor"
            strokeWidth="8"
            fill="none"
            className="text-muted/30"
          />
          <circle
            cx="80"
            cy="80"
            r="45"
            stroke="currentColor"
            strokeWidth="8"
            fill="none"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            className={cn("transition-all duration-1000 ease-out", getScoreColor())}
          />
        </svg>
        <div className="absolute flex flex-col items-center">
          <span className={cn("text-5xl font-black", getScoreColor())}>{score}</span>
          <span className="text-sm text-muted-foreground font-medium">/100</span>
        </div>
      </div>
      <p className={cn("text-center mt-4 text-xl font-bold", getScoreColor())}>
        {getScoreLabel()}
      </p>
    </div>
  );
}
