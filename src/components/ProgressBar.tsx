import type { AuditProgress } from '@/lib/wordpress-auditor';

export function ProgressBar({ progress }: { progress: AuditProgress }) {
  return (
    <div className="glass border border-violet-500/15 rounded-xl p-4 font-mono">
      <div className="flex items-center gap-2 mb-3 text-violet-400">
        <span className="text-xs animate-pulse-dot">▶</span>
        <span className="text-[9px] tracking-[3px] uppercase">wpsentry scan</span>
      </div>
      <div className="flex justify-between text-[10px] mb-2">
        <span className="text-white/30">{progress.step}</span>
        <span className="text-violet-400">{progress.percentage}%</span>
      </div>
      <div className="h-[2px] bg-white/[0.06] rounded-full overflow-visible relative">
        <div className="h-full rounded-full bg-gradient-to-r from-violet-700 to-violet-400 relative transition-all duration-500 ease-out"
          style={{ width: progress.percentage + '%' }}>
          <div className="absolute -right-[3px] top-1/2 -translate-y-1/2 w-[6px] h-[6px] rounded-full bg-violet-400 shadow-[0_0_8px_#8b5cf6]"/>
        </div>
      </div>
      <div className="flex justify-between mt-3">
        {Array.from({ length: progress.total }, (_, i) => (
          <span key={i} className={'text-[9px] tracking-[1px] ' + (i < progress.current ? 'text-violet-400' : 'text-white/15')}>
            {i < progress.current ? '[OK]' : '[··]'}
          </span>
        ))}
      </div>
    </div>
  );
}
