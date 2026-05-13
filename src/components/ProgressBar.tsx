import type { AuditProgress } from '@/lib/wordpress-auditor';

export function ProgressBar({ progress }: { progress:AuditProgress }) {
  return (
    <div className="glass rounded-2xl p-5 mono">
      <div className="flex items-center gap-2 mb-4 text-purple text-[10px] tracking-[2px] uppercase">
        <span className="animate-glow">▶</span> wpsentry scan
      </div>
      <div className="flex justify-between text-[10px] text-white/40 mb-2">
        <span>{progress.step}</span>
        <span className="text-purple font-bold">{progress.percentage}%</span>
      </div>
      <div className="h-1 bg-white/[0.06] rounded-full overflow-visible relative">
        <div className="h-full rounded-full transition-all duration-500 ease-out relative"
          style={{ width:progress.percentage+'%', background:'linear-gradient(90deg,#6d28d9,#8b5cf6)' }}>
          <div className="absolute right-0 top-1/2 -translate-y-1/2 w-3 h-3 rounded-full bg-purple shadow-glow-sm -translate-x-1/2"/>
        </div>
      </div>
      <div className="flex justify-between mt-3">
        {Array.from({length:progress.total},(_,i)=>(
          <div key={i} className={`text-[9px] tracking-wide ${i<progress.current?'text-purple':'text-white/15'}`}>
            {i<progress.current?'[OK]':'[··]'}
          </div>
        ))}
      </div>
    </div>
  );
}
