import type { AuditProgress } from '@/lib/wordpress-auditor';

export function ProgressBar({ progress }: { progress: AuditProgress }) {
  return (
    <div className="rounded-2xl p-5" style={{ background: 'rgba(139,92,246,0.06)', border: '1px solid rgba(139,92,246,0.15)' }}>
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <div className="w-1.5 h-1.5 rounded-full bg-purple-400" style={{ animation: 'blink 1s ease-in-out infinite', boxShadow: '0 0 6px #a78bfa' }}/>
          <span className="mono text-white/40 tracking-widest uppercase" style={{ fontSize: 9 }}>wpsentry scan</span>
        </div>
        <span className="mono font-bold" style={{ fontSize: 11, color: '#a78bfa' }}>{progress.percentage}%</span>
      </div>
      <p className="mono text-white/30 mb-3" style={{ fontSize: 10 }}>{progress.step}</p>
      <div className="scan-bar-track">
        <div className="scan-bar-fill" style={{ width: progress.percentage + '%' }}/>
      </div>
      <div className="flex justify-between mt-3">
        {Array.from({ length: progress.total }, (_, i) => (
          <span key={i} className="mono" style={{ fontSize: 9, color: i < progress.current ? '#a78bfa' : 'rgba(255,255,255,0.1)' }}>
            {i < progress.current ? '[OK]' : '[··]'}
          </span>
        ))}
      </div>
    </div>
  );
}
