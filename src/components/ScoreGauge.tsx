import type { CvssScore } from '@/types/wordpress-audit';

interface ScoreGaugeProps { score: number; cvss?: CvssScore; }

function cfg(s: number) {
  if (s >= 80) return { stroke:'#10b981', glow:'#10b98150', label:'Seguro',     pill:'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' };
  if (s >= 60) return { stroke:'#f59e0b', glow:'#f59e0b50', label:'Moderado',   pill:'bg-amber-500/10 text-amber-400 border-amber-500/20' };
  if (s >= 40) return { stroke:'#f97316', glow:'#f9731650', label:'Vulnerable',  pill:'bg-orange-500/10 text-orange-400 border-orange-500/20' };
  return             { stroke:'#ef4444', glow:'#ef444450', label:'Crítico',     pill:'bg-red-500/10 text-red-400 border-red-500/20' };
}
function cvssCol(s: string) {
  return ({None:'#10b981',Low:'#f59e0b',Medium:'#f97316',High:'#ef4444',Critical:'#dc2626'} as any)[s] || '#ffffff50';
}

export function ScoreGauge({ score, cvss }: ScoreGaugeProps) {
  const c = cfg(score);
  const R = 54; const circ = 2 * Math.PI * R;
  const offset = circ - (score / 100) * circ;
  return (
    <div className="glass rounded-2xl p-6 flex flex-col items-center gap-4 h-full justify-center">
      <span className="mono text-[9px] text-white/30 tracking-[2px] uppercase">Puntuación de seguridad</span>
      <div className="relative w-36 h-36">
        <svg width="144" height="144" viewBox="0 0 144 144" className="rotate-[-90deg]">
          <circle cx="72" cy="72" r={R} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="10"/>
          <circle cx="72" cy="72" r={R} fill="none" stroke={c.stroke} strokeWidth="10"
            strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
            style={{ transition:'stroke-dashoffset 1.2s cubic-bezier(.4,0,.2,1)', filter:'drop-shadow(0 0 10px '+c.glow+')' }}/>
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-extrabold leading-none tracking-tight" style={{ fontSize:'40px', color:c.stroke, textShadow:'0 0 30px '+c.glow, fontFamily:"'Space Grotesk',sans-serif" }}>{score}</span>
          <span className="mono text-[10px] text-white/20">/100</span>
        </div>
      </div>
      <div className={`px-4 py-1.5 rounded-full border text-xs font-bold tracking-wide ${c.pill}`}>{c.label}</div>
      {cvss && (
        <div className="w-full glass rounded-xl p-3 text-center">
          <div className="mono text-[8px] text-white/20 tracking-[2px] uppercase mb-1">CVSS 3.1</div>
          <div className="font-extrabold text-2xl tracking-tight" style={{ color:cvssCol(cvss.severity), textShadow:'0 0 20px '+cvssCol(cvss.severity)+'50', fontFamily:"'Space Grotesk',sans-serif" }}>{cvss.score.toFixed(1)}</div>
          <div className="text-xs font-bold mt-0.5" style={{ color:cvssCol(cvss.severity) }}>{cvss.severity}</div>
          {cvss.vector && <div className="mono text-[7.5px] text-white/15 mt-2 break-all leading-snug">{cvss.vector.replace('CVSS:3.1/','')}</div>}
        </div>
      )}
    </div>
  );
}
