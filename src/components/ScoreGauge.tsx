import type { CvssScore } from '@/types/wordpress-audit';

interface Props { score: number; cvss?: CvssScore; }

const palette = (s: number) => s >= 80
  ? { stroke: '#10b981', glow: '#10b98150', label: 'Seguro',     pill: 'rgba(16,185,129,0.12)', pillBorder: 'rgba(16,185,129,0.3)' }
  : s >= 60
  ? { stroke: '#f59e0b', glow: '#f59e0b50', label: 'Moderado',   pill: 'rgba(245,158,11,0.12)', pillBorder: 'rgba(245,158,11,0.3)' }
  : s >= 40
  ? { stroke: '#f97316', glow: '#f9731650', label: 'Vulnerable',  pill: 'rgba(249,115,22,0.12)', pillBorder: 'rgba(249,115,22,0.3)' }
  : { stroke: '#ef4444', glow: '#ef444450', label: 'Crítico',     pill: 'rgba(239,68,68,0.12)',  pillBorder: 'rgba(239,68,68,0.3)' };

const cvssCol = (s: string) => ({ None:'#10b981',Low:'#f59e0b',Medium:'#f97316',High:'#ef4444',Critical:'#dc2626' }[s] || '#ffffff40');

export function ScoreGauge({ score, cvss }: Props) {
  const p = palette(score);
  const R = 52; const C = 2 * Math.PI * R;
  const offset = C - (score / 100) * C;
  return (
    <div className="result-card h-full flex flex-col items-center justify-center gap-5 p-6">
      <span className="mono text-[9px] text-white/25 tracking-widest uppercase">Puntuación de seguridad</span>

      <div style={{ position: 'relative', width: 144, height: 144 }}>
        <svg width="144" height="144" viewBox="0 0 144 144" style={{ transform: 'rotate(-90deg)' }}>
          <circle cx="72" cy="72" r={R} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="9"/>
          <circle cx="72" cy="72" r={R} fill="none" stroke={p.stroke} strokeWidth="9"
            strokeDasharray={C} strokeDashoffset={offset} strokeLinecap="round"
            style={{ transition: 'stroke-dashoffset 1.2s cubic-bezier(.16,1,.3,1)', filter: 'drop-shadow(0 0 10px ' + p.glow + ')' }}/>
        </svg>
        <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
          <span style={{ fontSize: 40, fontWeight: 900, color: p.stroke, lineHeight: 1, letterSpacing: '-2px', fontFamily: 'Inter,sans-serif', textShadow: '0 0 30px ' + p.glow }}>{score}</span>
          <span className="mono text-white/20" style={{ fontSize: 10 }}>/100</span>
        </div>
      </div>

      <div style={{ padding: '4px 18px', borderRadius: 99, background: p.pill, border: '1px solid ' + p.pillBorder, color: p.stroke, fontSize: 12, fontWeight: 700, letterSpacing: '0.02em' }}>{p.label}</div>

      {cvss && (
        <div className="w-full rounded-xl p-4 text-center" style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.06)' }}>
          <div className="mono text-[9px] text-white/20 tracking-widest mb-1">CVSS 3.1</div>
          <div style={{ fontSize: 32, fontWeight: 900, color: cvssCol(cvss.severity), letterSpacing: '-1px', textShadow: '0 0 20px ' + cvssCol(cvss.severity) + '50', lineHeight: 1 }}>{cvss.score.toFixed(1)}</div>
          <div style={{ fontSize: 11, fontWeight: 700, color: cvssCol(cvss.severity), marginTop: 2 }}>{cvss.severity}</div>
          {cvss.vector && <div className="mono text-white/15 mt-2 break-all leading-relaxed" style={{ fontSize: 8 }}>{cvss.vector.replace('CVSS:3.1/','')}</div>}
        </div>
      )}
    </div>
  );
}
