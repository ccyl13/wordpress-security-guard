import type { CvssScore } from '@/types/wordpress-audit';

const scoreStyle = (s: number) => {
  if (s >= 80) return { stroke: '#10b981', glow: '#10b98150', label: 'Seguro',    bg: 'rgba(16,185,129,0.08)',  border: 'rgba(16,185,129,0.25)',  text: '#34d399' };
  if (s >= 60) return { stroke: '#f59e0b', glow: '#f59e0b50', label: 'Moderado',  bg: 'rgba(245,158,11,0.08)',  border: 'rgba(245,158,11,0.25)',  text: '#fbbf24' };
  if (s >= 40) return { stroke: '#f97316', glow: '#f9731650', label: 'Vulnerable', bg: 'rgba(249,115,22,0.08)',  border: 'rgba(249,115,22,0.25)',  text: '#fb923c' };
  return          { stroke: '#ef4444', glow: '#ef444450', label: 'Crítico',   bg: 'rgba(239,68,68,0.08)',   border: 'rgba(239,68,68,0.25)',   text: '#f87171' };
};
const cvssCol = (s: string) => ({ None:'#34d399',Low:'#fbbf24',Medium:'#fb923c',High:'#f87171',Critical:'#ef4444' }[s]||'rgba(255,255,255,0.4)');

export function ScoreGauge({ score, cvss }: { score: number; cvss?: CvssScore }) {
  const c = scoreStyle(score);
  const R = 52; const circ = 2 * Math.PI * R;
  const off = circ - (score / 100) * circ;
  return (
    <div className="result-card" style={{ display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center', gap:'16px', padding:'28px 20px', height:'100%' }}>
      <span style={{ fontSize:'10px', fontWeight:600, letterSpacing:'.1em', textTransform:'uppercase', color:'rgba(255,255,255,0.3)' }}>Puntuación de seguridad</span>
      <div style={{ position:'relative', width:'140px', height:'140px' }}>
        <svg width="140" height="140" viewBox="0 0 140 140" style={{ transform:'rotate(-90deg)' }}>
          <circle cx="70" cy="70" r={R} fill="none" stroke="rgba(255,255,255,0.05)" strokeWidth="10"/>
          <circle cx="70" cy="70" r={R} fill="none" stroke={c.stroke} strokeWidth="10"
            strokeDasharray={circ} strokeDashoffset={off} strokeLinecap="round"
            style={{ transition:'stroke-dashoffset 1.2s cubic-bezier(.4,0,.2,1)', filter:'drop-shadow(0 0 10px '+c.glow+')'}}/>
        </svg>
        <div style={{ position:'absolute', inset:0, display:'flex', flexDirection:'column', alignItems:'center', justifyContent:'center' }}>
          <span style={{ fontSize:'40px', fontWeight:900, color:c.text, lineHeight:1, letterSpacing:'-2px', fontFamily:"'Inter',sans-serif", textShadow:'0 0 30px '+c.glow }}>{score}</span>
          <span style={{ fontSize:'11px', color:'rgba(255,255,255,0.2)', fontFamily:'JetBrains Mono,monospace' }}>/100</span>
        </div>
      </div>
      <div style={{ padding:'5px 18px', borderRadius:'99px', background:c.bg, border:'1px solid '+c.border, color:c.text, fontSize:'13px', fontWeight:600 }}>{c.label}</div>
      {cvss && (
        <div style={{ width:'100%', background:'rgba(255,255,255,0.03)', border:'1px solid rgba(255,255,255,0.06)', borderRadius:'10px', padding:'14px', textAlign:'center' }}>
          <div style={{ fontSize:'9px', fontFamily:'JetBrains Mono,monospace', color:'rgba(255,255,255,0.2)', letterSpacing:'2px', marginBottom:'6px' }}>CVSS 3.1</div>
          <div style={{ fontSize:'30px', fontWeight:900, color:cvssCol(cvss.severity), fontFamily:"'Inter',sans-serif", letterSpacing:'-1px', lineHeight:1, textShadow:'0 0 20px '+cvssCol(cvss.severity)+'60' }}>{cvss.score.toFixed(1)}</div>
          <div style={{ fontSize:'12px', fontWeight:600, color:cvssCol(cvss.severity), marginTop:'4px' }}>{cvss.severity}</div>
          {cvss.vector && <div style={{ fontSize:'8px', fontFamily:'JetBrains Mono,monospace', color:'rgba(255,255,255,0.15)', marginTop:'8px', wordBreak:'break-all', lineHeight:1.5 }}>{cvss.vector.replace('CVSS:3.1/','')}</div>}
        </div>
      )}
    </div>
  );
}
