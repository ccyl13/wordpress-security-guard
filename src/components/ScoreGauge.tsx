import type { CvssScore } from '@/types/wordpress-audit';

interface ScoreGaugeProps { score: number; cvss?: CvssScore; }

function cfg(score: number) {
  if (score >= 80) return { stroke: '#10b981', glow: '#10b98160', label: 'Seguro',    labelBg: '#10b98118', labelColor: '#10b981', labelBorder: '#10b98140' };
  if (score >= 60) return { stroke: '#f59e0b', glow: '#f59e0b60', label: 'Moderado',  labelBg: '#f59e0b18', labelColor: '#f59e0b', labelBorder: '#f59e0b40' };
  if (score >= 40) return { stroke: '#f97316', glow: '#f9731660', label: 'Vulnerable', labelBg: '#f9731618', labelColor: '#f97316', labelBorder: '#f9731640' };
  return           { stroke: '#ef4444', glow: '#ef444460', label: 'Critico',    labelBg: '#ef444418', labelColor: '#ef4444', labelBorder: '#ef444440' };
}

function cvssColor(s: string) {
  return { None:'#10b981', Low:'#f59e0b', Medium:'#f97316', High:'#ef4444', Critical:'#dc2626' }[s] || '#ffffff60';
}

export function ScoreGauge({ score, cvss }: ScoreGaugeProps) {
  const c = cfg(score);
  const R = 54; const circ = 2 * Math.PI * R;
  const offset = circ - (score / 100) * circ;

  return (
    <div style={{ background: '#08080f', border: '1px solid #ffffff0a', borderRadius: '12px', padding: '24px 20px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '14px', height: '100%', justifyContent: 'center' }}>
      <span style={{ fontSize: '9px', fontFamily: 'JetBrains Mono,monospace', color: '#ffffff30', letterSpacing: '2px', textTransform: 'uppercase' }}>Puntuacion de seguridad</span>

      <div style={{ position: 'relative', width: '148px', height: '148px' }}>
        <svg width="148" height="148" viewBox="0 0 148 148" style={{ transform: 'rotate(-90deg)' }}>
          <circle cx="74" cy="74" r={R} fill="none" stroke="#ffffff08" strokeWidth="10"/>
          <circle cx="74" cy="74" r={R} fill="none" stroke={c.stroke} strokeWidth="10"
            strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
            style={{ transition: 'stroke-dashoffset 1.2s cubic-bezier(.4,0,.2,1)', filter: 'drop-shadow(0 0 8px ' + c.glow + ')' }}/>
        </svg>
        <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
          <span style={{ fontSize: '42px', fontWeight: 800, color: c.stroke, lineHeight: 1, letterSpacing: '-2px', fontFamily: "'Space Grotesk',sans-serif", textShadow: '0 0 30px ' + c.glow }}>{score}</span>
          <span style={{ fontSize: '10px', color: '#ffffff25', fontFamily: 'JetBrains Mono,monospace' }}>/100</span>
        </div>
      </div>

      <div style={{ padding: '5px 16px', borderRadius: '99px', background: c.labelBg, border: '1px solid ' + c.labelBorder, color: c.labelColor, fontSize: '12px', fontWeight: 700, letterSpacing: '.3px' }}>
        {c.label}
      </div>

      {cvss && (
        <div style={{ width: '100%', background: '#0d0d1e', border: '1px solid #ffffff08', borderRadius: '8px', padding: '12px', textAlign: 'center' }}>
          <div style={{ fontSize: '9px', fontFamily: 'JetBrains Mono,monospace', color: '#ffffff25', letterSpacing: '2px', marginBottom: '4px' }}>CVSS 3.1</div>
          <div style={{ fontSize: '28px', fontWeight: 800, color: cvssColor(cvss.severity), fontFamily: "'Space Grotesk',sans-serif", letterSpacing: '-1px', textShadow: '0 0 20px ' + cvssColor(cvss.severity) + '60', lineHeight: 1 }}>{cvss.score.toFixed(1)}</div>
          <div style={{ fontSize: '11px', fontWeight: 700, color: cvssColor(cvss.severity), marginTop: '2px' }}>{cvss.severity}</div>
          {cvss.vector && (
            <div style={{ fontSize: '8px', fontFamily: 'JetBrains Mono,monospace', color: '#ffffff18', marginTop: '6px', wordBreak: 'break-all', lineHeight: 1.4 }}>{cvss.vector.replace('CVSS:3.1/','')}</div>
          )}
        </div>
      )}
    </div>
  );
}
