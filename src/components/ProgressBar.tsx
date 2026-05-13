import type { AuditProgress } from '@/lib/wordpress-auditor';

interface ProgressBarProps { progress: AuditProgress; }

export function ProgressBar({ progress }: ProgressBarProps) {
  return (
    <div style={{ margin: '20px 0', padding: '16px 20px', background: '#0a0a16', border: '1px solid #8b5cf620', borderRadius: '10px', fontFamily: 'JetBrains Mono, monospace' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '12px', fontSize: '10px', color: '#8b5cf6' }}>
        <span style={{ animation: 'blink 1s ease-in-out infinite' }}>▶</span>
        <span style={{ letterSpacing: '2px', textTransform: 'uppercase', fontSize: '9px' }}>wpsentry scan</span>
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10px', color: '#ffffff30', marginBottom: '6px' }}>
        <span>{progress.step}</span>
        <span style={{ color: '#8b5cf6' }}>{progress.percentage}%</span>
      </div>
      <div style={{ height: '2px', background: '#ffffff06', borderRadius: '1px', overflow: 'visible', position: 'relative' }}>
        <div style={{ height: '100%', width: progress.percentage + '%', background: 'linear-gradient(90deg,#6d28d9,#8b5cf6)', borderRadius: '1px', transition: 'width .5s ease', position: 'relative' }}>
          <div style={{ position: 'absolute', right: '-2px', top: '50%', transform: 'translateY(-50%)', width: '5px', height: '5px', borderRadius: '50%', background: '#8b5cf6', boxShadow: '0 0 8px #8b5cf6' }}/>
        </div>
      </div>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '10px' }}>
        {Array.from({ length: progress.total }, (_, i) => (
          <div key={i} style={{ fontSize: '9px', color: i < progress.current ? '#8b5cf6' : '#ffffff15', letterSpacing: '1px' }}>
            {i < progress.current ? '[OK]' : '[··]'}
          </div>
        ))}
      </div>
    </div>
  );
}
