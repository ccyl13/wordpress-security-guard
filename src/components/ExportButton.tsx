import { Download } from 'lucide-react';
import type { AuditResult } from '@/types/wordpress-audit';

export function ExportButton({ result }: { result: AuditResult }) {
  const handle = () => {
    const data = JSON.stringify({ tool: 'WPSentry', version: '2.0', exportedAt: new Date().toISOString(), ...result }, null, 2);
    const a = document.createElement('a');
    const host = new URL(result.url).hostname.replace(/[^a-z0-9]/gi, '-');
    a.href = URL.createObjectURL(new Blob([data], { type: 'application/json' }));
    a.download = 'wpsentry-' + host + '-' + new Date().toISOString().split('T')[0] + '.json';
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
  };
  return (
    <button onClick={handle}
      className='flex items-center gap-2 px-4 py-2 rounded-xl mono font-medium transition-all duration-200'
      style={{ fontSize: 12, color: 'rgba(139,92,246,0.8)', background: 'rgba(139,92,246,0.08)', border: '1px solid rgba(139,92,246,0.2)' }}
      onMouseEnter={e => { e.currentTarget.style.background='rgba(139,92,246,0.15)'; e.currentTarget.style.borderColor='rgba(139,92,246,0.4)'; }}
      onMouseLeave={e => { e.currentTarget.style.background='rgba(139,92,246,0.08)'; e.currentTarget.style.borderColor='rgba(139,92,246,0.2)'; }}>
      <Download size={12}/>Exportar JSON
    </button>
  );
}