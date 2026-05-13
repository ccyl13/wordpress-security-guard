import type { AuditResult } from '@/types/wordpress-audit';
import { Download } from 'lucide-react';

export function ExportButton({ result }: { result: AuditResult }) {
  const handle = () => {
    const json = JSON.stringify({ tool: 'WPSentry', version: '2.0', exportedAt: new Date().toISOString(), ...result }, null, 2);
    const a = Object.assign(document.createElement('a'), {
      href: URL.createObjectURL(new Blob([json], { type: 'application/json' })),
      download: 'wpsentry-' + new URL(result.url).hostname.replace(/[^a-z0-9]/gi,'-') + '-' + new Date().toISOString().split('T')[0] + '.json',
    });
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
  };
  return (
    <button onClick={handle}
      className="flex items-center gap-2 px-4 py-2 rounded-lg glass border border-white/[0.08] text-sm font-mono text-white/50 hover:text-violet-400 hover:border-violet-500/30 hover:bg-violet-500/5 transition-all">
      <Download size={13}/>
      Exportar JSON
    </button>
  );
}
