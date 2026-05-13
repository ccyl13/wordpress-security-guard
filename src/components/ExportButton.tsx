import { Download } from 'lucide-react';
import type { AuditResult } from '@/types/wordpress-audit';

export function ExportButton({ result }: { result:AuditResult }) {
  const handle = () => {
    const blob = new Blob([JSON.stringify({ tool:'WPSentry', version:'2.0', exportedAt:new Date().toISOString(), ...result },null,2)], { type:'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const host = new URL(result.url).hostname.replace(/[^a-z0-9]/gi,'-');
    a.href=url; a.download='wpsentry-'+host+'-'+new Date().toISOString().split('T')[0]+'.json';
    document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(url);
  };
  return (
    <button onClick={handle}
      className="flex items-center gap-2 px-4 py-2 rounded-xl glass border border-purple/20 hover:border-purple/40 mono text-[11px] text-purple hover:text-purple-light transition-all duration-200 hover:-translate-y-0.5 font-semibold">
      <Download size={13}/>
      Exportar JSON
    </button>
  );
}
