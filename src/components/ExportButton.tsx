import { Button } from '@/components/ui/button';
import { Download, FileJson } from 'lucide-react';
import type { AuditResult } from '@/types/wordpress-audit';

interface ExportButtonProps {
  result: AuditResult;
}

export function ExportButton({ result }: ExportButtonProps) {
  const handleExport = () => {
    const exportData = {
      tool: 'WPSentry',
      version: '2.0',
      exportedAt: new Date().toISOString(),
      ...result,
    };
    const json = JSON.stringify(exportData, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const hostname = new URL(result.url).hostname.replace(/[^a-z0-9]/gi, '-');
    a.href = url;
    a.download = 'wpsentry-' + hostname + '-' + new Date().toISOString().split('T')[0] + '.json';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <Button
      onClick={handleExport}
      variant="outline"
      className="border-primary/20 text-primary hover:bg-primary/10 hover:border-primary/40 font-mono text-sm gap-2"
    >
      <FileJson className="w-4 h-4" />
      Exportar JSON
      <Download className="w-3 h-3 opacity-60" />
    </Button>
  );
}
