import { Button } from '@/components/ui/button';
import { Download } from 'lucide-react';
import type { AuditResult } from '@/types/wordpress-audit';
import { useToast } from '@/hooks/use-toast';

interface ExportButtonProps {
  result: AuditResult;
}

export function ExportButton({ result }: ExportButtonProps) {
  const { toast } = useToast();

  const handleExport = () => {
    const exportData = {
      ...result,
      timestamp: result.timestamp.toISOString(),
      exportedAt: new Date().toISOString(),
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], {
      type: 'application/json',
    });

    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `wp-audit-${new URL(result.url).hostname}-${Date.now()}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    toast({
      title: 'Exportado',
      description: 'El informe se ha descargado correctamente',
    });
  };

  return (
    <Button
      variant="outline"
      size="sm"
      onClick={handleExport}
      className="gap-2"
    >
      <Download className="w-4 h-4" />
      Exportar JSON
    </Button>
  );
}
