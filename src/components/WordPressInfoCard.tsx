import type { WordPressInfo, WordPressDetection } from '@/types/wordpress-audit';
import { CheckCircle2, XCircle, AlertTriangle, Info, Lock, Cpu } from 'lucide-react';

interface WordPressInfoCardProps {
  info: WordPressInfo;
  isWordPress: boolean;
  wpDetection: WordPressDetection;
}

function Row({ label, value, status }: { label: string; value: React.ReactNode; status?: 'good' | 'bad' | 'warn' | 'neutral' }) {
  const colors = { good: 'text-emerald-400', bad: 'text-red-400', warn: 'text-yellow-400', neutral: 'text-muted-foreground' };
  return (
    <div className="flex items-center justify-between py-2.5 border-b border-border/50 last:border-0">
      <span className="text-xs text-muted-foreground font-mono">{label}</span>
      <span className={"text-xs font-semibold font-mono text-right " + (status ? colors[status] : 'text-foreground')}>{value}</span>
    </div>
  );
}

export function WordPressInfoCard({ info, isWordPress, wpDetection }: WordPressInfoCardProps) {
  const detectionBadge = wpDetection === 'detected'
    ? { label: 'WordPress detectado', color: 'text-primary bg-primary/10 border-primary/20' }
    : wpDetection === 'blocked'
    ? { label: 'Acceso bloqueado', color: 'text-yellow-400 bg-yellow-400/10 border-yellow-400/20' }
    : { label: 'No detectado', color: 'text-muted-foreground bg-secondary border-border' };

  return (
    <div className="rounded-xl bg-card border border-border overflow-hidden h-full">
      <div className="px-5 py-4 border-b border-border flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Cpu className="w-4 h-4 text-primary" />
          <h3 className="font-semibold text-sm">Informacion del sitio</h3>
        </div>
        <span className={"text-xs font-mono px-2 py-0.5 rounded border " + detectionBadge.color}>
          {detectionBadge.label}
        </span>
      </div>
      <div className="px-5 py-2">
        <Row
          label="Version WordPress"
          value={info.version ? info.version : 'Oculta'}
          status={info.version ? 'warn' : 'good'}
        />
        <Row
          label="Tema activo"
          value={info.theme || 'No detectado'}
          status="neutral"
        />
        <Row
          label="Cabecera Generator"
          value={info.generator ? 'Expuesta' : 'Oculta'}
          status={info.generator ? 'bad' : 'good'}
        />
        <Row
          label="readme.html"
          value={info.readme ? 'Accesible' : 'Bloqueado'}
          status={info.readme ? 'bad' : 'good'}
        />
        {info.wafDetected !== undefined && (
          <Row
            label="WAF detectado"
            value={info.wafDetected || 'No detectado'}
            status={info.wafDetected ? 'good' : 'warn'}
          />
        )}
        {info.sslInfo && (
          <Row
            label="SSL / HTTPS"
            value={info.sslInfo.valid ? 'Valido' + (info.sslInfo.issuer ? ' - ' + info.sslInfo.issuer : '') : 'Invalido o ausente'}
            status={info.sslInfo.valid ? 'good' : 'bad'}
          />
        )}
      </div>
    </div>
  );
}
