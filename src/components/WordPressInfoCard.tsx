import type { WordPressInfo, WordPressDetection } from '@/types/wordpress-audit';
import { Cpu } from 'lucide-react';

function Row({ label, value, good }: { label: string; value: string; good: boolean | null }) {
  const vc = good === null ? 'text-white/50' : good ? 'text-emerald-400' : 'text-red-400';
  return (
    <div className="flex items-center justify-between py-2.5 border-b border-white/[0.04] last:border-0">
      <span className="font-mono text-[10px] text-white/30">{label}</span>
      <span className={'font-mono text-[11px] font-semibold ' + vc}>{value}</span>
    </div>
  );
}

export function WordPressInfoCard({ info, isWordPress, wpDetection }: { info: WordPressInfo; isWordPress: boolean; wpDetection: WordPressDetection }) {
  const dp = wpDetection === 'detected'
    ? { label: 'WordPress detectado', cls: 'pill-purple' }
    : wpDetection === 'blocked'
    ? { label: 'Acceso bloqueado', cls: 'pill-yellow' }
    : { label: 'No detectado', cls: 'pill-gray' };
  return (
    <div className="result-card h-full">
      <div className="card-header">
        <div className="flex items-center gap-2">
          <Cpu size={15} className="text-violet-400" />
          <span className="text-sm font-bold">Información del sitio</span>
        </div>
        <span className={'pill ' + dp.cls}>{dp.label}</span>
      </div>
      <div className="px-5 py-2">
        <Row label="Versión WordPress" value={info.version ?? 'Oculta'} good={!info.version} />
        <Row label="Tema activo" value={info.theme ?? 'No detectado'} good={null} />
        <Row label="Cabecera Generator" value={info.generator ? 'Expuesta' : 'Oculta'} good={!info.generator} />
        <Row label="readme.html" value={info.readme ? 'Accesible' : 'Bloqueado'} good={!info.readme} />
        {info.wafDetected !== undefined && (
          <Row label="WAF detectado" value={info.wafDetected || 'No detectado'} good={!!info.wafDetected} />
        )}
        {info.sslInfo && (
          <Row label="SSL / HTTPS" value={info.sslInfo.valid ? 'Válido' + (info.sslInfo.issuer ? ' — ' + info.sslInfo.issuer : '') : 'Inválido'} good={info.sslInfo.valid} />
        )}
      </div>
    </div>
  );
}
