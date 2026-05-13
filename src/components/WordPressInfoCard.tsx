import type { WordPressInfo, WordPressDetection } from '@/types/wordpress-audit';
import { Cpu } from 'lucide-react';

const Row = ({ label, value, good }: { label: string; value: string; good: boolean | null }) => (
  <div className="flex items-center justify-between py-2.5 border-b border-white/4 last:border-0">
    <span className="mono text-white/30" style={{ fontSize: 11 }}>{label}</span>
    <span className="mono font-medium" style={{ fontSize: 11, color: good === null ? 'rgba(255,255,255,0.5)' : good ? '#10b981' : '#ef4444' }}>{value}</span>
  </div>
);

export function WordPressInfoCard({ info, isWordPress, wpDetection }: { info: WordPressInfo; isWordPress: boolean; wpDetection: WordPressDetection }) {
  const badge = wpDetection === 'detected'
    ? { label: 'WordPress detectado', color: '#8b5cf6', bg: 'rgba(139,92,246,0.1)', border: 'rgba(139,92,246,0.3)' }
    : wpDetection === 'blocked'
    ? { label: 'Acceso bloqueado', color: '#f59e0b', bg: 'rgba(245,158,11,0.1)', border: 'rgba(245,158,11,0.3)' }
    : { label: 'No detectado', color: 'rgba(255,255,255,0.3)', bg: 'rgba(255,255,255,0.05)', border: 'rgba(255,255,255,0.1)' };
  return (
    <div className="result-card h-full overflow-hidden">
      <div className="card-header">
        <div className="flex items-center gap-2"><Cpu size={13} style={{ color: '#8b5cf6' }}/><span className="card-title">Información del sitio</span></div>
        <span className="mono px-2.5 py-1 rounded-full" style={{ fontSize: 10, color: badge.color, background: badge.bg, border: '1px solid ' + badge.border }}>{badge.label}</span>
      </div>
      <div className="px-4 py-2">
        <Row label="Versión WordPress" value={info.version || 'Oculta'} good={!info.version}/>
        <Row label="Tema activo" value={info.theme || 'No detectado'} good={null}/>
        <Row label="Cabecera Generator" value={info.generator ? 'Expuesta' : 'Oculta'} good={!info.generator}/>
        <Row label="readme.html" value={info.readme ? 'Accesible' : 'Bloqueado'} good={!info.readme}/>
        {info.wafDetected !== undefined && <Row label="WAF detectado" value={info.wafDetected || 'No detectado'} good={!!info.wafDetected}/>}
        {info.sslInfo && <Row label="SSL / HTTPS" value={info.sslInfo.valid ? 'Válido' + (info.sslInfo.issuer ? ' · ' + info.sslInfo.issuer : '') : 'Inválido'} good={info.sslInfo.valid}/>}
      </div>
    </div>
  );
}
