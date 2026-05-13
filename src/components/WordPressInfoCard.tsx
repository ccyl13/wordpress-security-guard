import type { WordPressInfo, WordPressDetection } from '@/types/wordpress-audit';
import { Cpu } from 'lucide-react';

function Row({ label, value, color }: { label: string; value: string; color?: string }) {
  return (
    <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',padding:'10px 20px',borderBottom:'1px solid rgba(255,255,255,0.04)'}}>
      <span style={{fontSize:'12px',color:'rgba(255,255,255,0.35)',fontFamily:'JetBrains Mono,monospace'}}>{label}</span>
      <span style={{fontSize:'12px',fontWeight:600,color:color||'rgba(255,255,255,0.7)',fontFamily:'JetBrains Mono,monospace'}}>{value}</span>
    </div>
  );
}

export function WordPressInfoCard({ info, isWordPress, wpDetection }: { info: WordPressInfo; isWordPress: boolean; wpDetection: WordPressDetection }) {
  const badge = wpDetection==='detected'
    ? {text:'WordPress detectado',bg:'rgba(124,58,237,0.12)',color:'#a78bfa',border:'rgba(124,58,237,0.3)'}
    : wpDetection==='blocked'
    ? {text:'Acceso bloqueado',bg:'rgba(245,158,11,0.1)',color:'#fbbf24',border:'rgba(245,158,11,0.25)'}
    : {text:'No detectado',bg:'rgba(255,255,255,0.04)',color:'rgba(255,255,255,0.4)',border:'rgba(255,255,255,0.1)'};
  return (
    <div className="result-card" style={{height:'100%'}}>
      <div className="card-header">
        <span className="card-title"><Cpu size={14} style={{color:'#a78bfa'}}/> Información del sitio</span>
        <span style={{fontSize:'11px',padding:'3px 10px',borderRadius:'99px',background:badge.bg,color:badge.color,border:'1px solid '+badge.border,fontWeight:500}}>{badge.text}</span>
      </div>
      <Row label="Versión WordPress" value={info.version||'Oculta'} color={info.version?'#fbbf24':'#34d399'}/>
      <Row label="Tema activo" value={info.theme||'No detectado'} color="rgba(255,255,255,0.55)"/>
      <Row label="Cabecera Generator" value={info.generator?'Expuesta':'Oculta'} color={info.generator?'#f87171':'#34d399'}/>
      <Row label="readme.html" value={info.readme?'Accesible':'Bloqueado'} color={info.readme?'#f87171':'#34d399'}/>
      {info.wafDetected!==undefined&&<Row label="WAF detectado" value={info.wafDetected||'No detectado'} color={info.wafDetected?'#34d399':'#fbbf24'}/>}
      {info.sslInfo&&<Row label="SSL / HTTPS" value={info.sslInfo.valid?'Válido'+(info.sslInfo.issuer?' · '+info.sslInfo.issuer:''):'Inválido'} color={info.sslInfo.valid?'#34d399':'#f87171'}/>}
    </div>
  );
}