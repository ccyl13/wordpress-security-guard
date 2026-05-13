import type { CvssScore } from '@/types/wordpress-audit';

function cfg(s:number){
  if(s>=80)return{stroke:'#10b981',glow:'#10b98150',label:'Seguro',lc:'text-emerald-400',lb:'bg-emerald-400/10 border-emerald-400/30'};
  if(s>=60)return{stroke:'#f59e0b',glow:'#f59e0b50',label:'Moderado',lc:'text-amber-400',lb:'bg-amber-400/10 border-amber-400/30'};
  if(s>=40)return{stroke:'#f97316',glow:'#f9731650',label:'Vulnerable',lc:'text-orange-400',lb:'bg-orange-400/10 border-orange-400/30'};
  return      {stroke:'#ef4444',glow:'#ef444450',label:'Critico',lc:'text-red-400',lb:'bg-red-400/10 border-red-400/30'};
}
function cvssClr(s:string){return{None:'text-emerald-400',Low:'text-amber-400',Medium:'text-orange-400',High:'text-red-400',Critical:'text-red-500'}[s]||'text-white/40';}

export function ScoreGauge({score,cvss}:{score:number;cvss?:CvssScore}){
  const c=cfg(score); const R=52; const circ=2*Math.PI*R;
  return(
    <div className="result-card p-6 flex flex-col items-center gap-4 h-full justify-center">
      <p className="mono-label">Puntuacion de seguridad</p>
      <div className="relative w-36 h-36">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 120 120">
          <circle cx="60" cy="60" r={R} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="10"/>
          <circle cx="60" cy="60" r={R} fill="none" stroke={c.stroke} strokeWidth="10"
            strokeDasharray={circ} strokeDashoffset={circ-(score/100)*circ} strokeLinecap="round"
            style={{transition:'stroke-dashoffset 1.2s cubic-bezier(.4,0,.2,1)',filter:'drop-shadow(0 0 10px '+c.glow+')'}}/>
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={'text-4xl font-extrabold tracking-[-2px] leading-none '+c.lc} style={{textShadow:'0 0 30px '+c.glow}}>{score}</span>
          <span className="font-mono text-[10px] text-white/20">/100</span>
        </div>
      </div>
      <span className={'text-xs font-bold px-4 py-1.5 rounded-full border '+c.lc+' '+c.lb}>{c.label}</span>
      {cvss&&(
        <div className="w-full glass rounded-xl p-3 text-center">
          <p className="mono-label mb-1">CVSS 3.1</p>
          <p className={'text-3xl font-extrabold tracking-[-1px] '+cvssClr(cvss.severity)} style={{textShadow:'0 0 20px currentColor'}}>{cvss.score.toFixed(1)}</p>
          <p className={'text-xs font-bold mt-0.5 '+cvssClr(cvss.severity)}>{cvss.severity}</p>
          {cvss.vector&&<p className="font-mono text-[8px] text-white/15 mt-2 break-all leading-relaxed">{cvss.vector.replace('CVSS:3.1/','')}</p>}
        </div>
      )}
    </div>
  );
}
