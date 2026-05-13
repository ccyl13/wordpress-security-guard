import type { AuditProgress } from '@/lib/wordpress-auditor';

export function ProgressBar({ progress }: { progress: AuditProgress }) {
  return (
    <div style={{padding:'18px 22px',background:'rgba(255,255,255,0.03)',border:'1px solid rgba(255,255,255,0.06)',borderRadius:'14px',fontFamily:'JetBrains Mono,monospace'}}>
      <style>{`@keyframes blink-prog{0%,100%{opacity:1}50%{opacity:.3}}`}</style>
      <div style={{display:'flex',alignItems:'center',gap:'8px',marginBottom:'14px'}}>
        <span style={{color:'#7c3aed',animation:'blink-prog 1s ease-in-out infinite',fontSize:'12px'}}>▶</span>
        <span style={{fontSize:'9px',color:'rgba(255,255,255,0.3)',letterSpacing:'2px',textTransform:'uppercase'}}>WPSentry scan</span>
      </div>
      <div style={{display:'flex',justifyContent:'space-between',fontSize:'11px',color:'rgba(255,255,255,0.35)',marginBottom:'8px'}}>
        <span>{progress.step}</span>
        <span style={{color:'#a78bfa',fontWeight:700}}>{progress.percentage}%</span>
      </div>
      <div style={{height:'2px',background:'rgba(255,255,255,0.06)',borderRadius:'99px',overflow:'visible',position:'relative'}}>
        <div style={{height:'100%',width:progress.percentage+'%',background:'linear-gradient(90deg,#4c1d95,#7c3aed,#a78bfa)',borderRadius:'99px',transition:'width .5s ease',position:'relative',boxShadow:'0 0 12px #7c3aed80'}}>
          <div style={{position:'absolute',right:'-3px',top:'50%',transform:'translateY(-50%)',width:'7px',height:'7px',borderRadius:'50%',background:'#a78bfa',boxShadow:'0 0 10px #a78bfa'}}/>
        </div>
      </div>
      <div style={{display:'flex',justifyContent:'space-between',marginTop:'10px'}}>
        {Array.from({length:progress.total},(_,i)=>(
          <span key={i} style={{fontSize:'9px',color:i<progress.current?'#7c3aed':'rgba(255,255,255,0.1)',letterSpacing:'1px',fontWeight:700}}>{i<progress.current?'[OK]':'[··]'}</span>
        ))}
      </div>
    </div>
  );
}