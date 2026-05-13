import type { UserEnumeration } from '@/types/wordpress-audit';
import { Users, User } from 'lucide-react';

export function UserEnumerationCard({ userEnumeration }: { userEnumeration: UserEnumeration }) {
  const { found, status, users, method, protectionDetails, reference } = userEnumeration;
  return (
    <div className="result-card">
      <div className="card-header">
        <span className="card-title"><Users size={14} style={{color:'#8b5cf6'}}/> Enumeración de usuarios</span>
        <span style={{fontSize:'11px',padding:'3px 10px',borderRadius:'99px',fontWeight:600,background:found?'rgba(239,68,68,0.1)':'rgba(16,185,129,0.1)',color:found?'#f87171':'#34d399',border:'1px solid '+(found?'rgba(239,68,68,0.25)':'rgba(16,185,129,0.25)')}}>
          {found?'Vulnerable':status==='protected'?'Protegido':'Sin usuarios'}
        </span>
      </div>
      <div style={{padding:'16px 20px',display:'flex',flexWrap:'wrap',gap:'16px',borderBottom:'1px solid rgba(255,255,255,0.04)'}}>
        <span className="mono" style={{fontSize:'11px',color:'rgba(255,255,255,0.3)'}}>Método: <span style={{color:'rgba(255,255,255,0.6)'}}>{method}</span></span>
        {reference?.owasp&&<span className="mono" style={{fontSize:'11px',color:'rgba(255,255,255,0.3)'}}>OWASP: <span style={{color:'rgba(255,255,255,0.6)'}}>{reference.owasp}</span></span>}
        {reference?.cvss&&<span className="mono" style={{fontSize:'11px',color:'rgba(255,255,255,0.3)'}}>CVSS: <span style={{color:found?'#f87171':'#34d399',fontWeight:700}}>{reference.cvss.score.toFixed(1)}</span></span>}
      </div>
      {protectionDetails&&<div style={{padding:'12px 20px',borderBottom:'1px solid rgba(255,255,255,0.04)'}}><p className="mono" style={{fontSize:'11px',color:'rgba(255,255,255,0.35)',lineHeight:1.6}}>{protectionDetails}</p></div>}
      {found&&users.length>0&&(
        <div style={{padding:'16px 20px'}}>
          <div className="mono" style={{fontSize:'9px',color:'rgba(255,255,255,0.2)',letterSpacing:'2px',marginBottom:'10px'}}>USUARIOS ENCONTRADOS</div>
          <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(200px,1fr))',gap:'8px'}}>
            {users.map(u=>(
              <div key={u.id} style={{display:'flex',alignItems:'center',gap:'10px',padding:'10px 14px',borderRadius:'10px',background:'rgba(239,68,68,0.06)',border:'1px solid rgba(239,68,68,0.15)'}}>
                <User size={13} style={{color:'#f87171',flexShrink:0}}/>
                <div style={{minWidth:0}}>
                  <div style={{fontSize:'12px',fontWeight:600,color:'rgba(255,255,255,0.8)',overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{u.name}</div>
                  <div className="mono" style={{fontSize:'10px',color:'rgba(255,255,255,0.3)'}}>@{u.slug}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}