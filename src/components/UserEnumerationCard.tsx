import type { UserEnumeration } from '@/types/wordpress-audit';
import { Users, ShieldAlert, ShieldCheck, User } from 'lucide-react';

export function UserEnumerationCard({ userEnumeration }: { userEnumeration: UserEnumeration }) {
  const { found, status, users, method, protectionDetails, reference } = userEnumeration;
  return (
    <div className="result-card overflow-hidden">
      <div className="card-header">
        <div className="flex items-center gap-2"><Users size={13} style={{ color: '#8b5cf6' }}/><span className="card-title">Enumeracion de usuarios</span></div>
        <div className="flex items-center gap-1.5">
          {found ? <ShieldAlert size={13} style={{ color: '#ef4444' }}/> : <ShieldCheck size={13} style={{ color: '#10b981' }}/>}
          <span className="mono font-medium" style={{ fontSize: 10, color: found ? '#ef4444' : '#10b981' }}>{found ? 'Vulnerable' : status === 'protected' ? 'Protegido' : 'No encontrado'}</span>
        </div>
      </div>
      <div className="px-4 py-4">
        <div className="mono flex flex-wrap gap-4 mb-3" style={{ fontSize: 10, color: 'rgba(255,255,255,0.25)' }}>
          <span>Metodo: <span className="text-white/50">{method}</span></span>
          {reference?.cvss && <span>CVSS: <span style={{ color: found ? '#ef4444' : '#10b981', fontWeight: 700 }}>{reference.cvss.score.toFixed(1)}</span></span>}
        </div>
        {protectionDetails && <p className="mono rounded-lg px-3 py-2 mb-3" style={{ fontSize: 10, color: 'rgba(255,255,255,0.25)', background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.05)' }}>{protectionDetails}</p>}
        {found && users.length > 0 && (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {users.map(u => (
              <div key={u.id} className="flex items-center gap-2 px-3 py-2 rounded-xl" style={{ background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)' }}>
                <User size={12} style={{ color: '#ef4444', flexShrink: 0 }}/>
                <div className="min-w-0">
                  <p className="mono font-semibold truncate" style={{ fontSize: 11, color: 'rgba(255,255,255,0.7)' }}>{u.name}</p>
                  <p className="mono truncate text-white/30" style={{ fontSize: 9 }}>@{u.slug}</p>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
