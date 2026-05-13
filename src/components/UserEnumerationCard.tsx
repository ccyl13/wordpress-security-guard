import type { UserEnumeration } from '@/types/wordpress-audit';
import { Users, ShieldAlert, ShieldCheck, User } from 'lucide-react';

export function UserEnumerationCard({ userEnumeration }: { userEnumeration: UserEnumeration }) {
  const { found, status, users, method, protectionDetails, reference } = userEnumeration;
  return (
    <div className="result-card">
      <div className="card-header">
        <div className="flex items-center gap-2">
          <Users size={15} className="text-violet-400" />
          <span className="text-sm font-bold">Enumeración de usuarios</span>
        </div>
        <div className="flex items-center gap-2">
          {found ? <ShieldAlert size={14} className="text-red-400" /> : <ShieldCheck size={14} className="text-emerald-400" />}
          <span className={'font-mono text-[10px] font-semibold ' + (found ? 'text-red-400' : 'text-emerald-400')}>
            {found ? 'Vulnerable' : status === 'protected' ? 'Protegido' : 'No encontrado'}
          </span>
        </div>
      </div>
      <div className="px-5 py-4 space-y-3">
        <div className="flex flex-wrap gap-4 font-mono text-[10px] text-white/30">
          <span>método: <span className="text-white/60">{method}</span></span>
          {reference?.owasp && <span>OWASP: <span className="text-white/60">{reference.owasp}</span></span>}
          {reference?.cvss && (
            <span>CVSS: <span className={'font-bold ' + (found ? 'text-red-400' : 'text-emerald-400')}>{reference.cvss.score.toFixed(1)}</span></span>
          )}
        </div>
        {protectionDetails && (
          <p className="font-mono text-[10px] text-white/30 glass rounded-lg px-3 py-2">{protectionDetails}</p>
        )}
        {found && users.length > 0 && (
          <div className="space-y-2">
            <p className="mono-label">Usuarios encontrados</p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {users.map(u => (
                <div key={u.id} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-red-950/20 border border-red-500/15">
                  <User size={12} className="text-red-400 shrink-0" />
                  <div className="min-w-0">
                    <p className="text-xs font-semibold text-white/80 truncate">{u.name}</p>
                    <p className="font-mono text-[9px] text-white/30 truncate">@{u.slug}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
