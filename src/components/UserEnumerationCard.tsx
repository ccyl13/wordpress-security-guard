import type { UserEnumeration } from '@/types/wordpress-audit';
import { Users, ShieldAlert, ShieldCheck, User } from 'lucide-react';

export function UserEnumerationCard({ userEnumeration }: { userEnumeration:UserEnumeration }) {
  const { found, status, users, method, protectionDetails, reference } = userEnumeration;
  return (
    <div className="glass rounded-2xl overflow-hidden">
      <div className="px-5 py-4 border-b border-white/[0.06] flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Users size={15} className="text-purple"/>
          <span className="font-bold text-sm">Enumeración de usuarios</span>
        </div>
        <div className="flex items-center gap-1.5">
          {found ? <ShieldAlert size={14} className="text-red-400"/> : <ShieldCheck size={14} className="text-emerald-400"/>}
          <span className={`mono text-[10px] font-bold ${found?'text-red-400':'text-emerald-400'}`}>
            {found?'Vulnerable':status==='protected'?'Protegido':'No encontrado'}
          </span>
        </div>
      </div>
      <div className="px-5 py-4 space-y-3">
        <div className="flex flex-wrap gap-4 mono text-[10px] text-white/35">
          <span>Método: <span className="text-white/60">{method}</span></span>
          {reference?.cvss && <span>CVSS: <span className={`font-bold ${found?'text-red-400':'text-emerald-400'}`}>{reference.cvss.score.toFixed(1)}</span></span>}
          {reference?.owasp && <span className="text-white/20">{reference.owasp}</span>}
        </div>
        {protectionDetails && <p className="mono text-[10px] text-white/30 bg-white/[0.03] rounded-lg px-3 py-2">{protectionDetails}</p>}
        {found && users.length>0 && (
          <div className="space-y-2">
            <p className="mono text-[9px] text-white/25 uppercase tracking-wider">Usuarios encontrados</p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {users.map(u => (
                <div key={u.id} className="flex items-center gap-2 px-3 py-2 rounded-xl bg-red-500/[0.06] border border-red-500/15">
                  <User size={12} className="text-red-400 shrink-0"/>
                  <div className="min-w-0">
                    <p className="text-xs font-semibold truncate">{u.name}</p>
                    <p className="mono text-[9px] text-white/30 truncate">@{u.slug}</p>
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
