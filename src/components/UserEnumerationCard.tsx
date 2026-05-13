import type { UserEnumeration } from '@/types/wordpress-audit';
import { Users, ShieldAlert, ShieldCheck, User } from 'lucide-react';

interface UserEnumerationCardProps {
  userEnumeration: UserEnumeration;
}

export function UserEnumerationCard({ userEnumeration }: UserEnumerationCardProps) {
  const { found, status, users, method, protectionDetails, reference } = userEnumeration;

  return (
    <div className="rounded-xl bg-card border border-border overflow-hidden">
      <div className="px-5 py-4 border-b border-border flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Users className="w-4 h-4 text-primary" />
          <h3 className="font-semibold text-sm">Enumeracion de usuarios</h3>
        </div>
        <div className="flex items-center gap-1.5">
          {found
            ? <ShieldAlert className="w-4 h-4 text-red-400" />
            : <ShieldCheck className="w-4 h-4 text-emerald-400" />}
          <span className={"text-xs font-mono " + (found ? 'text-red-400' : 'text-emerald-400')}>
            {found ? 'Vulnerable' : status === 'protected' ? 'Protegido' : 'No encontrado'}
          </span>
        </div>
      </div>

      <div className="px-5 py-4 space-y-3">
        <div className="flex flex-wrap gap-3 text-xs font-mono text-muted-foreground">
          <span>Metodo: <span className="text-foreground">{method}</span></span>
          {reference?.owasp && <span>OWASP: <span className="text-foreground">{reference.owasp}</span></span>}
          {reference?.cvss && <span>CVSS: <span className={"font-bold " + (found ? 'text-red-400' : 'text-emerald-400')}>{reference.cvss.score.toFixed(1)}</span></span>}
        </div>

        {protectionDetails && (
          <p className="text-xs text-muted-foreground bg-secondary/50 rounded-lg px-3 py-2 font-mono">{protectionDetails}</p>
        )}

        {found && users.length > 0 && (
          <div className="space-y-1.5">
            <p className="text-xs text-muted-foreground font-mono uppercase tracking-wider">Usuarios encontrados</p>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {users.map((u) => (
                <div key={u.id} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-red-950/20 border border-red-400/20">
                  <User className="w-3 h-3 text-red-400 shrink-0" />
                  <div className="min-w-0">
                    <p className="text-xs font-semibold text-foreground truncate">{u.name}</p>
                    <p className="text-xs font-mono text-muted-foreground/60 truncate">@{u.slug}</p>
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
