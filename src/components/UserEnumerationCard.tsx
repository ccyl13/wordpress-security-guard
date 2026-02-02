import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Users, ShieldAlert, ShieldCheck } from 'lucide-react';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import type { UserEnumeration } from '@/types/wordpress-audit';
import { cn } from '@/lib/utils';
import { SecurityReferenceBadges } from './SecurityReferenceBadges';

interface UserEnumerationCardProps {
  data: UserEnumeration;
}

export function UserEnumerationCard({ data }: UserEnumerationCardProps) {
  return (
    <Card className={cn(
      "bg-card border-border",
      data.found ? "border-red-500/30" : "border-green-500/30"
    )}>
      <CardHeader className="pb-4">
        <CardTitle className="flex items-center gap-3 text-xl">
          <Users className="w-6 h-6 text-primary" />
          Enumeración de Usuarios
          {data.found ? (
            <ShieldAlert className="w-5 h-5 text-red-400 ml-auto" />
          ) : (
            <ShieldCheck className="w-5 h-5 text-green-400 ml-auto" />
          )}
        </CardTitle>
      </CardHeader>
      <CardContent>
        {data.found ? (
          <div className="space-y-4">
            <div className="p-3 bg-red-500/10 border border-red-500/20 rounded-lg">
              <p className="text-red-400 font-medium">⚠️ Vulnerabilidad detectada</p>
              <p className="text-sm text-muted-foreground mt-1">
                Se pueden enumerar usuarios mediante: <code className="text-xs bg-background px-1 py-0.5 rounded">{data.method}</code>
              </p>
              {data.reference && (
                <SecurityReferenceBadges reference={data.reference} />
              )}
            </div>
            
            {data.users.length > 0 && (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-16">ID</TableHead>
                    <TableHead>Nombre</TableHead>
                    <TableHead>Slug</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {data.users.map((user) => (
                    <TableRow key={user.id}>
                      <TableCell className="font-mono">{user.id}</TableCell>
                      <TableCell>{user.name}</TableCell>
                      <TableCell className="font-mono text-muted-foreground">{user.slug}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </div>
        ) : (
          <div className="p-4 bg-green-500/10 border border-green-500/20 rounded-lg text-center">
            <p className="text-green-400 font-medium">✓ No se detectó enumeración de usuarios</p>
            <p className="text-sm text-muted-foreground mt-1">
              El sitio está protegido contra enumeración de usuarios vía REST API y parámetros author
            </p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
