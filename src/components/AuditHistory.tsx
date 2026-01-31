import { Clock, Trash2 } from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import { cn } from '@/lib/utils';

interface StoredAudit {
  url: string;
  timestamp: string;
  score: number;
  isWordPress: boolean;
}

interface AuditHistoryProps {
  history: StoredAudit[];
  onSelect: (url: string) => void;
  onClear: () => void;
}

function getScoreColor(score: number): string {
  if (score >= 80) return 'text-green-500';
  if (score >= 50) return 'text-yellow-500';
  return 'text-red-500';
}

export function AuditHistory({ history, onSelect, onClear }: AuditHistoryProps) {
  if (history.length === 0) return null;

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="sm" className="gap-2 text-muted-foreground">
          <Clock className="w-4 h-4" />
          Historial ({history.length})
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-72">
        {history.map((item) => {
          const hostname = new URL(item.url).hostname;
          const date = new Date(item.timestamp);
          
          return (
            <DropdownMenuItem
              key={item.url + item.timestamp}
              onClick={() => onSelect(item.url)}
              className="flex items-center justify-between cursor-pointer"
            >
              <div className="flex flex-col">
                <span className="font-mono text-sm truncate max-w-[180px]">
                  {hostname}
                </span>
                <span className="text-xs text-muted-foreground">
                  {date.toLocaleDateString('es-ES')}
                </span>
              </div>
              <span className={cn('font-bold', getScoreColor(item.score))}>
                {item.score}
              </span>
            </DropdownMenuItem>
          );
        })}
        <DropdownMenuSeparator />
        <DropdownMenuItem
          onClick={onClear}
          className="text-destructive cursor-pointer"
        >
          <Trash2 className="w-4 h-4 mr-2" />
          Limpiar historial
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
