import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Search, Loader2, AlertCircle, Globe } from 'lucide-react';

interface AuditFormProps {
  onSubmit: (url: string) => void;
  isLoading: boolean;
}

function isValidUrl(value: string): boolean {
  try {
    const url = new URL(value.startsWith('http') ? value : 'https://' + value);
    return url.hostname.includes('.') && url.hostname.length > 3;
  } catch {
    return false;
  }
}

export function AuditForm({ onSubmit, isLoading }: AuditFormProps) {
  const [url, setUrl] = useState('');
  const [touched, setTouched] = useState(false);

  const trimmed = url.trim();
  const isValid = trimmed.length > 0 && isValidUrl(trimmed);
  const showError = touched && trimmed.length > 0 && !isValid;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setTouched(true);
    if (!trimmed || !isValid) return;
    const normalized = trimmed.startsWith('http') ? trimmed : 'https://' + trimmed;
    onSubmit(normalized);
  };

  return (
    <form onSubmit={handleSubmit} className="w-full max-w-2xl mx-auto">
      <div className="relative flex gap-2">
        <div className="relative flex-1">
          <Globe className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
          <Input
            type="text"
            placeholder="ejemplo.com o https://ejemplo.com"
            value={url}
            onChange={(e) => { setUrl(e.target.value); setTouched(false); }}
            onBlur={() => setTouched(true)}
            className={
              'h-14 pl-11 pr-4 text-base bg-card/80 border font-mono transition-colors ' +
              (showError
                ? 'border-destructive/60 focus:border-destructive'
                : 'border-primary/20 focus:border-primary/60')
            }
            disabled={isLoading}
            aria-label="URL del sitio WordPress a auditar"
            autoComplete="off"
            spellCheck={false}
          />
          {showError && (
            <div className="absolute -bottom-5 left-0 flex items-center gap-1 text-destructive text-xs font-mono">
              <AlertCircle className="w-3 h-3" />
              <span>URL no valida. Prueba con: miweb.com</span>
            </div>
          )}
        </div>
        <Button
          type="submit"
          disabled={isLoading || !trimmed}
          className="h-14 px-8 text-sm font-bold bg-primary hover:bg-primary/85 text-primary-foreground shrink-0 transition-all duration-200"
        >
          {isLoading ? (
            <span className="flex items-center gap-2">
              <Loader2 className="w-4 h-4 animate-spin" />
              Escaneando...
            </span>
          ) : (
            <span className="flex items-center gap-2">
              <Search className="w-4 h-4" />
              Auditar
            </span>
          )}
        </Button>
      </div>
    </form>
  );
}
