import { useState } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Search, Loader2, AlertCircle } from 'lucide-react';

interface AuditFormProps {
  onSubmit: (url: string) => void;
  isLoading: boolean;
}

function isValidUrl(value: string): boolean {
  try {
    const url = new URL(value.startsWith('http') ? value : 'https://' + value);
    return url.hostname.includes('.');
  } catch {
    return false;
  }
}

export function AuditForm({ onSubmit, isLoading }: AuditFormProps) {
  const [url, setUrl] = useState('');
  const [touched, setTouched] = useState(false);

  const isValid = isValidUrl(url.trim());
  const showError = touched && url.trim().length > 0 && !isValid;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setTouched(true);
    const trimmed = url.trim();
    if (!trimmed || !isValid) return;
    const normalized = trimmed.startsWith('http') ? trimmed : 'https://' + trimmed;
    onSubmit(normalized);
  };

  return (
    <form onSubmit={handleSubmit} className='w-full max-w-2xl mx-auto'>
      <div className='flex gap-3'>
        <div className='relative flex-1'>
          <Input
            type='text'
            placeholder='https://ejemplo.com'
            value={url}
            onChange={(e) => { setUrl(e.target.value); setTouched(false); }}
            onBlur={() => setTouched(true)}
            className={`h-14 pl-5 pr-4 text-lg bg-card border-primary/30 focus:border-primary placeholder:text-muted-foreground/50 font-mono ${showError ? 'border-destructive focus:border-destructive' : ''}`}
            disabled={isLoading}
            aria-label='URL del sitio WordPress a auditar'
          />
          {showError && (
            <div className='absolute -bottom-6 left-0 flex items-center gap-1 text-destructive text-xs'>
              <AlertCircle className='w-3 h-3' />
              <span>Introduce una URL válida (ej: ejemplo.com)</span>
            </div>
          )}
        </div>
        <Button
          type='submit'
          disabled={isLoading || !url.trim()}
          className='h-14 px-8 text-lg font-bold bg-primary hover:bg-primary/80 text-primary-foreground'
        >
          {isLoading ? (
            <>
              <Loader2 className='w-5 h-5 mr-2 animate-spin' />
              Escaneando
            </>
          ) : (
            <>
              <Search className='w-5 h-5 mr-2' />
              Auditar
            </>
          )}
        </Button>
      </div>
    </form>
  );
}