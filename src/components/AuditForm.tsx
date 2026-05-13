import { useState } from 'react';
import { Search, Loader2 } from 'lucide-react';

function isValidUrl(v: string) {
  try { const u = new URL(v.startsWith('http') ? v : 'https://' + v); return u.hostname.includes('.') && u.hostname.length > 3; }
  catch { return false; }
}

export function AuditForm({ onSubmit, isLoading }: { onSubmit:(url:string)=>void; isLoading:boolean }) {
  const [url, setUrl] = useState('');
  const [touched, setTouched] = useState(false);
  const trimmed = url.trim();
  const valid = isValidUrl(trimmed);
  const showErr = touched && trimmed.length > 0 && !valid;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault(); setTouched(true);
    if (!trimmed || !valid) return;
    onSubmit(trimmed.startsWith('http') ? trimmed : 'https://' + trimmed);
  };

  return (
    <form onSubmit={handleSubmit} className="w-full">
      <div className="flex gap-0 w-full">
        <div className="relative flex-1">
          <span className="absolute left-4 top-1/2 -translate-y-1/2 text-white/25 pointer-events-none">
            <Search size={15}/>
          </span>
          <input
            type="text"
            placeholder="ejemplo.com o https://ejemplo.com"
            value={url}
            onChange={e => { setUrl(e.target.value); setTouched(false); }}
            onBlur={() => setTouched(true)}
            disabled={isLoading}
            autoComplete="off"
            spellCheck={false}
            className={
              'w-full h-12 sm:h-[50px] pl-11 pr-4 text-sm input-field rounded-l-xl rounded-r-none ' +
              (showErr ? 'border-red-500/40 focus:border-red-500/60 focus:shadow-none' : '')
            }
          />
          {showErr && (
            <p className="absolute top-full left-0 mt-1 font-mono text-[9px] text-red-400">
              ✗ URL no válida — prueba: miweb.com
            </p>
          )}
        </div>
        <button
          type="submit"
          disabled={isLoading || !trimmed}
          className="btn-primary h-12 sm:h-[50px] px-6 sm:px-8 text-sm rounded-r-xl rounded-l-none whitespace-nowrap flex items-center gap-2"
        >
          {isLoading
            ? <><Loader2 size={14} className="animate-spin"/>Escaneando</>
            : <>Auditar <span className="hidden sm:inline">→</span></>}
        </button>
      </div>
    </form>
  );
}
