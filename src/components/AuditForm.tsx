import { useState } from 'react';
import { Loader2 } from 'lucide-react';

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
      <div className="flex w-full rounded-xl overflow-hidden border border-white/10 focus-within:border-violet-500/40 focus-within:shadow-[0_0_0_3px_rgba(139,92,246,0.1)] transition-all">
        <div className="relative flex-1">
          <span className="absolute left-4 top-1/2 -translate-y-1/2 text-white/25 pointer-events-none text-base">⊕</span>
          <input
            type="text"
            placeholder="ejemplo.com"
            value={url}
            onChange={e => { setUrl(e.target.value); setTouched(false); }}
            onBlur={() => setTouched(true)}
            disabled={isLoading}
            autoComplete="off"
            spellCheck={false}
            className="w-full h-12 sm:h-[52px] pl-11 pr-4 text-sm bg-white/[0.03] text-white placeholder-white/20 font-mono outline-none border-0"
          />
        </div>
        <button
          type="submit"
          disabled={isLoading || !trimmed}
          className="btn-primary h-12 sm:h-[52px] px-6 sm:px-8 text-sm rounded-none rounded-r-xl whitespace-nowrap flex items-center gap-2 shrink-0"
        >
          {isLoading
            ? <><Loader2 size={14} className="animate-spin" />Escaneando</>
            : <>Auditar &rarr;</>}
        </button>
      </div>
      {showErr && (
        <p className="mt-1.5 font-mono text-[10px] text-red-400">✗ URL no válida — prueba: miweb.com</p>
      )}
    </form>
  );
}
