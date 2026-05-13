import { useState } from 'react';
import { Search, Loader2, Globe, AlertCircle } from 'lucide-react';

function isValidUrl(v: string) {
  try {
    const u = new URL(v.startsWith('http') ? v : 'https://' + v);
    return u.hostname.includes('.') && u.hostname.length > 3;
  } catch { return false; }
}

interface AuditFormProps { onSubmit: (url: string) => void; isLoading: boolean; }

export function AuditForm({ onSubmit, isLoading }: AuditFormProps) {
  const [url, setUrl] = useState('');
  const [touched, setTouched] = useState(false);
  const [focused, setFocused] = useState(false);
  const trimmed = url.trim();
  const isValid = trimmed.length > 0 && isValidUrl(trimmed);
  const showError = touched && trimmed.length > 0 && !isValid;

  const submit = (e: React.FormEvent) => {
    e.preventDefault(); setTouched(true);
    if (!isValid) return;
    onSubmit(trimmed.startsWith('http') ? trimmed : 'https://' + trimmed);
  };

  return (
    <form onSubmit={submit} className="w-full max-w-lg" style={{ position: 'relative' }}>
      <div className="flex" style={{
        borderRadius: '12px',
        boxShadow: focused
          ? '0 0 0 3px rgba(139,92,246,0.15), 0 0 40px rgba(139,92,246,0.1)'
          : '0 0 0 1px rgba(255,255,255,0.08)',
        transition: 'box-shadow 0.2s ease',
      }}>
        <div className="relative flex-1">
          <Globe size={14} className="absolute left-4 top-1/2 -translate-y-1/2 pointer-events-none" style={{ color: focused ? 'rgba(139,92,246,0.7)' : 'rgba(255,255,255,0.2)', transition: 'color 0.2s' }}/>
          <input
            type="text"
            placeholder="ejemplo.com"
            value={url}
            onChange={e => { setUrl(e.target.value); setTouched(false); }}
            onFocus={() => setFocused(true)}
            onBlur={() => { setFocused(false); setTouched(true); }}
            disabled={isLoading}
            autoComplete="off"
            spellCheck={false}
            className="input-field"
            style={{ borderRadius: '12px 0 0 12px', border: 'none', boxShadow: 'none' }}
          />
        </div>
        <button
          type="submit"
          disabled={isLoading || !trimmed}
          className="btn-primary"
          style={{ borderRadius: '0 12px 12px 0', height: '48px', minWidth: '120px', justifyContent: 'center' }}
        >
          {isLoading
            ? <><Loader2 size={14} className="animate-spin"/>Escaneando</>
            : <><Search size={14}/>Auditar</>}
        </button>
      </div>
      {showError && (
        <div className="absolute left-0 mono flex items-center gap-1.5 text-red-400/80 mt-2" style={{ fontSize: '11px', top: '100%' }}>
          <AlertCircle size={10}/>URL no válida · prueba con: miweb.com
        </div>
      )}
    </form>
  );
}
