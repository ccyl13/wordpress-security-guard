import { useState } from 'react';
import { Globe, Loader2 } from 'lucide-react';

function isValidUrl(v: string) {
  try { const u = new URL(v.startsWith('http') ? v : 'https://' + v); return u.hostname.includes('.') && u.hostname.length > 3; }
  catch { return false; }
}

export function AuditForm({ onSubmit, isLoading }: { onSubmit: (u: string) => void; isLoading: boolean }) {
  const [url, setUrl] = useState('');
  const [touched, setTouched] = useState(false);
  const trimmed = url.trim();
  const isValid = isValidUrl(trimmed);
  const showErr = touched && trimmed.length > 0 && !isValid;

  const submit = (e: React.FormEvent) => {
    e.preventDefault(); setTouched(true);
    if (!trimmed || !isValid) return;
    onSubmit(trimmed.startsWith('http') ? trimmed : 'https://' + trimmed);
  };

  return (
    <form onSubmit={submit} style={{ maxWidth: '580px', margin: '0 auto' }}>
      <div className="search-form" style={{ display: 'flex', position: 'relative' }}>
        <div style={{ position: 'relative', flex: 1 }}>
          <Globe size={16} style={{ position: 'absolute', left: '14px', top: '50%', transform: 'translateY(-50%)', color: 'rgba(255,255,255,0.2)', pointerEvents: 'none' }}/>
          <input
            className="search-input"
            type="text"
            placeholder="ejemplo.com o https://ejemplo.com"
            value={url}
            onChange={e => { setUrl(e.target.value); setTouched(false); }}
            onBlur={() => setTouched(true)}
            disabled={isLoading}
            autoComplete="off"
            spellCheck={false}
            style={{ borderColor: showErr ? 'rgba(239,68,68,0.4)' : undefined }}
          />
        </div>
        <button className="btn-primary" type="submit" disabled={isLoading || !trimmed}
          style={{ borderRadius: '0 12px 12px 0', height: '52px', opacity: !trimmed && !isLoading ? 0.5 : 1 }}>
          {isLoading ? <><Loader2 size={15} style={{ animation: 'spin 1s linear infinite' }}/> Escaneando</> : 'Auditar →'}
        </button>
      </div>
      {showErr && (
        <p style={{ marginTop: '8px', fontSize: '12px', color: '#f87171', textAlign: 'left', paddingLeft: '4px' }}>
          URL no válida — prueba con: miweb.com
        </p>
      )}
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </form>
  );
}
