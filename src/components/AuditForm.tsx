import { useState } from 'react';

function isValidUrl(value: string): boolean {
  try {
    const url = new URL(value.startsWith('http') ? value : 'https://' + value);
    return url.hostname.includes('.') && url.hostname.length > 3;
  } catch { return false; }
}

interface AuditFormProps {
  onSubmit: (url: string) => void;
  isLoading: boolean;
}

export function AuditForm({ onSubmit, isLoading }: AuditFormProps) {
  const [url, setUrl] = useState('');
  const [touched, setTouched] = useState(false);
  const [pressed, setPressed] = useState(false);
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
    <form onSubmit={handleSubmit} style={{ display: 'flex', gap: 0, maxWidth: '500px', position: 'relative' }}>
      <div style={{ flex: 1, position: 'relative' }}>
        <span style={{ position: 'absolute', left: '13px', top: '50%', transform: 'translateY(-50%)', color: '#ffffff20', fontSize: '14px', pointerEvents: 'none' }}>⊕</span>
        <input
          type="text"
          placeholder="ejemplo.com o https://ejemplo.com"
          value={url}
          onChange={e => { setUrl(e.target.value); setTouched(false); }}
          onBlur={() => setTouched(true)}
          disabled={isLoading}
          autoComplete="off"
          spellCheck={false}
          style={{
            width: '100%', height: '48px',
            background: '#0a0a16',
            border: '1px solid ' + (showError ? '#ef444430' : '#ffffff0c'),
            borderRight: 0,
            borderRadius: '8px 0 0 8px',
            padding: '0 14px 0 36px',
            color: '#fff',
            fontSize: '12px',
            fontFamily: 'JetBrains Mono, monospace',
            outline: 'none',
            transition: 'border-color .2s, background .2s',
          }}
          onFocus={e => { e.currentTarget.style.borderColor = '#8b5cf630'; e.currentTarget.style.background = '#0d0d1e'; }}
          onBlurCapture={e => { e.currentTarget.style.background = '#0a0a16'; }}
        />
        {showError && (
          <div style={{ position: 'absolute', top: '100%', left: 0, marginTop: '4px', fontSize: '9px', fontFamily: 'JetBrains Mono,monospace', color: '#ef4444', display: 'flex', alignItems: 'center', gap: '4px' }}>
            ✗ URL no válida — prueba con: miweb.com
          </div>
        )}
      </div>
      <button
        type="submit"
        disabled={isLoading || !trimmed}
        onMouseDown={() => setPressed(true)}
        onMouseUp={() => setPressed(false)}
        onMouseLeave={() => setPressed(false)}
        style={{
          height: '48px',
          padding: '0 22px',
          background: isLoading ? '#6d28d9' : '#8b5cf6',
          border: 'none',
          borderRadius: '0 8px 8px 0',
          color: '#fff',
          fontSize: '12px',
          fontWeight: 700,
          fontFamily: "'Space Grotesk', sans-serif",
          cursor: isLoading ? 'not-allowed' : 'pointer',
          letterSpacing: '.3px',
          whiteSpace: 'nowrap',
          position: 'relative',
          overflow: 'hidden',
          transition: 'all .12s ease',
          transform: pressed ? 'translateY(3px)' : 'translateY(-3px)',
          boxShadow: pressed
            ? '0 0 0 transparent, 0 2px 8px #8b5cf620'
            : '0 1px 0 #6d28d9, 0 2px 0 #5b21b6, 0 3px 0 #4c1d95, 0 4px 0 #3b0f75, 0 6px 14px #8b5cf640, inset 0 1px 0 #a78bfa40',
          opacity: (!trimmed && !isLoading) ? 0.5 : 1,
        }}
      >
        <span style={{ position: 'absolute', inset: 0, background: 'linear-gradient(180deg,#ffffff1a 0%,transparent 55%)', pointerEvents: 'none', borderRadius: 'inherit' }}/>
        {isLoading ? '⟳ Escaneando...' : 'Auditar →'}
      </button>
    </form>
  );
}
