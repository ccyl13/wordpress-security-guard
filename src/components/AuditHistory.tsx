import { useState, useRef, useEffect } from 'react';
import { Clock, Trash2, ChevronRight } from 'lucide-react';
import type { AuditResult } from '@/types/wordpress-audit';

interface Props {
  history: AuditResult[];
  onSelect: (url: string) => void;
  onClear: () => void;
}

export function AuditHistory({ history, onSelect, onClear }: Props) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  if (!history.length) return null;

  return (
    <div ref={ref} className="relative">
      <button
        onClick={() => setOpen(o => !o)}
        className="btn-icon flex items-center gap-1.5 px-3 w-auto"
      >
        <Clock size={13} />
        <span className="font-mono text-[10px] hidden sm:block">Historial ({history.length})</span>
      </button>

      {open && (
        <div
          className="absolute right-0 top-full mt-2 w-72 rounded-2xl overflow-hidden shadow-2xl shadow-black/80"
          style={{ zIndex: 9999, background: 'rgba(8,8,18,0.97)', border: '1px solid rgba(139,92,246,0.2)', backdropFilter: 'blur(20px)' }}
        >
          <div className="px-4 py-2.5 border-b border-white/[0.06] flex items-center justify-between">
            <span className="font-mono text-[9px] text-white/30 tracking-[2px] uppercase">Historial reciente</span>
            <button
              onClick={() => { onClear(); setOpen(false); }}
              className="flex items-center gap-1 font-mono text-[9px] text-white/25 hover:text-red-400 transition-colors"
            >
              <Trash2 size={10} /> Limpiar
            </button>
          </div>
          <div className="max-h-80 overflow-y-auto divide-y divide-white/[0.04]">
            {history.map((item, i) => {
              const host = (() => { try { return new URL(item.url).hostname; } catch { return item.url; } })();
              const score = item.overallScore;
              const sc = score >= 80 ? 'text-emerald-400' : score >= 60 ? 'text-amber-400' : score >= 40 ? 'text-orange-400' : 'text-red-400';
              return (
                <button key={i} onClick={() => { onSelect(item.url); setOpen(false); }}
                  className="w-full flex items-center justify-between px-4 py-3 hover:bg-white/[0.03] transition-colors text-left">
                  <div className="min-w-0">
                    <p className="text-[12px] font-semibold text-white/80 truncate">{host}</p>
                    <p className="font-mono text-[9px] text-white/25 mt-0.5">{new Date(item.timestamp).toLocaleDateString('es-ES')}</p>
                  </div>
                  <div className="flex items-center gap-2 shrink-0 ml-3">
                    <span className={'font-mono text-[14px] font-extrabold ' + sc}>{score}</span>
                    <ChevronRight size={11} className="text-white/20" />
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
