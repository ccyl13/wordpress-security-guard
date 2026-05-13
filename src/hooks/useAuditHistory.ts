import { useState } from 'react';
import type { AuditResult } from '@/types/wordpress-audit';

const KEY = 'wpsentry_audit_history';
const MAX = 10;

function toStr(ts: any): string {
  if (typeof ts === 'string' && ts.length > 0) return ts;
  if (ts instanceof Date) return ts.toISOString();
  return new Date().toISOString();
}

function load(): AuditResult[] {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return [];
    const arr = JSON.parse(raw);
    if (!Array.isArray(arr)) return [];
    return arr.map((item: any) => ({ ...item, timestamp: toStr(item.timestamp) }));
  } catch { return []; }
}

function save(history: AuditResult[]) {
  try { localStorage.setItem(KEY, JSON.stringify(history)); } catch { /* ignore */ }
}

export function useAuditHistory() {
  const [history, setHistory] = useState<AuditResult[]>(() => load());

  const addToHistory = (result: AuditResult) => {
    const item = { ...result, timestamp: toStr(result.timestamp) };
    setHistory(prev => {
      const next = [item, ...prev.filter(h => h.url !== item.url)].slice(0, MAX);
      save(next);
      return next;
    });
  };

  const clearHistory = () => {
    try { localStorage.removeItem(KEY); } catch { /* ignore */ }
    setHistory([]);
  };

  return { history, addToHistory, clearHistory };
}
