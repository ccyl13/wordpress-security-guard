import { useState, useEffect } from 'react';
import type { AuditResult } from '@/types/wordpress-audit';

const STORAGE_KEY = 'wp-audit-history';
const MAX_HISTORY = 10;

interface StoredAudit {
  url: string;
  timestamp: string;
  score: number;
  isWordPress: boolean;
}

export function useAuditHistory() {
  const [history, setHistory] = useState<StoredAudit[]>([]);

  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        setHistory(JSON.parse(stored));
      }
    } catch {
      // Ignore errors
    }
  }, []);

  const addToHistory = (result: AuditResult) => {
    const newEntry: StoredAudit = {
      url: result.url,
      timestamp: result.timestamp.toISOString(),
      score: result.overallScore,
      isWordPress: result.isWordPress,
    };

    setHistory((prev) => {
      // Remove duplicate if exists
      const filtered = prev.filter((h) => h.url !== result.url);
      const updated = [newEntry, ...filtered].slice(0, MAX_HISTORY);
      
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
      } catch {
        // Ignore storage errors
      }
      
      return updated;
    });
  };

  const clearHistory = () => {
    setHistory([]);
    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch {
      // Ignore errors
    }
  };

  return { history, addToHistory, clearHistory };
}
