import { useState } from 'react';
import { Github, Linkedin, Shield, Lock, Zap, Eye } from 'lucide-react';
import { AuditForm } from '@/components/AuditForm';
import { SecurityHeadersCard } from '@/components/SecurityHeadersCard';
import { EndpointsCard } from '@/components/EndpointsCard';
import { UserEnumerationCard } from '@/components/UserEnumerationCard';
import { WordPressInfoCard } from '@/components/WordPressInfoCard';
import { Recommendations } from '@/components/Recommendations';
import { AuditLoadingSkeleton } from '@/components/LoadingSkeleton';
import { ProgressBar } from '@/components/ProgressBar';
import { ExportButton } from '@/components/ExportButton';
import { AuditHistory } from '@/components/AuditHistory';
import { useAuditHistory } from '@/hooks/useAuditHistory';
import { auditWordPress, type AuditProgress } from '@/lib/wordpress-auditor';
import type { AuditResult } from '@/types/wordpress-audit';
import { Alert, AlertDescription } from '@/components/ui/alert';

const HexLogo = () => (
  <svg width="30" height="30" viewBox="0 0 30 30" fill="none">
    <polygon points="15,1 28,8.5 28,21.5 15,29 2,21.5 2,8.5"
      fill="rgba(139,92,246,0.15)" stroke="#a78bfa" strokeWidth="0.8"/>
    <polygon points="15,7 23,11.5 23,18.5 15,23 7,18.5 7,11.5"
      fill="rgba(139,92,246,0.3)" stroke="#a78bfa" strokeWidth="0.5"/>
    <circle cx="15" cy="15" r="3" fill="#a78bfa"/>
    <circle cx="15" cy="15" r="1.2" fill="white"/>
  </svg>
);

const CHECKS = [
  { icon: Lock,  label: 'Cabeceras HTTP',     desc: 'CSP · HSTS · X-Frame · XCTO · Referrer · Permissions', color: 'text-violet-400' },
  { icon: Zap,   label: 'Endpoints criticos', desc: 'xmlrpc · wp-admin · wp-json · debug.log · readme · .env', color: 'text-blue-400' },
  { icon: Eye,   label: 'Enumeracion users',  desc: 'REST API · author bypass · CVSS 3.1 · WAF · SSL/TLS', color: 'text-emerald-400' },
];

const STATS = [
  { n:'09',   l:'headers analizados',   c:'text-violet-400' },
  { n:'14',   l:'endpoints escaneados', c:'text-red-400' },
  { n:'10.0', l:'CVSS score max',       c:'text-emerald-400' },
  { n:'~8s',  l:'tiempo medio',         c:'text-amber-400' },
];

export default function Index() {
  const [isLoading, setIsLoading] = useState(false);
  const [progress, setProgress]   = useState<AuditProgress | null>(null);
  const [result, setResult]       = useState<AuditResult | null>(null);
  const [error, setError]         = useState<string | null>(null);
  const { history, addToHistory, clearHistory } = useAuditHistory();

  const handleAudit = async (url: string) => {
    setIsLoading(true); setError(null); setResult(null);
    setProgress({ step: 'Iniciando...', current: 0, total: 4, percentage: 0 });
    try {
      const r = await auditWordPress(url, setProgress);
      setResult(r); addToHistory(r);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error desconocido');
    } finally { setIsLoading(false); setProgress(null); }
  };

  return (
    <div className="min-h-screen bg-[#030308] text-white font-sans overflow-x-hidden">

      <div className="pointer-events-none fixed inset-x-0 h-28 bg-gradient-to-b from-transparent via-violet-500/[0.04] to-transparent animate-scanline"
        style={{ top: '-112px', zIndex: 50 }} />

      {/* HEADER */}
      <header className="sticky top-0 z-40 border-b border-white/[0.05] bg-[#030308]/85 backdrop-blur-xl">
        <div className="max-w-6xl mx-auto px-5 sm:px-8 h-14 flex items-center justify-between gap-4">
          <div className="flex items-center gap-2.5 shrink-0">
            <div className="animate-float"><HexLogo /></div>
            <div>
              <div className="text-[15px] font-extrabold tracking-tight leading-none">
                WP<span className="text-violet-400">Sentry</span>
              </div>
              <div className="font-mono text-[8px] text-white/20 tracking-[2px] uppercase mt-0.5">security auditor</div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-violet-500/20 bg-violet-500/5 shrink-0">
              <div className="w-1.5 h-1.5 rounded-full bg-violet-400 animate-pulse-dot" />
              <span className="font-mono text-[8px] text-violet-400/60 tracking-[2px] uppercase">online</span>
            </div>
            <AuditHistory history={history} onSelect={handleAudit} onClear={clearHistory} />
            <a href="https://github.com/ccyl13/" target="_blank" rel="noopener noreferrer" className="btn-icon" title="GitHub">
              <Github size={13} />
            </a>
            <a href="https://www.linkedin.com/in/thomasoneil%C3%A1lvarez/" target="_blank" rel="noopener noreferrer" className="btn-icon" title="LinkedIn">
              <Linkedin size={13} />
            </a>
          </div>
        </div>
      </header>

      {/* HERO */}
      <section className="relative overflow-hidden min-h-[85vh] flex flex-col justify-center">
        <div className="pointer-events-none absolute -top-60 -left-60 w-[700px] h-[700px] rounded-full opacity-50"
          style={{ background: 'radial-gradient(circle, rgba(139,92,246,0.15) 0%, transparent 70%)' }} />
        <div className="pointer-events-none absolute top-40 -right-40 w-[500px] h-[500px] rounded-full opacity-30"
          style={{ background: 'radial-gradient(circle, rgba(59,130,246,0.1) 0%, transparent 70%)' }} />
        <div className="pointer-events-none absolute inset-0 bg-grid [mask-image:radial-gradient(ellipse_70%_60%_at_30%_40%,black,transparent)]" />

        <svg className="pointer-events-none absolute top-0 right-0 w-80 h-80 lg:w-[420px] lg:h-[420px] opacity-[0.15] hidden md:block animate-float"
          viewBox="0 0 420 420" fill="none">
          <g transform="translate(120,40)">
            <polygon points="90,0 180,45 180,135 90,180 0,135 0,45" stroke="#a78bfa" strokeWidth="0.8" fill="rgba(139,92,246,0.04)" />
            <polygon points="90,28 138,53 138,103 90,128 42,103 42,53" stroke="#a78bfa" strokeWidth="0.5" fill="rgba(139,92,246,0.06)" strokeOpacity="0.5" />
            <line x1="90" y1="0" x2="90" y2="180" stroke="#a78bfa" strokeWidth="0.4" strokeOpacity="0.35" />
            <line x1="0" y1="90" x2="180" y2="90" stroke="#a78bfa" strokeWidth="0.4" strokeOpacity="0.35" />
            <circle cx="90" cy="90" r="18" stroke="#a78bfa" strokeWidth="0.5" strokeOpacity="0.4" fill="none" />
            <circle cx="90" cy="90" r="5" fill="#a78bfa" fillOpacity="0.45" />
            <ellipse cx="90" cy="90" rx="65" ry="18" stroke="#8b5cf6" strokeWidth="0.5" strokeOpacity="0.25" fill="none" strokeDasharray="3 6" />
          </g>
          <g transform="translate(18,200)" opacity="0.55">
            <polygon points="28,0 56,14 56,42 28,56 0,42 0,14" stroke="#60a5fa" strokeWidth="0.6" fill="rgba(59,130,246,0.05)" />
          </g>
          <circle cx="55" cy="155" r="2" fill="#a78bfa" fillOpacity="0.6" />
          <circle cx="265" cy="72" r="1.5" fill="#60a5fa" fillOpacity="0.5" />
          <circle cx="298" cy="272" r="2" fill="#34d399" fillOpacity="0.4" />
          <line x1="55" y1="155" x2="265" y2="72" stroke="#a78bfa" strokeWidth="0.3" strokeOpacity="0.12" />
          <line x1="265" y1="72" x2="298" y2="272" stroke="#60a5fa" strokeWidth="0.3" strokeOpacity="0.1" />
        </svg>

        <div className="relative max-w-6xl mx-auto px-5 sm:px-8 py-20 sm:py-28 w-full">
          <div className="animate-fade-up flex items-center gap-3 mb-8 flex-wrap">
            <div className="h-px w-6 bg-gradient-to-r from-violet-500 to-transparent shrink-0" />
            <span className="font-mono text-[9px] sm:text-[10px] text-violet-400/55 tracking-[2px] sm:tracking-[3px] uppercase">
              analisis pasivo · sin registro · sin instalacion
            </span>
          </div>

          <h1 className="animate-fade-up delay-100 font-extrabold leading-[0.9] tracking-[-3px] mb-6 max-w-3xl text-[52px] sm:text-[68px] lg:text-[80px]">
            Audita<br />
            <span className="gradient-text">cualquier WordPress</span><br />
            <span className="text-white/[0.08] text-[40px] sm:text-[52px] lg:text-[62px] tracking-[-2px]">en segundos</span>
          </h1>

          <p className="animate-fade-up delay-200 text-sm sm:text-base text-white/40 leading-relaxed mb-10 max-w-lg font-light">
            Cabeceras HTTP, endpoints sensibles, enumeracion de usuarios y puntuacion CVSS 3.1.
            <strong className="text-white/70 font-semibold"> Sin instalar nada.</strong>
          </p>

          <div className="animate-fade-up delay-300 max-w-xl">
            <AuditForm onSubmit={handleAudit} isLoading={isLoading} />
          </div>

          {isLoading && progress && (
            <div className="mt-6 max-w-xl animate-fade-in">
              <ProgressBar progress={progress} />
            </div>
          )}

          {error && (
            <div className="mt-4 max-w-xl animate-fade-in">
              <Alert variant="destructive" className="bg-red-950/30 border-red-500/20">
                <AlertDescription className="font-mono text-xs text-red-400">{error}</AlertDescription>
              </Alert>
            </div>
          )}

          <div className="animate-fade-up delay-400 mt-10 flex flex-wrap gap-3">
            {STATS.map((s, i) => (
              <div key={i} className="flex items-center gap-2 px-3 py-1.5 rounded-full glass border border-white/[0.06]">
                <span className={'font-mono text-[13px] font-extrabold ' + s.c}>{s.n}</span>
                <span className="font-mono text-[9px] text-white/25 uppercase tracking-[1px]">{s.l}</span>
              </div>
            ))}
          </div>

          {!result && !isLoading && (
            <div className="animate-fade-up delay-500 mt-16 flex flex-col items-center gap-2 opacity-30">
              <span className="font-mono text-[9px] tracking-[3px] uppercase text-white/40">scroll</span>
              <div className="w-px h-8 bg-gradient-to-b from-white/20 to-transparent" />
            </div>
          )}
        </div>
      </section>

      {/* FEATURES */}
      {!result && !isLoading && (
        <section className="max-w-6xl mx-auto px-5 sm:px-8 pb-24">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {CHECKS.map(({ icon: Icon, label, desc, color }, i) => (
              <div key={i} className={'animate-fade-up result-card p-6 group cursor-default delay-' + ((i+1)*100)}>
                <div className={'mb-4 transition-transform group-hover:scale-110 ' + color}><Icon size={20} /></div>
                <h3 className="font-bold text-sm mb-2 text-white/85">{label}</h3>
                <p className="font-mono text-[10px] text-white/30 leading-relaxed">{desc}</p>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* LOADING */}
      {isLoading && !result && (
        <div className="max-w-6xl mx-auto px-5 sm:px-8 pb-24 animate-fade-in">
          <AuditLoadingSkeleton />
        </div>
      )}

      {/* RESULTS */}
      {result && (
        <section className="max-w-6xl mx-auto px-5 sm:px-8 pb-24 animate-fade-up">
          <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-4 mb-8 pt-2">
            <div>
              <p className="mono-label mb-1.5">sitio auditado</p>
              <p className="font-mono text-violet-400 font-bold text-base truncate max-w-xs sm:max-w-lg">{result.url}</p>
              <p className="font-mono text-[10px] text-white/20 mt-1">{new Date(result.timestamp).toLocaleString('es-ES')}</p>
            </div>
            <ExportButton result={result} />
          </div>

          {/* Info del sitio a todo ancho */}
          <div className="mb-4">
            <WordPressInfoCard info={result.wordpressInfo} isWordPress={result.isWordPress} wpDetection={result.wpDetection} />
          </div>

          {/* Headers + Endpoints */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
            <SecurityHeadersCard headers={result.securityHeaders} />
            <EndpointsCard endpoints={result.endpoints} />
          </div>

          {/* User enum */}
          <div className="mb-4">
            <UserEnumerationCard userEnumeration={result.userEnumeration} />
          </div>

          <Recommendations result={result} />
        </section>
      )}

      {/* FOOTER */}
      <footer className="border-t border-white/[0.04] py-7 px-5 sm:px-8">
        <div className="max-w-6xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Shield size={11} className="text-violet-400/30" />
            <span className="font-mono text-[9px] text-white/15 tracking-[1px]">WPSENTRY v2.0 · USO ETICO Y EDUCATIVO</span>
          </div>
          <div className="flex items-center gap-5">
            <a href="https://github.com/ccyl13/" target="_blank" rel="noopener noreferrer"
              className="font-mono text-[9px] text-white/20 hover:text-violet-400/60 transition-colors tracking-[0.5px]">github/ccyl13</a>
            <a href="https://www.linkedin.com/in/thomasoneil%C3%A1lvarez/" target="_blank" rel="noopener noreferrer"
              className="font-mono text-[9px] text-white/20 hover:text-violet-400/60 transition-colors tracking-[0.5px]">Thomas Oneil Alvarez</a>
          </div>
        </div>
      </footer>
    </div>
  );
}
