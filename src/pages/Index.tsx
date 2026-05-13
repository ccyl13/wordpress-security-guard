import { useState } from 'react';
import { Github, Linkedin, Shield, ChevronRight, Zap, Lock, Eye, FileJson } from 'lucide-react';
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
import { ScoreGauge } from '@/components/ScoreGauge';
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
  { icon: Lock,  label: 'Cabeceras HTTP',    desc: 'CSP · HSTS · X-Frame · XCTO · Referrer · Permissions', color: 'text-violet-400' },
  { icon: Zap,   label: 'Endpoints criticos', desc: 'xmlrpc · wp-admin · wp-json · debug.log · readme · .env', color: 'text-blue-400' },
  { icon: Eye,   label: 'Enumeracion users',  desc: 'REST API · author bypass · CVSS 3.1 · WAF · SSL', color: 'text-emerald-400' },
];

const Index = () => {
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

      {/* scanline */}
      <div className="pointer-events-none fixed inset-x-0 h-[100px] bg-gradient-to-b from-transparent via-violet-500/5 to-transparent animate-scanline z-50" style={{top:'-100px'}}/>

      {/* ── HEADER ─────────────────────────────── */}
      <header className="sticky top-0 z-40 border-b border-white/[0.06] bg-[#030308]/80 backdrop-blur-xl">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 h-14 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="animate-float"><HexLogo/></div>
            <div>
              <span className="text-[15px] font-extrabold tracking-tight">
                WP<span className="text-violet-400">Sentry</span>
              </span>
              <p className="font-mono text-[9px] text-white/20 tracking-[2px] uppercase leading-none mt-0.5">security auditor</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <div className="hidden sm:flex items-center gap-1.5 px-3 py-1 rounded-full border border-violet-500/20 bg-violet-500/5">
              <div className="w-1.5 h-1.5 rounded-full bg-violet-400 animate-pulse-dot"/>
              <span className="font-mono text-[9px] text-violet-400/70 tracking-[2px]">ONLINE</span>
            </div>
            <AuditHistory history={history} onSelect={handleAudit} onClear={clearHistory}/>
            <a href="https://github.com/ccyl13/" target="_blank" rel="noopener noreferrer" className="btn-icon" title="GitHub">
              <Github size={14}/>
            </a>
            <a href="https://www.linkedin.com/in/thomasoneil%C3%A1lvarez/" target="_blank" rel="noopener noreferrer" className="btn-icon" title="LinkedIn">
              <Linkedin size={14}/>
            </a>
          </div>
        </div>
      </header>

      {/* ── HERO ───────────────────────────────── */}
      <section className="relative overflow-hidden">
        {/* glow blobs */}
        <div className="glow-blob-purple w-[600px] h-[600px] -top-40 -left-40 opacity-60"/>
        <div className="glow-blob-purple w-[400px] h-[400px] top-20 right-0 opacity-30"
          style={{background:'radial-gradient(circle,rgba(59,130,246,0.12) 0%,transparent 70%)'}}/>

        {/* grid */}
        <div className="absolute inset-0 bg-grid opacity-100 [mask-image:radial-gradient(ellipse_80%_60%_at_50%_0%,black,transparent)]"/>

        {/* 3D wireframe SVG */}
        <svg className="absolute top-0 right-0 w-[480px] h-[480px] opacity-[0.18] pointer-events-none hidden lg:block"
          viewBox="0 0 480 480" fill="none">
          <g transform="translate(180,40)">
            <polygon points="100,0 200,50 200,150 100,200 0,150 0,50"
              stroke="#a78bfa" strokeWidth="0.8" fill="rgba(139,92,246,0.04)"/>
            <polygon points="100,30 155,58 155,115 100,143 45,115 45,58"
              stroke="#a78bfa" strokeWidth="0.5" fill="rgba(139,92,246,0.06)" strokeOpacity="0.6"/>
            <line x1="100" y1="0" x2="100" y2="200" stroke="#a78bfa" strokeWidth="0.4" strokeOpacity="0.4"/>
            <line x1="0" y1="100" x2="200" y2="100" stroke="#a78bfa" strokeWidth="0.4" strokeOpacity="0.4"/>
            <circle cx="100" cy="100" r="20" stroke="#a78bfa" strokeWidth="0.5" strokeOpacity="0.5" fill="none"/>
            <circle cx="100" cy="100" r="6" fill="#a78bfa" fillOpacity="0.4"/>
            <ellipse cx="100" cy="100" rx="70" ry="20" stroke="#8b5cf6" strokeWidth="0.5" strokeOpacity="0.3"
              fill="none" strokeDasharray="3 6"/>
          </g>
          <g transform="translate(20,200)" opacity="0.6">
            <polygon points="30,0 60,15 60,45 30,60 0,45 0,15"
              stroke="#60a5fa" strokeWidth="0.6" fill="rgba(59,130,246,0.05)"/>
          </g>
          <g transform="translate(280,280)" opacity="0.5">
            <polygon points="24,0 48,12 48,36 24,48 0,36 0,12"
              stroke="#a78bfa" strokeWidth="0.5" fill="rgba(139,92,246,0.04)"/>
          </g>
          <circle cx="60" cy="160" r="2" fill="#a78bfa" fillOpacity="0.6"/>
          <circle cx="300" cy="80" r="1.5" fill="#60a5fa" fillOpacity="0.5"/>
          <circle cx="340" cy="300" r="2" fill="#34d399" fillOpacity="0.4"/>
          <line x1="60" y1="160" x2="300" y2="80" stroke="#a78bfa" strokeWidth="0.3" strokeOpacity="0.15"/>
          <line x1="300" y1="80" x2="340" y2="300" stroke="#60a5fa" strokeWidth="0.3" strokeOpacity="0.12"/>
        </svg>

        <div className="relative max-w-6xl mx-auto px-4 sm:px-6 pt-20 pb-16 sm:pt-28 sm:pb-20">

          {/* eyebrow */}
          <div className="animate-fade-up flex items-center gap-3 mb-8">
            <div className="h-px w-8 bg-gradient-to-r from-violet-500 to-transparent"/>
            <span className="font-mono text-[10px] text-violet-400/60 tracking-[3px] uppercase">
              analisis pasivo · sin registro · sin instalacion
            </span>
          </div>

          {/* headline */}
          <h1 className="animate-fade-up delay-100 text-5xl sm:text-6xl lg:text-7xl font-extrabold leading-[0.92] tracking-[-3px] mb-6 max-w-3xl">
            Audita<br/>
            <span className="gradient-text">cualquier WordPress</span><br/>
            <span className="text-white/10 text-4xl sm:text-5xl lg:text-6xl tracking-[-2px]">en segundos</span>
          </h1>

          {/* sub */}
          <p className="animate-fade-up delay-200 font-mono text-[12px] text-white/35 leading-relaxed mb-10 max-w-md">
            <span className="text-violet-400/60">$</span> cabeceras · endpoints · users · cvss 3.1<br/>
            <span className="text-violet-400/60">→</span> sin tocar el servidor. sin dejar rastro.
          </p>

          {/* form */}
          <div className="animate-fade-up delay-300 max-w-xl">
            <AuditForm onSubmit={handleAudit} isLoading={isLoading}/>
          </div>

          {/* progress */}
          {isLoading && progress && (
            <div className="mt-6 max-w-xl animate-fade-in">
              <ProgressBar progress={progress}/>
            </div>
          )}

          {/* error */}
          {error && (
            <div className="mt-4 max-w-xl animate-fade-in">
              <Alert variant="destructive" className="bg-red-950/30 border-red-500/20 text-red-400">
                <AlertDescription className="font-mono text-xs">{error}</AlertDescription>
              </Alert>
            </div>
          )}

          {/* stats bar */}
          <div className="animate-fade-up delay-400 mt-12 flex gap-0 border border-white/[0.06] rounded-2xl overflow-hidden max-w-xl glass">
            {[
              { n:'09', l:'headers',   c:'text-violet-400' },
              { n:'14', l:'endpoints', c:'text-red-400' },
              { n:'10.0', l:'cvss max', c:'text-emerald-400' },
              { n:'~8s', l:'avg scan', c:'text-amber-400' },
            ].map((s,i,a) => (
              <div key={i} className={'flex-1 px-4 py-3 ' + (i < a.length-1 ? 'border-r border-white/[0.06]' : '')}>
                <div className={'text-[17px] font-extrabold font-mono tracking-[-1px] leading-none mb-1 ' + s.c}>{s.n}</div>
                <div className="font-mono text-[8px] text-white/20 tracking-[1.5px] uppercase">{s.l}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ── FEATURE CARDS (no results) ─────────── */}
      {!result && !isLoading && (
        <section className="max-w-6xl mx-auto px-4 sm:px-6 pb-20">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {CHECKS.map(({ icon: Icon, label, desc, color }, i) => (
              <div key={i} className={'animate-fade-up result-card p-6 delay-' + ((i+1)*100)}>
                <div className={'mb-4 ' + color}><Icon size={20}/></div>
                <h3 className="font-bold text-sm mb-2 text-white/90">{label}</h3>
                <p className="font-mono text-[10px] text-white/30 leading-relaxed">{desc}</p>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* ── LOADING SKELETON ───────────────────── */}
      {isLoading && !result && (
        <div className="max-w-6xl mx-auto px-4 sm:px-6 pb-20 animate-fade-in">
          <AuditLoadingSkeleton/>
        </div>
      )}

      {/* ── RESULTS ────────────────────────────── */}
      {result && (
        <section className="max-w-6xl mx-auto px-4 sm:px-6 pb-20 animate-fade-up">

          {/* result header */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-8 pt-2">
            <div>
              <p className="mono-label mb-1">sitio auditado</p>
              <p className="font-mono text-violet-400 font-bold text-base sm:text-lg truncate max-w-sm sm:max-w-xl">{result.url}</p>
              <p className="font-mono text-[10px] text-white/20 mt-1">{new Date(result.timestamp).toLocaleString('es-ES')}</p>
            </div>
            <ExportButton result={result}/>
          </div>

          {/* score + info */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4">
            <ScoreGauge score={result.overallScore} cvss={result.cvssOverall}/>
            <div className="lg:col-span-2">
              <WordPressInfoCard info={result.wordpressInfo} isWordPress={result.isWordPress} wpDetection={result.wpDetection}/>
            </div>
          </div>

          {/* headers + endpoints */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
            <SecurityHeadersCard headers={result.securityHeaders}/>
            <EndpointsCard endpoints={result.endpoints}/>
          </div>

          {/* user enum */}
          <div className="mb-4">
            <UserEnumerationCard userEnumeration={result.userEnumeration}/>
          </div>

          {/* recommendations */}
          <Recommendations result={result}/>
        </section>
      )}

      {/* ── FOOTER ─────────────────────────────── */}
      <footer className="border-t border-white/[0.05] py-6 px-4 sm:px-6">
        <div className="max-w-6xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Shield size={12} className="text-violet-400/40"/>
            <span className="font-mono text-[9px] text-white/15 tracking-[1px]">WPSENTRY v2.0 · USO ÉTICO Y EDUCATIVO</span>
          </div>
          <div className="flex items-center gap-5">
            {[
              { label:'ccyl13', href:'https://github.com/ccyl13/' },
              { label:'Thomas Oneil', href:'https://www.linkedin.com/in/thomasoneil%C3%A1lvarez/' },
            ].map(({ label, href }) => (
              <a key={label} href={href} target="_blank" rel="noopener noreferrer"
                className="font-mono text-[9px] text-white/20 hover:text-violet-400/60 transition-colors tracking-[0.5px]">
                {label}
              </a>
            ))}
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Index;
