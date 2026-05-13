import { useState } from 'react';
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
import { AlertTriangle, Github, Linkedin, ShieldCheck, Zap, Eye } from 'lucide-react';
import { Alert, AlertDescription } from '@/components/ui/alert';

const HexLogo = () => (
  <svg width="30" height="30" viewBox="0 0 30 30" fill="none">
    <polygon points="15,1 28,8 28,22 15,29 2,22 2,8" fill="#8b5cf6" fillOpacity=".18" stroke="#a78bfa" strokeWidth=".8"/>
    <polygon points="15,6 24,11 24,19 15,24 6,19 6,11" fill="#8b5cf6" fillOpacity=".3" stroke="#a78bfa" strokeWidth=".5"/>
    <circle cx="15" cy="15" r="3.5" fill="#a78bfa"/>
    <circle cx="15" cy="15" r="1.5" fill="#fff"/>
  </svg>
);

const STATS = [
  { n: '09', l: 'headers HTTP',  c: 'text-purple-light' },
  { n: '14', l: 'endpoints',     c: 'text-red-400' },
  { n: '10.0', l: 'CVSS max',    c: 'text-emerald-400' },
  { n: '<10s', l: 'tiempo medio', c: 'text-amber-400' },
];

const FEATURES = [
  { icon: ShieldCheck, title: 'Cabeceras HTTP', desc: 'CSP · HSTS · X-Frame · X-Content-Type · Referrer-Policy y más con referencias OWASP y CWE', color: 'text-purple-light', border: 'hover:border-purple-500/30' },
  { icon: Zap,         title: 'Endpoints críticos', desc: '/xmlrpc.php · /wp-login · /wp-admin · /wp-json · /readme.html · /.env · /debug.log', color: 'text-blue-400', border: 'hover:border-blue-500/30' },
  { icon: Eye,         title: 'Users + CVSS 3.1', desc: 'Enumeración via REST API y author archives · Score 0–10 · Vector AV:N/AC:L · WAF detection', color: 'text-emerald-400', border: 'hover:border-emerald-500/30' },
];

const Index = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [progress, setProgress] = useState<AuditProgress | null>(null);
  const [result, setResult] = useState<AuditResult | null>(null);
  const [error, setError] = useState<string | null>(null);
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
    <div className="noise min-h-screen bg-bg text-white overflow-x-hidden">
      <div className="scanline" />

      {/* ── HEADER ── */}
      <header className="sticky top-0 z-50 border-b border-white/[0.06] bg-bg/80 backdrop-blur-xl">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 h-14 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <HexLogo />
            <div>
              <div className="text-[15px] font-extrabold tracking-tight leading-none">
                WP<span className="text-purple">Sentry</span>
              </div>
              <div className="mono text-[8px] text-white/20 tracking-[2px] mt-0.5">SECURITY AUDITOR</div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-purple/20 mono text-[9px] text-purple/70 tracking-widest">
              <div className="dot-live" />
              ONLINE
            </div>
            <AuditHistory history={history} onSelect={handleAudit} onClear={clearHistory} />
            {[
              { Icon: Github, href: 'https://github.com/ccyl13/', label: 'GitHub' },
              { Icon: Linkedin, href: 'https://www.linkedin.com/in/thomasoneil%C3%A1lvarez/', label: 'LinkedIn' },
            ].map(({ Icon, href, label }) => (
              <a key={label} href={href} target="_blank" rel="noopener noreferrer"
                className="w-8 h-8 rounded-lg glass flex items-center justify-center text-white/30 hover:text-purple-light hover:border-purple/30 transition-all duration-200 hover:-translate-y-0.5">
                <Icon size={13} />
              </a>
            ))}
          </div>
        </div>
      </header>

      {/* ── HERO ── */}
      <section className="relative pt-24 pb-16 px-4 sm:px-6 overflow-hidden">
        {/* Glow orbs */}
        <div className="glow-orb w-[600px] h-[600px] bg-purple/[0.12] top-[-200px] left-1/2 -translate-x-1/2 animate-glow" />
        <div className="glow-orb w-[400px] h-[400px] bg-purple/[0.07] top-32 left-[-100px]" />
        <div className="glow-orb w-[300px] h-[300px] bg-blue-600/[0.05] top-16 right-[-50px]" />

        {/* 3D SVG */}
        <div className="absolute inset-0 pointer-events-none overflow-hidden">
          <svg className="absolute right-0 top-0 w-[55%] max-w-[500px] opacity-40" viewBox="0 0 400 400" fill="none">
            <g transform="translate(200,60)">
              <polygon points="80,0 160,40 160,120 80,160 0,120 0,40" fill="#8b5cf6" fillOpacity=".05" stroke="#a78bfa" strokeWidth=".8" strokeOpacity=".5"/>
              <polygon points="80,20 136,50 136,110 80,140 24,110 24,50" fill="none" stroke="#a78bfa" strokeWidth=".5" strokeOpacity=".35"/>
              <polygon points="80,40 112,58 112,100 80,118 48,100 48,58" fill="#8b5cf6" fillOpacity=".07" stroke="#a78bfa" strokeWidth=".4" strokeOpacity=".3"/>
              <circle cx="80" cy="80" r="8" fill="#a78bfa" fillOpacity=".3"/>
              <circle cx="80" cy="80" r="3" fill="#a78bfa" fillOpacity=".7"/>
              <line x1="80" y1="0" x2="80" y2="160" stroke="#a78bfa" strokeWidth=".3" strokeOpacity=".2"/>
              <line x1="0" y1="80" x2="160" y2="80" stroke="#a78bfa" strokeWidth=".3" strokeOpacity=".2"/>
            </g>
            <g transform="translate(300,200)" opacity=".5">
              <polygon points="30,0 60,15 60,45 30,60 0,45 0,15" fill="#3b82f6" fillOpacity=".08" stroke="#60a5fa" strokeWidth=".6" strokeOpacity=".4"/>
              <polygon points="30,10 48,20 48,40 30,50 12,40 12,20" fill="none" stroke="#60a5fa" strokeWidth=".3" strokeOpacity=".3"/>
            </g>
            <ellipse cx="240" cy="160" rx="120" ry="28" fill="none" stroke="#8b5cf6" strokeWidth=".5" strokeOpacity=".12" strokeDasharray="3 8"/>
            <circle cx="130" cy="90" r="2" fill="#8b5cf6" fillOpacity=".6"/>
            <circle cx="360" cy="130" r="1.5" fill="#3b82f6" fillOpacity=".5"/>
            <circle cx="290" cy="240" r="1.5" fill="#10b981" fillOpacity=".5"/>
            <line x1="130" y1="90" x2="360" y2="130" stroke="#8b5cf6" strokeWidth=".3" strokeOpacity=".1"/>
            <line x1="360" y1="130" x2="290" y2="240" stroke="#3b82f6" strokeWidth=".3" strokeOpacity=".08"/>
          </svg>
          {/* Perspective grid */}
          <svg className="absolute bottom-0 left-0 right-0 w-full opacity-[0.04]" viewBox="0 0 800 200" preserveAspectRatio="xMidYMax slice">
            {[0,80,160,240,320,400,480,560,640,720,800].map((x,i) => <line key={i} x1="400" y1="0" x2={x} y2="200" stroke="#8b5cf6" strokeWidth=".8"/>)}
            {[50,100,150].map((y,i) => <line key={i} x1="0" y1={y} x2="800" y2={y} stroke="#8b5cf6" strokeWidth=".8"/>)}
          </svg>
        </div>

        <div className="relative max-w-4xl mx-auto text-center">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full glass-purple mono text-[10px] text-purple-light/80 tracking-[2px] uppercase mb-8 animate-fade-in">
            <div className="dot-live" />
            análisis pasivo · sin registro · sin instalación
          </div>
          <h1 className="text-5xl sm:text-6xl md:text-7xl font-extrabold leading-[0.9] tracking-tight mb-6 animate-fade-up">
            Audita cualquier<br />
            <span className="text-gradient">WordPress</span>
            <br />
            <span className="text-white/15 text-4xl sm:text-5xl md:text-6xl">en segundos</span>
          </h1>
          <p className="mono text-sm text-white/40 max-w-md mx-auto mb-10 leading-relaxed animate-fade-up delay-100">
            <span className="text-purple/70">$</span> cabeceras · endpoints · users · cvss 3.1<br />
            <span className="text-purple/70">→</span> sin tocar el servidor. sin dejar rastro.
          </p>
          <div className="animate-fade-up delay-200">
            <AuditForm onSubmit={handleAudit} isLoading={isLoading} />
          </div>
        </div>

        {/* Stats strip */}
        <div className="relative max-w-2xl mx-auto mt-14 grid grid-cols-4 divide-x divide-white/[0.06] border border-white/[0.06] rounded-2xl glass animate-fade-up delay-300">
          {STATS.map((s, i) => (
            <div key={i} className="px-4 py-4 text-center">
              <div className={`mono text-xl font-bold ${s.c}`}>{s.n}</div>
              <div className="mono text-[9px] text-white/25 uppercase tracking-widest mt-1">{s.l}</div>
            </div>
          ))}
        </div>
      </section>

      {/* ── PROGRESS / ERROR ── */}
      {isLoading && progress && (
        <div className="max-w-6xl mx-auto px-4 sm:px-6 pb-4 animate-fade-in">
          <ProgressBar progress={progress} />
        </div>
      )}
      {error && (
        <div className="max-w-6xl mx-auto px-4 sm:px-6 pb-6 animate-fade-in">
          <Alert variant="destructive" className="border-red-500/20 bg-red-500/5">
            <AlertTriangle className="w-4 h-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        </div>
      )}

      {/* ── FEATURES (no result) ── */}
      {!result && !isLoading && (
        <section className="max-w-6xl mx-auto px-4 sm:px-6 pb-24">
          <div className="divider mb-16" />
          <div className="text-center mb-12">
            <div className="mono text-[10px] text-purple/60 tracking-[3px] uppercase mb-3">qué analiza</div>
            <h2 className="text-3xl sm:text-4xl font-extrabold tracking-tight">
              Auditoría completa.<br /><span className="text-white/30">Sin instalar nada.</span>
            </h2>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {FEATURES.map(({ icon: Icon, title, desc, color, border }, i) => (
              <div key={i} className={`glass rounded-2xl p-6 transition-all duration-300 hover-lift hover:shadow-card-hover cursor-default border border-white/[0.07] ${border} animate-fade-up`}
                style={{ animationDelay: i * 80 + 'ms' }}>
                <div className={`w-10 h-10 rounded-xl glass-purple flex items-center justify-center mb-4 ${color}`}>
                  <Icon size={18} />
                </div>
                <h3 className="font-bold text-sm mb-2">{title}</h3>
                <p className="mono text-[10px] text-white/35 leading-relaxed">{desc}</p>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* ── SKELETON ── */}
      {isLoading && !result && (
        <div className="max-w-6xl mx-auto px-4 sm:px-6 pb-16 animate-fade-in">
          <AuditLoadingSkeleton />
        </div>
      )}

      {/* ── RESULTS ── */}
      {result && (
        <section className="max-w-6xl mx-auto px-4 sm:px-6 pb-24 animate-fade-up">
          <div className="divider mb-8" />
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-8">
            <div>
              <div className="mono text-[9px] text-white/25 tracking-[2px] uppercase mb-1">sitio auditado</div>
              <div className="mono text-purple font-bold text-base truncate max-w-sm sm:max-w-lg">{result.url}</div>
              <div className="mono text-[9px] text-white/20 mt-1">{new Date(result.timestamp).toLocaleString('es-ES')}</div>
            </div>
            <ExportButton result={result} />
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4">
            <ScoreGauge score={result.overallScore} cvss={result.cvssOverall} />
            <div className="lg:col-span-2">
              <WordPressInfoCard info={result.wordpressInfo} isWordPress={result.isWordPress} wpDetection={result.wpDetection} />
            </div>
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
            <SecurityHeadersCard headers={result.securityHeaders} />
            <EndpointsCard endpoints={result.endpoints} />
          </div>
          <div className="mb-4">
            <UserEnumerationCard userEnumeration={result.userEnumeration} />
          </div>
          <Recommendations result={result} />
        </section>
      )}

      {/* ── FOOTER ── */}
      <footer className="border-t border-white/[0.05] py-8 px-4">
        <div className="max-w-6xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <HexLogo />
            <div>
              <div className="text-sm font-bold">WP<span className="text-purple">Sentry</span></div>
              <div className="mono text-[8px] text-white/20 tracking-widest">USO ÉTICO Y EDUCATIVO</div>
            </div>
          </div>
          <div className="flex items-center gap-6">
            {[
              { label: '↗ github.com/ccyl13', href: 'https://github.com/ccyl13/' },
              { label: '↗ Thomas Oneil', href: 'https://www.linkedin.com/in/thomasoneil%C3%A1lvarez/' },
            ].map(({ label, href }) => (
              <a key={label} href={href} target="_blank" rel="noopener noreferrer"
                className="mono text-[10px] text-white/25 hover:text-purple-light transition-colors duration-200">
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
