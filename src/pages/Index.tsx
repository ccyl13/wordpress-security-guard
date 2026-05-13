import { useState } from 'react';
import { Github, Linkedin, Shield } from 'lucide-react';
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
      <div className="pointer-events-none fixed inset-x-0 h-[120px] bg-gradient-to-b from-transparent via-violet-500/[0.04] to-transparent animate-scanline z-30" style={{top:'-120px'}}/>

      {/* HEADER */}
      <header className="sticky top-0 z-50 border-b border-white/[0.06] bg-[#030308]/85 backdrop-blur-xl">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 h-14 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="animate-float"><HexLogo/></div>
            <div>
              <span className="text-[15px] font-extrabold tracking-tight">
                WP<span className="text-violet-400">Sentry</span>
              </span>
              <p className="font-mono text-[8px] text-white/20 tracking-[2px] uppercase leading-none mt-0.5">security auditor</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <div className="hidden sm:flex items-center gap-1.5 px-3 py-1 rounded-full border border-violet-500/20 bg-violet-500/5 mr-1">
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

      {/* HERO */}
      <section className="relative min-h-[90vh] flex flex-col justify-center overflow-hidden">
        {/* glow blobs */}
        <div className="absolute -top-40 -left-40 w-[700px] h-[700px] rounded-full pointer-events-none"
          style={{background:'radial-gradient(circle,rgba(139,92,246,0.15) 0%,transparent 70%)'}}/>
        <div className="absolute top-1/4 right-0 w-[400px] h-[400px] rounded-full pointer-events-none"
          style={{background:'radial-gradient(circle,rgba(59,130,246,0.07) 0%,transparent 70%)'}}/>

        {/* grid */}
        <div className="absolute inset-0 bg-grid [mask-image:radial-gradient(ellipse_80%_70%_at_50%_0%,black_30%,transparent)]"/>

        {/* 3D wireframe — right side, desktop only */}
        <svg className="absolute top-0 right-0 w-[420px] h-[420px] pointer-events-none hidden lg:block opacity-20"
          viewBox="0 0 420 420" fill="none">
          <g transform="translate(120,30)">
            <polygon points="100,0 200,50 200,150 100,200 0,150 0,50"
              stroke="#a78bfa" strokeWidth="0.8" fill="rgba(139,92,246,0.04)"/>
            <polygon points="100,30 155,58 155,115 100,143 45,115 45,58"
              stroke="#a78bfa" strokeWidth="0.5" fill="rgba(139,92,246,0.06)" strokeOpacity="0.6"/>
            <line x1="100" y1="0" x2="100" y2="200" stroke="#a78bfa" strokeWidth="0.4" strokeOpacity="0.4"/>
            <line x1="0" y1="100" x2="200" y2="100" stroke="#a78bfa" strokeWidth="0.4" strokeOpacity="0.4"/>
            <circle cx="100" cy="100" r="24" stroke="#a78bfa" strokeWidth="0.6" fill="none" strokeOpacity="0.4"/>
            <circle cx="100" cy="100" r="6" fill="#a78bfa" fillOpacity="0.5"/>
            <ellipse cx="100" cy="100" rx="80" ry="22" stroke="#8b5cf6" strokeWidth="0.5"
              fill="none" strokeOpacity="0.25" strokeDasharray="3 6"/>
          </g>
          <g transform="translate(20,220)" opacity="0.5">
            <polygon points="28,0 56,14 56,42 28,56 0,42 0,14"
              stroke="#60a5fa" strokeWidth="0.6" fill="rgba(59,130,246,0.05)"/>
          </g>
          <circle cx="55" cy="150" r="2" fill="#a78bfa" fillOpacity="0.6"/>
          <circle cx="280" cy="60" r="1.5" fill="#60a5fa" fillOpacity="0.5"/>
          <line x1="55" y1="150" x2="280" y2="60" stroke="#a78bfa" strokeWidth="0.3" strokeOpacity="0.12"/>
        </svg>

        <div className="relative z-10 max-w-6xl mx-auto px-4 sm:px-6 py-20 sm:py-28 w-full">
          {/* eyebrow */}
          <div className="flex items-center gap-3 mb-8 animate-fade-up">
            <div className="h-px w-8 bg-gradient-to-r from-violet-500 to-transparent"/>
            <span className="font-mono text-[10px] text-violet-400/60 tracking-[3px] uppercase">
              análisis pasivo · sin registro · sin instalación
            </span>
          </div>

          {/* headline - gradient text */}
          <h1 className="animate-fade-up delay-100 font-extrabold leading-[0.9] tracking-[-3px] mb-6 max-w-4xl">
            <span className="block text-5xl sm:text-7xl lg:text-8xl text-white">Audita</span>
            <span className="block text-5xl sm:text-7xl lg:text-8xl gradient-text">cualquier WordPress</span>
            <span className="block text-4xl sm:text-5xl lg:text-6xl text-white/10 tracking-[-2px] mt-1">en segundos</span>
          </h1>

          {/* subtitle */}
          <p className="animate-fade-up delay-200 text-base sm:text-lg text-white/40 font-light mb-10 max-w-xl leading-relaxed">
            Cabeceras HTTP, endpoints sensibles, enumeración de
            usuarios y puntuación CVSS 3.1. <strong className="text-white/70 font-semibold">Sin instalar nada.</strong>
          </p>

          {/* form */}
          <div className="animate-fade-up delay-300 max-w-lg">
            <AuditForm onSubmit={handleAudit} isLoading={isLoading}/>
          </div>

          {/* progress */}
          {isLoading && progress && (
            <div className="mt-6 max-w-lg animate-fade-in">
              <ProgressBar progress={progress}/>
            </div>
          )}

          {/* error */}
          {error && (
            <div className="mt-4 max-w-lg animate-fade-in">
              <Alert variant="destructive" className="bg-red-950/30 border-red-500/20">
                <AlertDescription className="font-mono text-xs text-red-400">{error}</AlertDescription>
              </Alert>
            </div>
          )}

          {/* stats pills */}
          <div className="animate-fade-up delay-400 mt-10 flex flex-wrap gap-3">
            {[
              {n:'09', l:'headers analizados',   c:'text-violet-400'},
              {n:'14', l:'endpoints escaneados', c:'text-red-400'},
              {n:'10.0',l:'CVSS score máx',      c:'text-emerald-400'},
              {n:'~8s', l:'tiempo medio',         c:'text-amber-400'},
            ].map((s,i) => (
              <div key={i} className="flex items-center gap-2 px-4 py-2 rounded-full glass border border-white/[0.07]">
                <span className={'font-mono text-sm font-bold ' + s.c}>{s.n}</span>
                <span className="font-mono text-[10px] text-white/30">{s.l}</span>
              </div>
            ))}
          </div>

          {/* scroll hint */}
          {!result && !isLoading && (
            <div className="absolute bottom-8 left-1/2 -translate-x-1/2 flex flex-col items-center gap-1 animate-fade-in delay-500">
              <span className="font-mono text-[9px] text-white/20 tracking-[3px] uppercase">scroll</span>
              <div className="w-px h-8 bg-gradient-to-b from-white/20 to-transparent"/>
            </div>
          )}
        </div>
      </section>

      {/* FEATURE CARDS */}
      {!result && !isLoading && (
        <section className="max-w-6xl mx-auto px-4 sm:px-6 pb-24">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            {[
              { color:'text-violet-400', label:'Cabeceras HTTP', desc:'CSP · HSTS · X-Frame-Options · X-Content-Type · Referrer-Policy · Permissions-Policy y más', ref:'OWASP A05:2021' },
              { color:'text-blue-400',   label:'Endpoints críticos', desc:'xmlrpc.php · wp-admin · wp-json · debug.log · readme.html · wp-config.php.bak · .env', ref:'CWE-749' },
              { color:'text-emerald-400',label:'Usuarios + CVSS 3.1', desc:'REST API · author bypass · score 0.0→10.0 · vector AV:N · WAF detection · SSL/TLS', ref:'A07:2021' },
            ].map(({ color, label, desc, ref }, i) => (
              <div key={i} className={'result-card p-6 group animate-fade-up delay-' + ((i+1)*100)}>
                <div className="flex items-start justify-between mb-4">
                  <div className={'w-2 h-2 rounded-full mt-1.5 ' + color.replace('text-','bg-') + ' shadow-[0_0_8px_currentColor]'}/>
                  <span className={'font-mono text-[9px] ' + color + '/50'}>{ref}</span>
                </div>
                <h3 className="font-bold text-sm mb-2 text-white/90">{label}</h3>
                <p className="font-mono text-[10px] text-white/30 leading-relaxed">{desc}</p>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* LOADING */}
      {isLoading && !result && (
        <div className="max-w-6xl mx-auto px-4 sm:px-6 pb-24 animate-fade-in">
          <AuditLoadingSkeleton/>
        </div>
      )}

      {/* RESULTS */}
      {result && (
        <section className="max-w-6xl mx-auto px-4 sm:px-6 pb-24 animate-fade-up">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 mb-8 pt-2">
            <div>
              <p className="mono-label mb-1">sitio auditado</p>
              <p className="font-mono text-violet-400 font-bold text-base sm:text-lg break-all">{result.url}</p>
              <p className="font-mono text-[10px] text-white/20 mt-1">{new Date(result.timestamp).toLocaleString('es-ES')}</p>
            </div>
            <ExportButton result={result}/>
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4">
            <ScoreGauge score={result.overallScore} cvss={result.cvssOverall}/>
            <div className="lg:col-span-2">
              <WordPressInfoCard info={result.wordpressInfo} isWordPress={result.isWordPress} wpDetection={result.wpDetection}/>
            </div>
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
            <SecurityHeadersCard headers={result.securityHeaders}/>
            <EndpointsCard endpoints={result.endpoints}/>
          </div>
          <div className="mb-4">
            <UserEnumerationCard userEnumeration={result.userEnumeration}/>
          </div>
          <Recommendations result={result}/>
        </section>
      )}

      {/* FOOTER */}
      <footer className="border-t border-white/[0.05] py-6 px-4 sm:px-6">
        <div className="max-w-6xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Shield size={12} className="text-violet-400/40"/>
            <span className="font-mono text-[9px] text-white/15 tracking-[1px]">WPSENTRY v2.0 · USO ÉTICO Y EDUCATIVO</span>
          </div>
          <div className="flex items-center gap-5">
            <a href="https://github.com/ccyl13/" target="_blank" rel="noopener noreferrer"
              className="font-mono text-[9px] text-white/20 hover:text-violet-400/60 transition-colors tracking-[0.5px]">ccyl13</a>
            <a href="https://www.linkedin.com/in/thomasoneil%C3%A1lvarez/" target="_blank" rel="noopener noreferrer"
              className="font-mono text-[9px] text-white/20 hover:text-violet-400/60 transition-colors tracking-[0.5px]">Thomas Oneil Álvarez</a>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Index;
