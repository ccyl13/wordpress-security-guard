import { useState, useEffect, useRef } from 'react';
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
import { AlertTriangle, Github, Linkedin, Shield, Zap, Lock, Globe, ChevronRight } from 'lucide-react';

const CHECKS = [
  { icon: Shield,  label: 'Cabeceras HTTP',      desc: 'CSP · HSTS · X-Frame · XCTO y más',    color: '#8b5cf6' },
  { icon: Globe,   label: 'Endpoints críticos',  desc: 'xmlrpc · wp-admin · debug.log · .env',  color: '#3b82f6' },
  { icon: Zap,     label: 'Enumeración users',   desc: 'REST API · author archive bypass',       color: '#10b981' },
  { icon: Lock,    label: 'Score CVSS 3.1',       desc: 'Vector AV:N · recomendaciones reales',  color: '#f59e0b' },
];

const HexIcon = () => (
  <svg width="30" height="30" viewBox="0 0 30 30" fill="none">
    <polygon points="15,1 28,8 28,22 15,29 2,22 2,8" fill="rgba(139,92,246,0.2)" stroke="rgba(167,139,250,0.6)" strokeWidth="0.8"/>
    <polygon points="15,7 24,12 24,20 15,24 6,20 6,12" fill="rgba(139,92,246,0.35)" stroke="rgba(167,139,250,0.4)" strokeWidth="0.5"/>
    <circle cx="15" cy="15" r="3.5" fill="#a78bfa"/>
    <circle cx="15" cy="15" r="1.5" fill="white"/>
  </svg>
);

export default function Index() {
  const [isLoading, setIsLoading] = useState(false);
  const [progress, setProgress] = useState<AuditProgress | null>(null);
  const [result, setResult] = useState<AuditResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [mousePos, setMousePos] = useState({ x: 0, y: 0 });
  const heroRef = useRef<HTMLDivElement>(null);
  const { history, addToHistory, clearHistory } = useAuditHistory();

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (!heroRef.current) return;
      const rect = heroRef.current.getBoundingClientRect();
      setMousePos({
        x: ((e.clientX - rect.left) / rect.width) * 100,
        y: ((e.clientY - rect.top) / rect.height) * 100,
      });
    };
    window.addEventListener('mousemove', handler);
    return () => window.removeEventListener('mousemove', handler);
  }, []);

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
    <div className="min-h-screen bg-black text-white overflow-x-hidden">

      {/* ── HEADER ── */}
      <header className="fixed top-0 inset-x-0 z-50 border-b border-white/5" style={{ background: 'rgba(0,0,0,0.8)', backdropFilter: 'blur(20px)', WebkitBackdropFilter: 'blur(20px)' }}>
        <div className="max-w-6xl mx-auto px-4 sm:px-6 h-14 flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <HexIcon/>
            <div>
              <div className="text-[15px] font-bold tracking-tight leading-none">
                WP<span style={{ color: '#8b5cf6' }}>Sentry</span>
              </div>
              <div className="mono text-[8px] text-white/20 tracking-[2px] mt-0.5">SECURITY AUDITOR</div>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <div className="hidden sm:flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-white/8 mono text-[9px] text-white/30 tracking-widest">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" style={{ animation: 'blink 2s ease-in-out infinite', boxShadow: '0 0 6px #10b981' }}/>
              ONLINE
            </div>
            <AuditHistory history={history} onSelect={handleAudit} onClear={clearHistory}/>
            {[
              { href: 'https://github.com/ccyl13/', icon: Github, label: 'GitHub' },
              { href: 'https://www.linkedin.com/in/thomasoneil%C3%A1lvarez/', icon: Linkedin, label: 'LinkedIn' },
            ].map(({ href, icon: Icon, label }) => (
              <a key={label} href={href} target="_blank" rel="noopener noreferrer"
                className="w-8 h-8 rounded-lg border border-white/8 flex items-center justify-center text-white/30 transition-all duration-200 hover:border-purple-500/40 hover:text-purple-400 hover:bg-purple-500/10"
                style={{ background: 'rgba(255,255,255,0.03)' }}>
                <Icon size={13}/>
              </a>
            ))}
          </div>
        </div>
      </header>

      {/* ── HERO ── */}
      <section ref={heroRef} className="relative min-h-screen flex flex-col items-center justify-center px-4 pt-14 overflow-hidden">

        {/* ambient glow that follows mouse */}
        <div className="absolute inset-0 pointer-events-none" style={{ background: 'radial-gradient(600px circle at ' + mousePos.x + '% ' + mousePos.y + '%, rgba(139,92,246,0.07) 0%, transparent 70%)', transition: 'background 0.3s ease' }}/>

        {/* static glows */}
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[400px] rounded-full pointer-events-none" style={{ background: 'radial-gradient(ellipse, rgba(139,92,246,0.12) 0%, transparent 70%)', filter: 'blur(60px)', animation: 'glow-pulse 5s ease-in-out infinite' }}/>
        <div className="absolute bottom-1/4 left-1/4 w-64 h-64 rounded-full pointer-events-none" style={{ background: 'radial-gradient(circle, rgba(59,130,246,0.08) 0%, transparent 70%)', filter: 'blur(40px)' }}/>

        {/* grid mesh */}
        <div className="absolute inset-0 pointer-events-none" style={{
          backgroundImage: 'linear-gradient(rgba(139,92,246,0.04) 1px, transparent 1px), linear-gradient(90deg, rgba(139,92,246,0.04) 1px, transparent 1px)',
          backgroundSize: '60px 60px',
          maskImage: 'radial-gradient(ellipse 80% 60% at 50% 40%, black 40%, transparent 100%)',
          WebkitMaskImage: 'radial-gradient(ellipse 80% 60% at 50% 40%, black 40%, transparent 100%)',
        }}/>

        {/* 3D wireframe cubes */}
        <svg className="absolute inset-0 w-full h-full pointer-events-none opacity-30" viewBox="0 0 1200 800" preserveAspectRatio="xMidYMid slice">
          <g transform="translate(900,80)" opacity="0.6" style={{ animation: 'float 8s ease-in-out infinite' }}>
            <polygon points="80,0 160,40 80,80 0,40" fill="rgba(139,92,246,0.06)" stroke="rgba(167,139,250,0.35)" strokeWidth="0.7"/>
            <polygon points="0,40 80,80 80,160 0,120" fill="rgba(139,92,246,0.04)" stroke="rgba(124,58,237,0.3)" strokeWidth="0.7"/>
            <polygon points="80,80 160,40 160,120 80,160" fill="rgba(109,40,217,0.06)" stroke="rgba(124,58,237,0.25)" strokeWidth="0.7"/>
            <line x1="80" y1="0" x2="80" y2="80" stroke="rgba(167,139,250,0.2)" strokeWidth="0.5"/>
            <line x1="0" y1="40" x2="160" y2="40" stroke="rgba(167,139,250,0.15)" strokeWidth="0.5"/>
            <polygon points="80,20 120,40 80,60 40,40" fill="rgba(139,92,246,0.08)" stroke="rgba(167,139,250,0.3)" strokeWidth="0.5"/>
            <circle cx="80" cy="40" r="3" fill="rgba(167,139,250,0.6)"/>
          </g>
          <g transform="translate(80,100)" opacity="0.45" style={{ animation: 'float 10s ease-in-out infinite', animationDelay: '-3s' }}>
            <polygon points="50,0 100,25 50,50 0,25" fill="rgba(139,92,246,0.06)" stroke="rgba(167,139,250,0.3)" strokeWidth="0.7"/>
            <polygon points="0,25 50,50 50,100 0,75" fill="rgba(139,92,246,0.04)" stroke="rgba(124,58,237,0.25)" strokeWidth="0.7"/>
            <polygon points="50,50 100,25 100,75 50,100" fill="rgba(109,40,217,0.06)" stroke="rgba(124,58,237,0.2)" strokeWidth="0.7"/>
          </g>
          <g transform="translate(1050,300)" opacity="0.35" style={{ animation: 'float 7s ease-in-out infinite', animationDelay: '-5s' }}>
            <polygon points="30,0 60,15 30,30 0,15" fill="rgba(59,130,246,0.08)" stroke="rgba(96,165,250,0.3)" strokeWidth="0.6"/>
            <polygon points="0,15 30,30 30,60 0,45" fill="rgba(37,99,235,0.05)" stroke="rgba(59,130,246,0.2)" strokeWidth="0.6"/>
            <polygon points="30,30 60,15 60,45 30,60" fill="rgba(29,78,216,0.08)" stroke="rgba(59,130,246,0.18)" strokeWidth="0.6"/>
          </g>
          <ellipse cx="600" cy="320" rx="300" ry="60" fill="none" stroke="rgba(139,92,246,0.08)" strokeWidth="0.8" strokeDasharray="3 9"/>
          <circle cx="240" cy="180" r="2" fill="rgba(139,92,246,0.6)"/>
          <circle cx="960" cy="250" r="1.5" fill="rgba(59,130,246,0.5)"/>
          <circle cx="700" cy="420" r="1.5" fill="rgba(16,185,129,0.4)"/>
          <line x1="240" y1="180" x2="960" y2="250" stroke="rgba(139,92,246,0.06)" strokeWidth="0.5"/>
        </svg>

        {/* content */}
        <div className="relative z-10 text-center max-w-4xl mx-auto w-full">

          {/* pill badge */}
          <div className="animate-fade-up inline-flex items-center gap-2 px-4 py-1.5 rounded-full border border-white/10 mb-8 mono text-[10px] text-white/40 tracking-widest" style={{ background: 'rgba(139,92,246,0.08)' }}>
            <span className="w-1 h-1 rounded-full bg-purple-400" style={{ boxShadow: '0 0 6px #a78bfa' }}/>
            ANÁLISIS PASIVO · SIN REGISTRO · SIN INSTALACIÓN
            <ChevronRight size={10} className="text-purple-400/60"/>
          </div>

          {/* headline */}
          <h1 className="animate-fade-up delay-100 font-black leading-none tracking-tight mb-6" style={{ fontSize: 'clamp(48px, 8vw, 88px)', letterSpacing: '-0.04em' }}>
            <span className="block text-white">Audita cualquier</span>
            <span className="block gradient-text" style={{ paddingBottom: '4px' }}>WordPress</span>
            <span className="block" style={{ color: 'rgba(255,255,255,0.15)', fontSize: '0.75em', fontStyle: 'italic', fontWeight: 300 }}>en segundos</span>
          </h1>

          {/* subheadline */}
          <p className="animate-fade-up delay-200 text-white/40 mb-10 mx-auto leading-relaxed" style={{ fontSize: 'clamp(15px, 2vw, 18px)', maxWidth: '520px', fontWeight: 400 }}>
            Cabeceras HTTP, endpoints sensibles, enumeración de usuarios y puntuación CVSS&nbsp;3.1.
            <strong className="text-white/60 font-medium"> Sin instalar nada.</strong>
          </p>

          {/* form */}
          <div className="animate-fade-up delay-300 flex justify-center mb-6">
            <AuditForm onSubmit={handleAudit} isLoading={isLoading}/>
          </div>

          {/* progress */}
          {isLoading && progress && (
            <div className="animate-fade-in max-w-lg mx-auto mb-6">
              <ProgressBar progress={progress}/>
            </div>
          )}

          {/* error */}
          {error && (
            <div className="animate-fade-in max-w-lg mx-auto mb-6 flex items-center gap-3 px-4 py-3 rounded-xl border border-red-500/20 text-red-400 text-sm" style={{ background: 'rgba(239,68,68,0.08)' }}>
              <AlertTriangle size={14} className="shrink-0"/>
              {error}
            </div>
          )}

          {/* stat pills */}
          {!result && !isLoading && (
            <div className="animate-fade-up delay-400 flex flex-wrap justify-center gap-3 mt-4">
              {[
                { n: '09', l: 'headers analizados', c: '#8b5cf6' },
                { n: '14', l: 'endpoints escaneados', c: '#ef4444' },
                { n: '10.0', l: 'CVSS score máx', c: '#10b981' },
                { n: '~8s', l: 'tiempo medio', c: '#f59e0b' },
              ].map(s => (
                <div key={s.l} className="flex items-center gap-2 px-4 py-2 rounded-full border border-white/6 mono text-xs" style={{ background: 'rgba(255,255,255,0.03)' }}>
                  <span style={{ color: s.c, fontWeight: 700, fontSize: '13px' }}>{s.n}</span>
                  <span className="text-white/25">{s.l}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* scroll hint */}
        {!result && !isLoading && (
          <div className="absolute bottom-8 left-1/2 -translate-x-1/2 flex flex-col items-center gap-2 animate-fade-up delay-500">
            <span className="mono text-[9px] text-white/20 tracking-widest">SCROLL</span>
            <div className="w-px h-8" style={{ background: 'linear-gradient(to bottom, rgba(139,92,246,0.4), transparent)' }}/>
          </div>
        )}
      </section>

      {/* ── FEATURE CARDS ── */}
      {!result && !isLoading && (
        <section className="px-4 py-24 max-w-6xl mx-auto">
          <div className="text-center mb-16">
            <p className="mono text-[10px] text-purple-400/60 tracking-widest mb-4">QUÉ ANALIZA</p>
            <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-white/90">Todo lo que importa,<br/>de una sola vez</h2>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {CHECKS.map(({ icon: Icon, label, desc, color }, i) => (
              <div key={label} className="glass p-6 group" style={{ animationDelay: i * 0.1 + 's' }}>
                <div className="w-10 h-10 rounded-xl flex items-center justify-center mb-4 transition-all duration-300 group-hover:scale-110" style={{ background: color + '15', border: '1px solid ' + color + '30' }}>
                  <Icon size={18} style={{ color }}/>
                </div>
                <div className="font-semibold text-white/80 text-sm mb-2">{label}</div>
                <div className="mono text-[11px] text-white/30 leading-relaxed">{desc}</div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* ── LOADING SKELETON ── */}
      {isLoading && !result && (
        <section className="px-4 py-12 max-w-6xl mx-auto">
          <AuditLoadingSkeleton/>
        </section>
      )}

      {/* ── RESULTS ── */}
      {result && (
        <section className="px-4 py-10 max-w-6xl mx-auto animate-fade-up">
          {/* result header */}
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 mb-8 p-5 rounded-2xl border border-white/6" style={{ background: 'rgba(255,255,255,0.02)' }}>
            <div>
              <div className="mono text-[9px] text-white/20 tracking-widest mb-1.5">SITIO AUDITADO</div>
              <div className="font-mono font-semibold text-purple-400 text-base sm:text-lg break-all">{result.url}</div>
              <div className="mono text-[10px] text-white/20 mt-1">{new Date(result.timestamp).toLocaleString('es-ES')}</div>
            </div>
            <ExportButton result={result}/>
          </div>

          {/* score + info */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 mb-4">
            <div className="lg:col-span-1">
              <ScoreGauge score={result.overallScore} cvss={result.cvssOverall}/>
            </div>
            <div className="lg:col-span-2">
              <WordPressInfoCard info={result.wordpressInfo} isWordPress={result.isWordPress} wpDetection={result.wpDetection}/>
            </div>
          </div>

          {/* headers + endpoints */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
            <SecurityHeadersCard headers={result.securityHeaders}/>
            <EndpointsCard endpoints={result.endpoints}/>
          </div>

          {/* users */}
          <div className="mb-4">
            <UserEnumerationCard userEnumeration={result.userEnumeration}/>
          </div>

          {/* recs */}
          <Recommendations result={result}/>
        </section>
      )}

      {/* ── FOOTER ── */}
      <footer className="border-t border-white/5 py-8 px-4">
        <div className="max-w-6xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <HexIcon/>
            <span className="mono text-[10px] text-white/20 tracking-widest">WPSENTRY · USO ÉTICO Y EDUCATIVO</span>
          </div>
          <div className="flex items-center gap-6">
            {[
              { label: 'ccyl13', href: 'https://github.com/ccyl13/', icon: Github },
              { label: 'Thomas Oneil', href: 'https://www.linkedin.com/in/thomasoneil%C3%A1lvarez/', icon: Linkedin },
            ].map(({ label, href, icon: Icon }) => (
              <a key={label} href={href} target="_blank" rel="noopener noreferrer"
                className="flex items-center gap-1.5 mono text-[10px] text-white/20 hover:text-purple-400/60 transition-colors">
                <Icon size={11}/>{label}
              </a>
            ))}
          </div>
        </div>
      </footer>
    </div>
  );
}
