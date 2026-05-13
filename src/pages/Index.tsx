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
import { AlertTriangle, Github, Linkedin, Shield, Zap, Lock, Eye } from 'lucide-react';

const FEATURES = [
  { icon: Shield, color: '#7c3aed', label: 'Cabeceras HTTP', desc: 'CSP, HSTS, X-Frame, X-Content-Type y 5 más con referencias OWASP y score CVSS por cabecera' },
  { icon: Zap,    color: '#2563eb', label: 'Endpoints críticos', desc: 'xmlrpc.php, wp-admin, wp-json, debug.log, .env, .git y 8 rutas más detectadas automáticamente' },
  { icon: Eye,    color: '#06b6d4', label: 'Enumeración de usuarios', desc: 'Detecta si la REST API o los archivos de autor exponen usuarios válidos del sistema' },
  { icon: Lock,   color: '#10b981', label: 'Score CVSS 3.1', desc: 'Puntuación de riesgo estándar agregada con vector AV:N, recomendaciones y código de corrección' },
];

const HexIcon = () => (
  <svg width="28" height="28" viewBox="0 0 28 28" fill="none">
    <polygon points="14,1 26,7.5 26,20.5 14,27 2,20.5 2,7.5" fill="#7c3aed" fillOpacity=".2" stroke="#a78bfa" strokeWidth=".8"/>
    <polygon points="14,6 22,10.5 22,17.5 14,22 6,17.5 6,10.5" fill="#7c3aed" fillOpacity=".35" stroke="#a78bfa" strokeWidth=".5"/>
    <circle cx="14" cy="14" r="3" fill="#a78bfa"/>
    <circle cx="14" cy="14" r="1.2" fill="#fff"/>
  </svg>
);

const Index = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [progress, setProgress] = useState<AuditProgress | null>(null);
  const [result, setResult] = useState<AuditResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { history, addToHistory, clearHistory } = useAuditHistory();
  const resultsRef = useRef<HTMLDivElement>(null);

  const handleAudit = async (url: string) => {
    setIsLoading(true); setError(null); setResult(null);
    setProgress({ step: 'Iniciando...', current: 0, total: 4, percentage: 0 });
    try {
      const r = await auditWordPress(url, setProgress);
      setResult(r); addToHistory(r);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Error desconocido');
    } finally { setIsLoading(false); setProgress(null); }
  };

  useEffect(() => {
    if (result && resultsRef.current) {
      setTimeout(() => resultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 100);
    }
  }, [result]);

  return (
    <div style={{ minHeight: '100vh', background: '#000005', color: '#fff', fontFamily: "'Inter',sans-serif", position: 'relative', overflowX: 'hidden' }}>
      <div className="scanline"/>
      <div className="noise-bg" style={{ position: 'fixed', inset: 0, pointerEvents: 'none', zIndex: 0 }}/>

      {/* ORB LIGHTS */}
      <div className="orb" style={{ width: '600px', height: '600px', background: 'radial-gradient(circle, #7c3aed18 0%, transparent 70%)', top: '-100px', left: '-150px' }}/>
      <div className="orb" style={{ width: '500px', height: '500px', background: 'radial-gradient(circle, #2563eb12 0%, transparent 70%)', top: '100px', right: '-100px' }}/>
      <div className="orb" style={{ width: '400px', height: '400px', background: 'radial-gradient(circle, #06b6d410 0%, transparent 70%)', top: '300px', left: '40%' }}/>

      {/* ── HEADER ── */}
      <header style={{ position: 'sticky', top: 0, zIndex: 50, borderBottom: '1px solid rgba(255,255,255,0.05)', backdropFilter: 'blur(20px)', background: 'rgba(0,0,5,0.7)', padding: '0 24px' }}>
        <div style={{ maxWidth: '1100px', margin: '0 auto', height: '60px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <HexIcon/>
            <div>
              <div style={{ fontSize: '15px', fontWeight: 700, letterSpacing: '-0.3px', lineHeight: 1 }}>
                WP<span style={{ color: '#a78bfa' }}>Sentry</span>
              </div>
              <div className="mono" style={{ fontSize: '9px', color: 'rgba(255,255,255,0.2)', letterSpacing: '2px' }}>SECURITY AUDITOR</div>
            </div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <div className="status-badge">
              <div className="glow-dot" style={{ width: '5px', height: '5px' }}/>
              Online
            </div>
            <AuditHistory history={history} onSelect={handleAudit} onClear={clearHistory}/>
            {[
              { Icon: Github, href: 'https://github.com/ccyl13/', label: 'GitHub' },
              { Icon: Linkedin, href: 'https://www.linkedin.com/in/thomasoneil%C3%A1lvarez/', label: 'LinkedIn' },
            ].map(({ Icon, href, label }) => (
              <a key={label} href={href} target="_blank" rel="noopener noreferrer"
                style={{ width: '32px', height: '32px', borderRadius: '8px', background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.07)', display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'rgba(255,255,255,0.35)', transition: 'all .2s', textDecoration: 'none' }}
                onMouseEnter={e => { const el = e.currentTarget as HTMLElement; el.style.background='rgba(124,58,237,0.12)'; el.style.borderColor='rgba(124,58,237,0.4)'; el.style.color='#a78bfa'; }}
                onMouseLeave={e => { const el = e.currentTarget as HTMLElement; el.style.background='rgba(255,255,255,0.04)'; el.style.borderColor='rgba(255,255,255,0.07)'; el.style.color='rgba(255,255,255,0.35)'; }}>
                <Icon size={14}/>
              </a>
            ))}
          </div>
        </div>
      </header>

      {/* ── HERO ── */}
      <section style={{ position: 'relative', zIndex: 1, padding: '100px 24px 80px', textAlign: 'center' }}>
        <div style={{ maxWidth: '820px', margin: '0 auto' }}>

          <div className="fade-up" style={{ marginBottom: '24px' }}>
            <div className="status-badge" style={{ display: 'inline-flex' }}>
              <div className="glow-dot" style={{ width: '5px', height: '5px' }}/>
              Análisis pasivo · Sin registro · Sin instalación
            </div>
          </div>

          <h1 className="fade-up delay-1 hero-h1" style={{ fontSize: '72px', fontWeight: 900, lineHeight: 1, letterSpacing: '-4px', marginBottom: '20px' }}>
            <span className="grad-text">Audita cualquier</span>
            <br/>
            <span style={{ color: '#fff' }}>WordPress</span>
            <br/>
            <span style={{ color: 'rgba(255,255,255,0.15)', fontSize: '60px', letterSpacing: '-3px' }}>en segundos</span>
          </h1>

          <p className="fade-up delay-2 hero-sub" style={{ fontSize: '18px', color: 'rgba(255,255,255,0.45)', fontWeight: 400, lineHeight: 1.7, marginBottom: '48px', maxWidth: '540px', margin: '0 auto 48px' }}>
            Cabeceras HTTP, endpoints expuestos, enumeración de usuarios y score CVSS 3.1.
            <span style={{ color: 'rgba(255,255,255,0.7)' }}> Sin tocar el servidor.</span>
          </p>

          <div className="fade-up delay-3">
            <AuditForm onSubmit={handleAudit} isLoading={isLoading}/>
          </div>

          {/* STATS ROW */}
          <div className="fade-up delay-4" style={{ display: 'flex', justifyContent: 'center', gap: '0', marginTop: '56px', borderTop: '1px solid rgba(255,255,255,0.05)', borderBottom: '1px solid rgba(255,255,255,0.05)', padding: '20px 0' }}>
            {[
              { n: '09', l: 'Headers', c: '#a78bfa' },
              { n: '14', l: 'Endpoints', c: '#f87171' },
              { n: '10.0', l: 'CVSS Max', c: '#34d399' },
              { n: '~8s', l: 'Avg scan', c: '#fbbf24' },
            ].map((s, i) => (
              <div key={i} style={{ flex: 1, textAlign: 'center', borderRight: i < 3 ? '1px solid rgba(255,255,255,0.05)' : 'none', padding: '0 20px' }}>
                <div className="mono" style={{ fontSize: '22px', fontWeight: 700, color: s.c, letterSpacing: '-1px', lineHeight: 1, marginBottom: '4px' }}>{s.n}</div>
                <div style={{ fontSize: '11px', color: 'rgba(255,255,255,0.25)', letterSpacing: '0.05em', textTransform: 'uppercase' }}>{s.l}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* PROGRESS / ERROR */}
      {(isLoading || error) && (
        <div style={{ position: 'relative', zIndex: 1, padding: '0 24px 24px', maxWidth: '820px', margin: '0 auto' }}>
          {isLoading && progress && <ProgressBar progress={progress}/>}
          {error && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', padding: '14px 18px', background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)', borderRadius: '12px', color: '#fca5a5', fontSize: '14px' }}>
              <AlertTriangle size={16} style={{ flexShrink: 0 }}/>
              {error}
            </div>
          )}
        </div>
      )}

      {/* ── RESULTS ── */}
      {result && (
        <div ref={resultsRef} style={{ position: 'relative', zIndex: 1, padding: '0 24px 80px', maxWidth: '1100px', margin: '0 auto' }}>
          <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px', marginBottom: '32px', paddingBottom: '24px', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
            <div>
              <div className="mono" style={{ fontSize: '10px', color: 'rgba(255,255,255,0.2)', letterSpacing: '2px', marginBottom: '6px' }}>SITIO AUDITADO</div>
              <div className="mono" style={{ fontSize: '16px', color: '#a78bfa', fontWeight: 600 }}>{result.url}</div>
              <div style={{ fontSize: '11px', color: 'rgba(255,255,255,0.2)', marginTop: '4px' }}>{new Date(result.timestamp).toLocaleString('es-ES')}</div>
            </div>
            <ExportButton result={result}/>
          </div>

          <div className="grid-results-top" style={{ display: 'grid', gridTemplateColumns: '280px 1fr', gap: '16px', marginBottom: '16px' }}>
            <ScoreGauge score={result.overallScore} cvss={result.cvssOverall}/>
            <WordPressInfoCard info={result.wordpressInfo} isWordPress={result.isWordPress} wpDetection={result.wpDetection}/>
          </div>
          <div className="grid-results-mid" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px', marginBottom: '16px' }}>
            <SecurityHeadersCard headers={result.securityHeaders}/>
            <EndpointsCard endpoints={result.endpoints}/>
          </div>
          <div style={{ marginBottom: '16px' }}>
            <UserEnumerationCard userEnumeration={result.userEnumeration}/>
          </div>
          <Recommendations result={result}/>
        </div>
      )}

      {/* LOADING SKELETON */}
      {isLoading && !result && (
        <div style={{ position: 'relative', zIndex: 1, padding: '0 24px 80px', maxWidth: '1100px', margin: '0 auto' }}>
          <AuditLoadingSkeleton/>
        </div>
      )}

      {/* ── FEATURES ── */}
      {!result && !isLoading && (
        <section style={{ position: 'relative', zIndex: 1, padding: '0 24px 100px' }}>
          <div style={{ maxWidth: '1100px', margin: '0 auto' }}>
            <div className="feat-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: '12px' }}>
              {FEATURES.map(({ icon: Icon, color, label, desc }, i) => (
                <div key={i} className="glass glass-hover fade-up" style={{ borderRadius: '16px', padding: '24px', animationDelay: i * 0.08 + 's' }}>
                  <div style={{ width: '40px', height: '40px', borderRadius: '10px', background: color + '15', border: '1px solid ' + color + '30', display: 'flex', alignItems: 'center', justifyContent: 'center', marginBottom: '16px' }}>
                    <Icon size={18} style={{ color }}/>
                  </div>
                  <div style={{ fontSize: '14px', fontWeight: 600, marginBottom: '8px', color: '#fff' }}>{label}</div>
                  <div style={{ fontSize: '12px', color: 'rgba(255,255,255,0.35)', lineHeight: 1.6 }}>{desc}</div>
                </div>
              ))}
            </div>
          </div>
        </section>
      )}

      {/* ── FOOTER ── */}
      <footer style={{ position: 'relative', zIndex: 1, borderTop: '1px solid rgba(255,255,255,0.05)', padding: '20px 24px' }}>
        <div style={{ maxWidth: '1100px', margin: '0 auto', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
          <div className="mono" style={{ fontSize: '11px', color: 'rgba(255,255,255,0.15)', letterSpacing: '1px' }}>WPSENTRY v2.0 · USO ÉTICO Y EDUCATIVO</div>
          <div style={{ display: 'flex', gap: '20px' }}>
            {[
              { label: '← ccyl13', href: 'https://github.com/ccyl13/' },
              { label: 'Thomas Oneil →', href: 'https://www.linkedin.com/in/thomasoneil%C3%A1lvarez/' },
            ].map(({ label, href }) => (
              <a key={label} href={href} target="_blank" rel="noopener noreferrer" className="mono"
                style={{ fontSize: '11px', color: 'rgba(255,255,255,0.2)', textDecoration: 'none', transition: 'color .2s' }}
                onMouseEnter={e => (e.currentTarget.style.color = '#a78bfa')}
                onMouseLeave={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.2)')}>
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
