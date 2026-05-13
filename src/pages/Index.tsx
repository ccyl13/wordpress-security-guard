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
import { AlertTriangle, Github, Linkedin } from 'lucide-react';
import { Alert, AlertDescription } from '@/components/ui/alert';

const HexLogo = () => (
  <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
    <polygon points="16,1 29,8.5 29,23.5 16,31 3,23.5 3,8.5" fill="#8b5cf6" fillOpacity=".15" stroke="#a78bfa" strokeWidth=".8"/>
    <polygon points="16,7 25,12 25,20 16,25 7,20 7,12" fill="#8b5cf6" fillOpacity=".3" stroke="#a78bfa" strokeWidth=".5"/>
    <circle cx="16" cy="16" r="3.5" fill="#a78bfa"/>
    <circle cx="16" cy="16" r="1.5" fill="#fff"/>
  </svg>
);

const Bg3D = () => (
  <svg className="absolute inset-0 w-full h-full pointer-events-none" viewBox="0 0 680 520" preserveAspectRatio="xMidYMid slice">
    <defs>
      <radialGradient id="rg1" cx="25%" cy="35%" r="50%">
        <stop offset="0%" stopColor="#8b5cf6" stopOpacity=".13"/>
        <stop offset="100%" stopColor="#8b5cf6" stopOpacity="0"/>
      </radialGradient>
      <radialGradient id="rg2" cx="80%" cy="15%" r="35%">
        <stop offset="0%" stopColor="#3b82f6" stopOpacity=".06"/>
        <stop offset="100%" stopColor="#3b82f6" stopOpacity="0"/>
      </radialGradient>
    </defs>
    <rect width="680" height="520" fill="url(#rg1)"/>
    <rect width="680" height="520" fill="url(#rg2)"/>
    <g stroke="#8b5cf6" strokeOpacity=".055" strokeWidth=".5">
      {[0,76,152,228,304,380,456,532,608,680].map((x,i) => (
        <line key={i} x1="340" y1="220" x2={x} y2="520"/>
      ))}
      <line x1="0" y1="300" x2="680" y2="300" strokeOpacity=".035"/>
      <line x1="0" y1="360" x2="680" y2="360" strokeOpacity=".025"/>
      <line x1="0" y1="420" x2="680" y2="420" strokeOpacity=".015"/>
    </g>
    <g transform="translate(490,18)" opacity=".5">
      <polygon points="70,0 140,35 70,70 0,35" fill="#8b5cf6" fillOpacity=".06" stroke="#a78bfa" strokeWidth=".6" strokeOpacity=".5"/>
      <polygon points="0,35 70,70 70,140 0,105" fill="#8b5cf6" fillOpacity=".04" stroke="#7c3aed" strokeWidth=".6" strokeOpacity=".4"/>
      <polygon points="70,70 140,35 140,105 70,140" fill="#6d28d9" fillOpacity=".08" stroke="#7c3aed" strokeWidth=".6" strokeOpacity=".35"/>
      <line x1="70" y1="0" x2="70" y2="70" stroke="#a78bfa" strokeWidth=".3" strokeOpacity=".3"/>
      <line x1="0" y1="35" x2="140" y2="35" stroke="#a78bfa" strokeWidth=".3" strokeOpacity=".25"/>
      <polygon points="70,18 104,36 70,54 36,36" fill="#8b5cf6" fillOpacity=".08" stroke="#a78bfa" strokeWidth=".4" strokeOpacity=".4"/>
      <circle cx="70" cy="36" r="3" fill="#a78bfa" fillOpacity=".5"/>
    </g>
    <g transform="translate(28,32)" opacity=".4">
      <polygon points="42,0 84,21 42,42 0,21" fill="#8b5cf6" fillOpacity=".07" stroke="#a78bfa" strokeWidth=".6" strokeOpacity=".5"/>
      <polygon points="0,21 42,42 42,84 0,63" fill="#8b5cf6" fillOpacity=".04" stroke="#7c3aed" strokeWidth=".5" strokeOpacity=".4"/>
      <polygon points="42,42 84,21 84,63 42,84" fill="#6d28d9" fillOpacity=".07" stroke="#7c3aed" strokeWidth=".5" strokeOpacity=".3"/>
      <line x1="42" y1="0" x2="42" y2="84" stroke="#a78bfa" strokeWidth=".3" strokeOpacity=".25"/>
      <line x1="0" y1="21" x2="84" y2="21" stroke="#a78bfa" strokeWidth=".3" strokeOpacity=".2"/>
    </g>
    <g transform="translate(580,110)" opacity=".4">
      <polygon points="22,0 44,11 22,22 0,11" fill="#3b82f6" fillOpacity=".1" stroke="#60a5fa" strokeWidth=".5" strokeOpacity=".5"/>
      <polygon points="0,11 22,22 22,44 0,33" fill="#2563eb" fillOpacity=".06" stroke="#3b82f6" strokeWidth=".4" strokeOpacity=".4"/>
      <polygon points="22,22 44,11 44,33 22,44" fill="#1d4ed8" fillOpacity=".1" stroke="#3b82f6" strokeWidth=".4" strokeOpacity=".3"/>
    </g>
    <g transform="translate(270,22)" opacity=".25">
      <path d="M70,0 L140,22 L140,88 Q140,140 70,158 Q0,140 0,88 L0,22Z" fill="#8b5cf6" fillOpacity=".04" stroke="#a78bfa" strokeWidth=".7"/>
      <path d="M70,26 L112,42 L112,88 Q112,125 70,138 Q28,125 28,88 L28,42Z" fill="none" stroke="#a78bfa" strokeWidth=".4" strokeOpacity=".5"/>
      <line x1="70" y1="50" x2="70" y2="118" stroke="#a78bfa" strokeWidth=".4" strokeOpacity=".4"/>
      <line x1="42" y1="84" x2="98" y2="84" stroke="#a78bfa" strokeWidth=".4" strokeOpacity=".4"/>
      <circle cx="70" cy="84" r="14" fill="none" stroke="#a78bfa" strokeWidth=".5" strokeOpacity=".3"/>
      <circle cx="70" cy="84" r="5" fill="#a78bfa" fillOpacity=".25"/>
    </g>
    <ellipse cx="340" cy="140" rx="155" ry="36" fill="none" stroke="#8b5cf6" strokeWidth=".5" strokeOpacity=".1" strokeDasharray="2 8"/>
    <circle cx="188" cy="108" r="2" fill="#8b5cf6" fillOpacity=".7"/>
    <circle cx="500" cy="88" r="1.5" fill="#3b82f6" fillOpacity=".6"/>
    <circle cx="430" cy="165" r="1.5" fill="#10b981" fillOpacity=".5"/>
    <line x1="188" y1="108" x2="500" y2="88" stroke="#8b5cf6" strokeWidth=".3" strokeOpacity=".12"/>
    <line x1="500" y1="88" x2="430" y2="165" stroke="#3b82f6" strokeWidth=".3" strokeOpacity=".1"/>
  </svg>
);

const FEATURE_ITEMS = [
  { color: '#ef4444', label: 'Content-Security-Policy' },
  { color: '#ef4444', label: 'Strict-Transport-Security' },
  { color: '#f97316', label: 'X-Frame-Options' },
  { color: '#f97316', label: 'X-Content-Type-Options' },
  { color: '#eab308', label: 'Referrer-Policy' },
  { color: '#ffffff20', label: 'Permissions-Policy' },
];
const ENDPOINT_ITEMS = [
  { color: '#ef4444', label: '/xmlrpc.php' },
  { color: '#ef4444', label: '/wp-login.php' },
  { color: '#f97316', label: '/wp-admin/' },
  { color: '#f97316', label: '/wp-json/wp/v2/' },
  { color: '#eab308', label: '/readme.html' },
  { color: '#ffffff20', label: '/debug.log · /.env' },
];
const USER_ITEMS = [
  { color: '#8b5cf6', label: '/wp/v2/users REST' },
  { color: '#8b5cf6', label: 'author archive bypass' },
  { color: '#10b981', label: 'score 0.0 → 10.0 CVSS' },
  { color: '#10b981', label: 'AV:N/AC:L/PR:N/UI:N' },
  { color: '#eab308', label: 'WAF detection' },
  { color: '#ffffff20', label: 'SSL / TLS · Generator' },
];

const FeatureCol = ({ title, tag, items, accent, barWidth, owasp }: any) => (
  <div style={{ background: '#02020a', padding: '18px 20px', position: 'relative', overflow: 'hidden', borderTop: '1px solid #ffffff05', transition: 'background .2s' }}
    onMouseEnter={e => (e.currentTarget.style.background = '#04040f')}
    onMouseLeave={e => (e.currentTarget.style.background = '#02020a')}>
    <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: '1px', background: 'linear-gradient(90deg,transparent,' + accent + '80,transparent)', opacity: 0 }}
      className="col-topline"/>
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
      <span style={{ fontSize: '11px', fontWeight: 700, letterSpacing: '.5px', textTransform: 'uppercase', color: accent }}>{title}</span>
      <span style={{ fontSize: '8px', fontFamily: 'JetBrains Mono,monospace', padding: '2px 6px', borderRadius: '3px', color: accent + '70', background: accent + '12', border: '1px solid ' + accent + '25', letterSpacing: '.5px' }}>{tag}</span>
    </div>
    <div style={{ display: 'flex', flexDirection: 'column', gap: '5px' }}>
      {items.map((it: any, i: number) => (
        <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '7px', fontSize: '10px', fontFamily: 'JetBrains Mono,monospace', color: '#ffffff30', padding: '3px 5px', borderRadius: '4px', transition: 'all .15s', cursor: 'default', border: '1px solid transparent' }}
          onMouseEnter={e => { e.currentTarget.style.color='#ffffff65'; e.currentTarget.style.background='#ffffff04'; e.currentTarget.style.borderColor='#ffffff08'; }}
          onMouseLeave={e => { e.currentTarget.style.color='#ffffff30'; e.currentTarget.style.background='transparent'; e.currentTarget.style.borderColor='transparent'; }}>
          <div style={{ width: '4px', height: '4px', borderRadius: '50%', background: it.color, flexShrink: 0, boxShadow: it.color !== '#ffffff20' ? '0 0 5px ' + it.color + '80' : 'none' }}/>
          {it.label}
        </div>
      ))}
    </div>
    <div style={{ marginTop: '12px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '8px', fontFamily: 'JetBrains Mono,monospace', color: '#ffffff15', marginBottom: '3px' }}>
        <span>cobertura</span><span>{owasp}</span>
      </div>
      <div style={{ height: '1.5px', background: '#ffffff06', borderRadius: '1px', position: 'relative' }}>
        <div style={{ height: '100%', width: barWidth, background: accent, borderRadius: '1px', position: 'relative' }}>
          <div style={{ position: 'absolute', right: '-2px', top: '50%', transform: 'translateY(-50%)', width: '4px', height: '4px', borderRadius: '50%', background: accent, boxShadow: '0 0 6px ' + accent }}/>
        </div>
      </div>
    </div>
  </div>
);

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
      const auditResult = await auditWordPress(url, setProgress);
      setResult(auditResult); addToHistory(auditResult);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error desconocido');
    } finally { setIsLoading(false); setProgress(null); }
  };

  return (
    <div style={{ minHeight: '100vh', background: '#02020a', color: '#fff', fontFamily: "'Space Grotesk', sans-serif" }}>

      {/* scanline */}
      <div style={{ position: 'fixed', left: 0, right: 0, height: '100px', background: 'linear-gradient(180deg,transparent,#8b5cf608,transparent)', animation: 'scanline 6s linear infinite', pointerEvents: 'none', zIndex: 50 }}/>

      {/* HEADER */}
      <header style={{ borderBottom: '1px solid #ffffff07', background: '#02020aee', backdropFilter: 'blur(12px)', position: 'sticky', top: 0, zIndex: 40, padding: '12px 24px', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <HexLogo/>
          <div>
            <div style={{ fontSize: '16px', fontWeight: 800, letterSpacing: '-.5px', lineHeight: 1 }}>
              WP<span style={{ color: '#8b5cf6' }}>Sentry</span>
            </div>
            <div style={{ fontSize: '9px', fontFamily: 'JetBrains Mono,monospace', color: '#ffffff20', letterSpacing: '2px', marginTop: '1px' }}>SECURITY AUDITOR</div>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '5px', padding: '3px 9px', border: '1px solid #8b5cf625', borderRadius: '3px', fontSize: '9px', fontFamily: 'JetBrains Mono,monospace', color: '#8b5cf670', letterSpacing: '1.5px' }}>
            <div style={{ width: '5px', height: '5px', borderRadius: '50%', background: '#8b5cf6', boxShadow: '0 0 6px #8b5cf6', animation: 'blink 2s ease-in-out infinite' }}/>
            ONLINE
          </div>
          <AuditHistory history={history} onSelect={handleAudit} onClear={clearHistory}/>
          {[
            { icon: Github, href: 'https://github.com/ccyl13/', title: 'GitHub' },
            { icon: Linkedin, href: 'https://www.linkedin.com/in/thomasoneil%C3%A1lvarez/', title: 'LinkedIn' },
          ].map(({ icon: Icon, href, title }) => (
            <a key={title} href={href} target="_blank" rel="noopener noreferrer" title={title}
              style={{ width: '30px', height: '30px', borderRadius: '6px', background: '#ffffff04', border: '1px solid #ffffff08', display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#ffffff30', transition: 'all .2s', textDecoration: 'none' }}
              onMouseEnter={e => { const el = e.currentTarget as HTMLElement; el.style.borderColor='#8b5cf640'; el.style.color='#a78bfa'; el.style.transform='translateY(-1px)'; el.style.background='#8b5cf610'; }}
              onMouseLeave={e => { const el = e.currentTarget as HTMLElement; el.style.borderColor='#ffffff08'; el.style.color='#ffffff30'; el.style.transform=''; el.style.background='#ffffff04'; }}>
              <Icon size={13}/>
            </a>
          ))}
        </div>
      </header>

      {/* HERO */}
      <section style={{ position: 'relative', overflow: 'hidden', padding: '48px 28px 0' }}>
        <Bg3D/>
        <div style={{ position: 'relative', zIndex: 2, maxWidth: '700px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '16px' }}>
            <div style={{ width: '28px', height: '1px', background: 'linear-gradient(90deg,#8b5cf6,transparent)' }}/>
            <span style={{ fontSize: '9px', fontFamily: 'JetBrains Mono,monospace', color: '#8b5cf680', letterSpacing: '3px', textTransform: 'uppercase' }}>análisis pasivo · sin registro · sin instalación</span>
          </div>
          <h1 style={{ fontSize: '52px', fontWeight: 800, lineHeight: .92, letterSpacing: '-2.5px', marginBottom: '16px' }}>
            Audita<br/>
            <span style={{ color: '#8b5cf6', textShadow: '0 0 60px #8b5cf630', display: 'block' }}>cualquier WordPress</span>
            <span style={{ color: '#ffffff12', display: 'block', fontSize: '44px', letterSpacing: '-2px' }}>en segundos</span>
          </h1>
          <p style={{ fontSize: '11px', fontFamily: 'JetBrains Mono,monospace', color: '#ffffff35', lineHeight: 1.8, marginBottom: '24px', maxWidth: '380px' }}>
            <span style={{ color: '#8b5cf660' }}>$</span> cabeceras · endpoints · users · cvss 3.1<br/>
            <span style={{ color: '#8b5cf660' }}>→</span> sin tocar el servidor. sin dejar rastro.
          </p>
          <AuditForm onSubmit={handleAudit} isLoading={isLoading}/>
        </div>

        {/* stat strip */}
        <div style={{ display: 'flex', borderTop: '1px solid #ffffff06', borderBottom: '1px solid #ffffff06', marginTop: '24px', position: 'relative', zIndex: 2 }}>
          {[
            { n: '09', l: 'headers', c: '#8b5cf6' },
            { n: '14', l: 'endpoints', c: '#ef4444' },
            { n: '10.0', l: 'cvss max', c: '#10b981' },
            { n: '~8s', l: 'avg scan', c: '#f59e0b' },
          ].map((s, i) => (
            <div key={i} style={{ flex: 1, padding: '10px 16px', borderRight: i < 3 ? '1px solid #ffffff06' : 'none' }}>
              <div style={{ fontSize: '18px', fontWeight: 800, letterSpacing: '-1px', fontFamily: 'JetBrains Mono,monospace', color: s.c, lineHeight: 1, marginBottom: '2px' }}>{s.n}</div>
              <div style={{ fontSize: '8.5px', fontFamily: 'JetBrains Mono,monospace', color: '#ffffff18', letterSpacing: '1.5px', textTransform: 'uppercase' }}>{s.l}</div>
            </div>
          ))}
        </div>
      </section>

      {isLoading && progress && (
        <div style={{ padding: '0 28px' }}>
          <ProgressBar progress={progress}/>
        </div>
      )}
      {error && (
        <div style={{ padding: '16px 28px' }}>
          <Alert variant="destructive">
            <AlertTriangle className="w-4 h-4"/>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        </div>
      )}

      {/* FEATURE COLS — only when no result */}
      {!result && !isLoading && (
        <section style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '1px', background: '#ffffff05', marginTop: '1px' }}>
          <FeatureCol title="Cabeceras HTTP" tag="09 checks" items={FEATURE_ITEMS} accent="#8b5cf6" barWidth="72%" owasp="OWASP A05"/>
          <FeatureCol title="Endpoints" tag="14 paths" items={ENDPOINT_ITEMS} accent="#3b82f6" barWidth="88%" owasp="CWE-749"/>
          <FeatureCol title="Users + CVSS" tag="3.1" items={USER_ITEMS} accent="#10b981" barWidth="64%" owasp="A07:2021"/>
        </section>
      )}

      {isLoading && !result && (
        <div style={{ padding: '24px 28px' }}>
          <AuditLoadingSkeleton/>
        </div>
      )}

      {/* RESULTS */}
      {result && (
        <section style={{ padding: '24px 28px 48px', animation: 'fadein .4s ease-out' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '24px', flexWrap: 'wrap', gap: '12px' }}>
            <div>
              <div style={{ fontSize: '9px', fontFamily: 'JetBrains Mono,monospace', color: '#ffffff20', letterSpacing: '2px', marginBottom: '4px' }}>SITIO AUDITADO</div>
              <div style={{ fontSize: '15px', fontFamily: 'JetBrains Mono,monospace', color: '#8b5cf6', fontWeight: 700 }}>{result.url}</div>
              <div style={{ fontSize: '9px', color: '#ffffff20', fontFamily: 'JetBrains Mono,monospace', marginTop: '2px' }}>{new Date(result.timestamp).toLocaleString('es-ES')}</div>
            </div>
            <ExportButton result={result}/>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: '12px', marginBottom: '12px' }}>
            <ScoreGauge score={result.overallScore} cvss={result.cvssOverall}/>
            <WordPressInfoCard info={result.wordpressInfo} isWordPress={result.isWordPress} wpDetection={result.wpDetection}/>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '12px' }}>
            <SecurityHeadersCard headers={result.securityHeaders}/>
            <EndpointsCard endpoints={result.endpoints}/>
          </div>
          <div style={{ marginBottom: '12px' }}>
            <UserEnumerationCard userEnumeration={result.userEnumeration}/>
          </div>
          <Recommendations result={result}/>
        </section>
      )}

      {/* FOOTER */}
      <footer style={{ borderTop: '1px solid #ffffff05', padding: '10px 24px', display: 'flex', justifyContent: 'space-between', alignItems: 'center', background: '#02020a' }}>
        <span style={{ fontSize: '8px', fontFamily: 'JetBrains Mono,monospace', color: '#ffffff15', letterSpacing: '1px' }}>WPSENTRY v2.0 · USO ÉTICO Y EDUCATIVO</span>
        <div style={{ display: 'flex', gap: '14px' }}>
          {[
            { label: 'ccyl13', href: 'https://github.com/ccyl13/' },
            { label: 'Thomas Oneil', href: 'https://www.linkedin.com/in/thomasoneil%C3%A1lvarez/' },
          ].map(({ label, href }) => (
            <a key={label} href={href} target="_blank" rel="noopener noreferrer"
              style={{ fontSize: '8px', fontFamily: 'JetBrains Mono,monospace', color: '#ffffff20', textDecoration: 'none', letterSpacing: '.5px', transition: 'color .2s' }}
              onMouseEnter={e => (e.currentTarget.style.color = '#8b5cf680')}
              onMouseLeave={e => (e.currentTarget.style.color = '#ffffff20')}>
              {label}
            </a>
          ))}
        </div>
      </footer>
    </div>
  );
};

export default Index;
