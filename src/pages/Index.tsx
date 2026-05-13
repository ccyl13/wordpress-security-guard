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
import { AlertTriangle, Shield, Github, Linkedin, Terminal, Zap, Lock } from 'lucide-react';
import { Alert, AlertDescription } from '@/components/ui/alert';

const Index = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [progress, setProgress] = useState<AuditProgress | null>(null);
  const [result, setResult] = useState<AuditResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { history, addToHistory, clearHistory } = useAuditHistory();

  const handleAudit = async (url: string) => {
    setIsLoading(true);
    setError(null);
    setResult(null);
    setProgress({ step: 'Iniciando...', current: 0, total: 4, percentage: 0 });
    try {
      const auditResult = await auditWordPress(url, setProgress);
      setResult(auditResult);
      addToHistory(auditResult);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error desconocido');
    } finally {
      setIsLoading(false);
      setProgress(null);
    }
  };

  return (
    <div className="min-h-screen bg-background bg-grid">
      {/* Header */}
      <header className="border-b border-primary/10 bg-card/80 backdrop-blur-md sticky top-0 z-50">
        <div className="container mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-primary/10 border border-primary/30 flex items-center justify-center animate-pulse-glow">
              <Shield className="w-5 h-5 text-primary" />
            </div>
            <div>
              <span className="text-lg font-black tracking-tight text-foreground">WP<span className="text-primary">Sentry</span></span>
              <p className="text-xs text-muted-foreground font-mono leading-none">security auditor</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <AuditHistory history={history} onSelect={handleAudit} onClear={clearHistory} />
            <a href="https://github.com/ccyl13/" target="_blank" rel="noopener noreferrer"
               className="p-2 rounded-lg bg-primary/5 border border-primary/10 text-muted-foreground hover:text-primary hover:border-primary/30 hover:bg-primary/10 transition-all duration-200" title="GitHub">
              <Github className="w-4 h-4" />
            </a>
            <a href="https://www.linkedin.com/in/thomasoneil%C3%A1lvarez/" target="_blank" rel="noopener noreferrer"
               className="p-2 rounded-lg bg-primary/5 border border-primary/10 text-muted-foreground hover:text-primary hover:border-primary/30 hover:bg-primary/10 transition-all duration-200" title="LinkedIn">
              <Linkedin className="w-4 h-4" />
            </a>
          </div>
        </div>
      </header>

      {/* Hero */}
      <section className="py-20 px-4 relative overflow-hidden">
        <div className="absolute inset-0 pointer-events-none">
          <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-primary/5 rounded-full blur-3xl" />
        </div>
        <div className="container mx-auto max-w-4xl text-center relative">
          <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full bg-primary/10 border border-primary/20 text-primary text-xs font-mono mb-6 animate-fade-in">
            <Terminal className="w-3 h-3" />
            <span>v2.0 &mdash; auditoria pasiva, sin intrusiones</span>
          </div>
          <h2 className="text-5xl md:text-6xl font-black mb-5 tracking-tight leading-tight animate-fade-in">
            Audita cualquier<br />
            <span className="text-primary relative">WordPress</span>
            <br />en segundos
          </h2>
          <p className="text-lg text-muted-foreground mb-10 max-w-2xl mx-auto animate-fade-in font-light">
            Cabeceras HTTP, endpoints sensibles, enumeracion de usuarios, version de WordPress y puntuacion CVSS.
            <strong className="text-foreground"> Sin registro. Sin instalacion.</strong>
          </p>
          <div className="animate-fade-in">
            <AuditForm onSubmit={handleAudit} isLoading={isLoading} />
          </div>
          {isLoading && progress && (
            <div className="mt-8 animate-fade-in">
              <ProgressBar progress={progress} />
            </div>
          )}
          {error && (
            <Alert variant="destructive" className="mt-6 max-w-xl mx-auto animate-fade-in">
              <AlertTriangle className="w-4 h-4" />
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
        </div>
      </section>

      {/* Features strip */}
      {!result && !isLoading && (
        <section className="pb-16 px-4 animate-fade-in">
          <div className="container mx-auto max-w-4xl">
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              {[
                { icon: Lock, label: 'Cabeceras HTTP', desc: 'CSP, HSTS, X-Frame-Options y mas' },
                { icon: Zap, label: 'Endpoints criticos', desc: 'xmlrpc, wp-admin, wp-json expuestos' },
                { icon: Shield, label: 'Score CVSS', desc: 'Puntuacion de riesgo estandar' },
              ].map(({ icon: Icon, label, desc }) => (
                <div key={label} className="p-5 rounded-xl bg-card border border-border hover:border-primary/30 transition-colors">
                  <Icon className="w-5 h-5 text-primary mb-3" />
                  <p className="font-semibold text-sm mb-1">{label}</p>
                  <p className="text-xs text-muted-foreground">{desc}</p>
                </div>
              ))}
            </div>
          </div>
        </section>
      )}

      {isLoading && !result && (
        <section className="pb-16 px-4">
          <div className="container mx-auto max-w-6xl">
            <AuditLoadingSkeleton />
          </div>
        </section>
      )}

      {/* Results */}
      {result && (
        <section className="pb-20 px-4 animate-fade-in">
          <div className="container mx-auto max-w-6xl">
            <div className="flex flex-col sm:flex-row items-center justify-between gap-4 mb-8">
              <div>
                <p className="text-xs text-muted-foreground font-mono mb-1">sitio auditado</p>
                <p className="font-mono text-primary font-semibold text-lg truncate max-w-md">{result.url}</p>
                <p className="text-xs text-muted-foreground mt-1">{new Date(result.timestamp).toLocaleString('es-ES')}</p>
              </div>
              <ExportButton result={result} />
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
              <div className="lg:col-span-1">
                <ScoreGauge score={result.overallScore} cvss={result.cvssOverall} />
              </div>
              <div className="lg:col-span-2">
                <WordPressInfoCard info={result.wordpressInfo} isWordPress={result.isWordPress} wpDetection={result.wpDetection} />
              </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
              <SecurityHeadersCard headers={result.securityHeaders} />
              <EndpointsCard endpoints={result.endpoints} />
            </div>

            <div className="mb-6">
              <UserEnumerationCard userEnumeration={result.userEnumeration} />
            </div>

            <Recommendations result={result} />
          </div>
        </section>
      )}

      {/* Footer */}
      <footer className="border-t border-border py-8 px-4">
        <div className="container mx-auto max-w-6xl flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-muted-foreground">
          <div className="flex items-center gap-2">
            <Shield className="w-3 h-3 text-primary" />
            <span className="font-mono">WPSentry &mdash; uso etico y educativo</span>
          </div>
          <div className="flex items-center gap-4">
            <a href="https://github.com/ccyl13/" target="_blank" rel="noopener noreferrer" className="hover:text-primary transition-colors flex items-center gap-1">
              <Github className="w-3 h-3" /> ccyl13
            </a>
            <a href="https://www.linkedin.com/in/thomasoneil%C3%A1lvarez/" target="_blank" rel="noopener noreferrer" className="hover:text-primary transition-colors flex items-center gap-1">
              <Linkedin className="w-3 h-3" /> Thomas Oneil
            </a>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default Index;
