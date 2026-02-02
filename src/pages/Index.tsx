import { useState } from 'react';
import { AuditForm } from '@/components/AuditForm';
import { ScoreGauge } from '@/components/ScoreGauge';
import { SecurityHeadersCard } from '@/components/SecurityHeadersCard';
import { EndpointsCard } from '@/components/EndpointsCard';
import { UserEnumerationCard } from '@/components/UserEnumerationCard';
import { WordPressInfoCard } from '@/components/WordPressInfoCard';
import { Recommendations } from '@/components/Recommendations';
import { AuditLoadingSkeleton } from '@/components/LoadingSkeleton';
import { ProgressBar } from '@/components/ProgressBar';
import { ExportButton } from '@/components/ExportButton';
import { AuditHistory } from '@/components/AuditHistory';
import { OverallCvssCard } from '@/components/SecurityReferenceBadges';
import { useAuditHistory } from '@/hooks/useAuditHistory';
import { auditWordPress, type AuditProgress } from '@/lib/wordpress-auditor';
import type { AuditResult } from '@/types/wordpress-audit';
import { Shield, Terminal, AlertTriangle, Github } from 'lucide-react';
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

  const handleHistorySelect = (url: string) => {
    handleAudit(url);
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-primary/10 rounded-lg animate-pulse-glow">
              <Shield className="w-6 h-6 text-primary" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight">WP Security Auditor</h1>
              <p className="text-xs text-muted-foreground">Análisis de seguridad para WordPress</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <AuditHistory 
              history={history} 
              onSelect={handleHistorySelect}
              onClear={clearHistory}
            />
            <a 
              href="https://github.com/ccyl13" 
              target="_blank" 
              rel="noopener noreferrer"
              className="text-muted-foreground hover:text-foreground transition-colors"
            >
              <Github className="w-5 h-5" />
            </a>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="py-16 px-4">
        <div className="container mx-auto max-w-4xl text-center">
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 text-primary text-sm font-medium mb-6 animate-fade-in">
            <Terminal className="w-4 h-4" />
            100% Frontend • Sin Backend • GitHub Pages Ready
          </div>
          <h2 className="text-4xl md:text-5xl font-black mb-4 tracking-tight animate-fade-in">
            Audita la seguridad de<br />
            <span className="text-primary">cualquier WordPress</span>
          </h2>
          <p className="text-lg text-muted-foreground mb-8 max-w-2xl mx-auto animate-fade-in">
            Analiza cabeceras de seguridad, endpoints sensibles, enumeración de usuarios y más. 
            Todo desde tu navegador, sin necesidad de servidor.
          </p>
          
          <AuditForm onSubmit={handleAudit} isLoading={isLoading} />
          
          {isLoading && progress && (
            <ProgressBar progress={progress} />
          )}
          
          {error && (
            <Alert variant="destructive" className="mt-6 max-w-xl mx-auto animate-fade-in">
              <AlertTriangle className="w-4 h-4" />
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
        </div>
      </section>

      {/* Results Section */}
      {result && (
        <section className="pb-16 px-4 animate-fade-in">
          <div className="container mx-auto max-w-6xl">
            {/* URL and Export */}
            <div className="flex flex-col sm:flex-row items-center justify-between gap-4 mb-8">
              <div className="text-center sm:text-left">
                <p className="text-sm text-muted-foreground">
                  Resultado para <code className="bg-muted px-2 py-1 rounded font-mono">{result.url}</code>
                </p>
                <p className="text-xs text-muted-foreground mt-1">
                  {result.timestamp.toLocaleString('es-ES')}
                </p>
              </div>
              <ExportButton result={result} />
            </div>

            {/* WordPress Detection Warning */}
            {!result.isWordPress && (
              <Alert className="mb-8 max-w-xl mx-auto border-destructive/30 bg-destructive/10">
                <AlertTriangle className="w-4 h-4 text-destructive" />
                <AlertDescription className="text-destructive">
                  Este sitio no parece ser WordPress. Los resultados pueden ser limitados.
                </AlertDescription>
              </Alert>
            )}

            {/* Score and CVSS */}
            <div className="flex flex-col sm:flex-row items-center justify-center gap-8 mb-12">
              <ScoreGauge score={result.overallScore} />
              {result.cvssOverall && (
                <OverallCvssCard cvss={result.cvssOverall} />
              )}
            </div>

            {/* Results Grid */}
            <div className="grid md:grid-cols-2 gap-6">
              <SecurityHeadersCard headers={result.securityHeaders} />
              <EndpointsCard endpoints={result.endpoints} />
              <UserEnumerationCard data={result.userEnumeration} />
              <WordPressInfoCard info={result.wordpressInfo} isWordPress={result.isWordPress} />
              <Recommendations result={result} />
            </div>
          </div>
        </section>
      )}

      {/* Loading Skeleton */}
      {isLoading && !result && progress && progress.percentage >= 50 && (
        <section className="pb-16 px-4">
          <div className="container mx-auto max-w-6xl">
            <AuditLoadingSkeleton />
          </div>
        </section>
      )}

      {/* Footer */}
      <footer className="border-t border-border py-6">
        <div className="container mx-auto px-4 text-center text-sm text-muted-foreground">
          <p>
            WP Security Auditor • Herramienta de código abierto para auditorías de seguridad WordPress
          </p>
          <p className="mt-1 text-xs">
            Usa proxies CORS públicos. Solo para sitios de tu propiedad o con autorización.
          </p>
        </div>
      </footer>
    </div>
  );
};

export default Index;
