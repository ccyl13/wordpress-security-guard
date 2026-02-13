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
import { useAuditHistory } from '@/hooks/useAuditHistory';
import { auditWordPress, type AuditProgress } from '@/lib/wordpress-auditor';
import type { AuditResult } from '@/types/wordpress-audit';
import { AlertTriangle, ShieldOff, Shield, MessageCircle, Mail } from 'lucide-react';
import { Alert, AlertDescription } from '@/components/ui/alert';
import jiratekLogo from '@/assets/logo-jiratek.jpg';

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
            <img src={jiratekLogo} alt="JIRATEK" className="w-10 h-10 rounded-lg" />
            <div>
              <h1 className="text-xl font-bold tracking-tight">JIRATEK</h1>
              <p className="text-xs text-muted-foreground">Ciberseguridad</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <AuditHistory 
              history={history} 
              onSelect={handleHistorySelect}
              onClear={clearHistory}
            />
            <a 
              href="https://wa.me/34644254179" 
              target="_blank" 
              rel="noopener noreferrer"
              className="p-2 rounded-lg bg-primary/10 text-primary hover:bg-primary/20 transition-colors"
              title="WhatsApp"
            >
              <MessageCircle className="w-5 h-5" />
            </a>
            <a 
              href="mailto:hola@jiratek.com" 
              className="p-2 rounded-lg bg-primary/10 text-primary hover:bg-primary/20 transition-colors"
              title="Email"
            >
              <Mail className="w-5 h-5" />
            </a>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="py-16 px-4">
        <div className="container mx-auto max-w-4xl text-center">
          <h2 className="text-4xl md:text-5xl font-black mb-4 tracking-tight animate-fade-in">
            Audita la seguridad de<br />
            <span className="text-primary">cualquier WordPress</span>
          </h2>
          <p className="text-lg text-muted-foreground mb-8 max-w-2xl mx-auto animate-fade-in">
            Analiza cabeceras de seguridad, endpoints sensibles, enumeración de usuarios y más.
            Herramienta de <strong className="text-primary">JIRATEK Ciberseguridad</strong>.
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

            {/* WordPress Detection Status */}
            {result.wpDetection === 'not_detected' && (
              <Alert className="mb-8 max-w-xl mx-auto border-destructive/30 bg-destructive/10">
                <AlertTriangle className="w-4 h-4 text-destructive" />
                <AlertDescription className="text-destructive">
                  Este sitio no parece ser WordPress. Los resultados pueden ser limitados.
                </AlertDescription>
              </Alert>
            )}
            {result.wpDetection === 'blocked' && (
              <Alert className="mb-8 max-w-xl mx-auto border-yellow-500/30 bg-yellow-500/10">
                <ShieldOff className="w-4 h-4 text-yellow-500" />
                <AlertDescription className="text-yellow-400">
                  <strong>No se pudo verificar si es WordPress.</strong> {result.wpDetectionDetails}
                  <br />
                  <span className="text-xs text-muted-foreground mt-1 block">
                    El sitio puede estar protegido por WAF, captcha o bloqueo anti-bot. Los resultados del análisis pueden estar incompletos.
                  </span>
                </AlertDescription>
              </Alert>
            )}
            {result.wpDetection === 'detected' && result.detectedWpPath && (
              <Alert className="mb-8 max-w-xl mx-auto border-primary/30 bg-primary/10">
                <Shield className="w-4 h-4 text-primary" />
                <AlertDescription className="text-primary">
                  WordPress detectado en subdirectorio: <code className="bg-muted px-1.5 py-0.5 rounded font-mono text-xs">{result.detectedWpPath}</code>
                </AlertDescription>
              </Alert>
            )}

            

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
            JIRATEK Ciberseguridad • Auditoría de seguridad WordPress
          </p>
          <p className="mt-2 flex items-center justify-center gap-4">
            <a href="https://wa.me/34644254179" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline inline-flex items-center gap-1">
              <MessageCircle className="w-4 h-4" /> WhatsApp
            </a>
            <a href="mailto:hola@jiratek.com" className="text-primary hover:underline inline-flex items-center gap-1">
              <Mail className="w-4 h-4" /> hola@jiratek.com
            </a>
          </p>
          <p className="mt-1 text-xs">
            Solo para sitios de tu propiedad o con autorización.
          </p>
        </div>
      </footer>
    </div>
  );
};

export default Index;
