import { useState } from 'react';
import { AuditForm } from '@/components/AuditForm';
import { ScoreGauge } from '@/components/ScoreGauge';
import { SecurityHeadersCard } from '@/components/SecurityHeadersCard';
import { EndpointsCard } from '@/components/EndpointsCard';
import { UserEnumerationCard } from '@/components/UserEnumerationCard';
import { WordPressInfoCard } from '@/components/WordPressInfoCard';
import { auditWordPress } from '@/lib/wordpress-auditor';
import type { AuditResult } from '@/types/wordpress-audit';
import { Shield, Terminal, AlertTriangle, Github } from 'lucide-react';
import { Alert, AlertDescription } from '@/components/ui/alert';

const Index = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [progress, setProgress] = useState('');
  const [result, setResult] = useState<AuditResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleAudit = async (url: string) => {
    setIsLoading(true);
    setError(null);
    setResult(null);
    setProgress('Iniciando auditoría...');

    try {
      const auditResult = await auditWordPress(url, setProgress);
      setResult(auditResult);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error desconocido');
    } finally {
      setIsLoading(false);
      setProgress('');
    }
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-primary/10 rounded-lg">
              <Shield className="w-6 h-6 text-primary" />
            </div>
            <div>
              <h1 className="text-xl font-bold tracking-tight">WP Security Auditor</h1>
              <p className="text-xs text-muted-foreground">Análisis de seguridad para WordPress</p>
            </div>
          </div>
          <a 
            href="https://github.com" 
            target="_blank" 
            rel="noopener noreferrer"
            className="text-muted-foreground hover:text-foreground transition-colors"
          >
            <Github className="w-5 h-5" />
          </a>
        </div>
      </header>

      {/* Hero Section */}
      <section className="py-16 px-4">
        <div className="container mx-auto max-w-4xl text-center">
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-primary/10 text-primary text-sm font-medium mb-6">
            <Terminal className="w-4 h-4" />
            100% Frontend • Sin Backend • GitHub Pages Ready
          </div>
          <h2 className="text-4xl md:text-5xl font-black mb-4 tracking-tight">
            Audita la seguridad de<br />
            <span className="text-primary">cualquier WordPress</span>
          </h2>
          <p className="text-lg text-muted-foreground mb-8 max-w-2xl mx-auto">
            Analiza cabeceras de seguridad, endpoints sensibles, enumeración de usuarios y más. 
            Todo desde tu navegador, sin necesidad de servidor.
          </p>
          
          <AuditForm onSubmit={handleAudit} isLoading={isLoading} />
          
          {isLoading && progress && (
            <p className="mt-4 text-sm text-muted-foreground animate-pulse">
              {progress}
            </p>
          )}
          
          {error && (
            <Alert variant="destructive" className="mt-6 max-w-xl mx-auto">
              <AlertTriangle className="w-4 h-4" />
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          )}
        </div>
      </section>

      {/* Results Section */}
      {result && (
        <section className="pb-16 px-4">
          <div className="container mx-auto max-w-6xl">
            {/* URL and Timestamp */}
            <div className="text-center mb-8">
              <p className="text-sm text-muted-foreground">
                Resultado para <code className="bg-muted px-2 py-1 rounded">{result.url}</code>
              </p>
              <p className="text-xs text-muted-foreground mt-1">
                {result.timestamp.toLocaleString('es-ES')}
              </p>
            </div>

            {/* WordPress Detection Warning */}
            {!result.isWordPress && (
              <Alert className="mb-8 max-w-xl mx-auto border-yellow-500/30 bg-yellow-500/10">
                <AlertTriangle className="w-4 h-4 text-yellow-500" />
                <AlertDescription className="text-yellow-500">
                  Este sitio no parece ser WordPress. Los resultados pueden ser limitados.
                </AlertDescription>
              </Alert>
            )}

            {/* Score */}
            <div className="flex justify-center mb-12">
              <ScoreGauge score={result.overallScore} />
            </div>

            {/* Results Grid */}
            <div className="grid md:grid-cols-2 gap-6">
              <SecurityHeadersCard headers={result.securityHeaders} />
              <EndpointsCard endpoints={result.endpoints} />
              <UserEnumerationCard data={result.userEnumeration} />
              <WordPressInfoCard info={result.wordpressInfo} isWordPress={result.isWordPress} />
            </div>
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
            Esta herramienta usa proxies CORS públicos. Úsala solo en sitios de tu propiedad o con autorización.
          </p>
        </div>
      </footer>
    </div>
  );
};

export default Index;
