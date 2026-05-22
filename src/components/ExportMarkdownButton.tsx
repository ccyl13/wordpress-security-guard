import type { AuditResult } from '@/types/wordpress-audit';
import { FileText } from 'lucide-react';

function scoreLabel(s: number): string {
  if (s >= 80) return 'Seguro';
  if (s >= 60) return 'Moderado';
  if (s >= 40) return 'Vulnerable';
  return 'Crítico';
}

function statusEmoji(s: string): string {
  return s === 'secure' ? '✅' : s === 'warning' ? '⚠️' : s === 'vulnerable' ? '❌' : 'ℹ️';
}

function riskEmoji(r: string): string {
  return { critical: '🔴', high: '🟠', medium: '🟡', low: '🔵', info: 'ℹ️' }[r] || '⚪';
}

function buildMarkdown(r: AuditResult): string {
  const date = new Date(r.timestamp).toLocaleString('es-ES');
  const label = scoreLabel(r.overallScore);

  const headersFail = r.securityHeaders.filter(h => h.status === 'vulnerable').length;
  const headersWarn = r.securityHeaders.filter(h => h.status === 'warning').length;
  const headersOk = r.securityHeaders.filter(h => h.status === 'secure').length;
  const endpointsExposed = r.endpoints.filter(e => e.status === 'accessible').length;
  const endpointsBlocked = r.endpoints.filter(e => e.status !== 'accessible').length;
  const usersExposed = r.userEnumeration.found ? r.userEnumeration.users.length : 0;

  // --- Build the Markdown ---
  const lines: string[] = [];

  // Header
  lines.push('# 🛡️ WPSentry — Informe de Auditoría de Seguridad');
  lines.push('');
  lines.push('> Este documento contiene los resultados completos de una auditoría de seguridad pasiva.');
  lines.push('> Analiza los datos y genera una lista de tareas de remediación con prioridades, tiempos estimados y criticidad.');
  lines.push('');

  // Site info
  lines.push('## 📋 Información General');
  lines.push('');
  lines.push(`| Campo | Valor |`);
  lines.push(`|---|---|`);
  lines.push(`| **Sitio auditado** | \`${r.url}\` |`);
  lines.push(`| **Fecha** | ${date} |`);
  lines.push(`| **Puntuación** | **${r.overallScore}/100** — ${label} |`);
  if (r.cvssOverall) {
    lines.push(`| **CVSS 3.1** | **${r.cvssOverall.score.toFixed(1)}** — ${r.cvssOverall.severity} |`);
    lines.push(`| **Vector CVSS** | \`${r.cvssOverall.vector}\` |`);
  }
  lines.push(`| **WordPress detectado** | ${r.isWordPress ? 'Sí' : 'No'} |`);
  lines.push(`| **Versión WordPress** | ${r.wordpressInfo.version || 'Oculta / No detectada'} |`);
  lines.push(`| **Tema activo** | ${r.wordpressInfo.theme || 'No detectado'} |`);
  lines.push(`| **Meta Generator** | ${r.wordpressInfo.generator ? 'Expuesta ⚠️' : 'Oculta ✅'} |`);
  lines.push(`| **readme.html** | ${r.wordpressInfo.readme ? 'Accesible ⚠️' : 'Bloqueado ✅'} |`);
  lines.push(`| **WAF detectado** | ${r.wordpressInfo.wafDetected || 'No detectado'} |`);
  lines.push(`| **SSL / HTTPS** | ${r.wordpressInfo.sslInfo?.valid ? 'Válido ✅' : 'No seguro ❌'} |`);
  lines.push(`| **Tipo de auditoría** | Pasiva — Sin intrusiones |`);
  lines.push('');

  // Quick stats
  lines.push('## 📊 Resumen Rápido');
  lines.push('');
  lines.push(`| Métrica | Valor |`);
  lines.push(`|---|---|`);
  lines.push(`| Cabeceras fallidas | **${headersFail}** ❌ |`);
  lines.push(`| Cabeceras con advertencia | **${headersWarn}** ⚠️ |`);
  lines.push(`| Cabeceras correctas | **${headersOk}** ✅ |`);
  lines.push(`| Endpoints expuestos | **${endpointsExposed}** ❌ |`);
  lines.push(`| Endpoints bloqueados | **${endpointsBlocked}** ✅ |`);
  lines.push(`| Usuarios expuestos | **${usersExposed}** ${usersExposed > 0 ? '❌' : '✅'} |`);
  lines.push('');

  // Security Headers
  lines.push('## 🔒 Cabeceras HTTP de Seguridad');
  lines.push('');
  lines.push(`| Cabecera | Estado | Nivel | Descripción | OWASP | CWE | CVSS |`);
  lines.push(`|---|---|---|---|---|---|---|`);
  for (const h of r.securityHeaders) {
    const owasp = h.reference?.owasp || '—';
    const cwe = h.reference?.cwe || '—';
    const cvss = h.reference?.cvss ? `${h.reference.cvss.score.toFixed(1)} (${h.reference.cvss.severity})` : '—';
    lines.push(`| \`${h.name}\` | ${statusEmoji(h.status)} ${h.status} | ${h.status} | ${h.description} | ${owasp} | ${cwe} | ${cvss} |`);
  }
  lines.push('');

  // Endpoints
  lines.push('## 🌐 Endpoints Sensibles');
  lines.push('');
  lines.push(`| Endpoint | URL | Riesgo | HTTP | Estado | Descripción |`);
  lines.push(`|---|---|---|---|---|---|`);
  for (const ep of r.endpoints) {
    const path = (() => { try { const u = new URL(ep.url); return u.pathname + u.search; } catch { return ep.url; } })();
    const httpCode = ep.statusCode && ep.statusCode > 0 ? `${ep.statusCode}` : '—';
    const exposed = ep.status === 'accessible';
    const statusLabel = exposed ? '❌ EXPUESTO' : '✅ OK';
    lines.push(`| **${ep.name}** | \`${path}\` | ${riskEmoji(ep.risk)} ${ep.risk} | ${httpCode} | ${statusLabel} | ${ep.description} |`);
  }
  lines.push('');

  // Detailed endpoint references (for exposed ones)
  const exposedEndpoints = r.endpoints.filter(e => e.status === 'accessible');
  if (exposedEndpoints.length > 0) {
    lines.push('### Detalle de Endpoints Expuestos');
    lines.push('');
    for (const ep of exposedEndpoints) {
      const ref = ep.reference;
      lines.push(`- **${ep.name}** (\`${ep.url}\`)`);
      lines.push(`  - Riesgo: ${riskEmoji(ep.risk)} **${ep.risk.toUpperCase()}**`);
      lines.push(`  - Descripción: ${ep.description}`);
      if (ref?.owasp) lines.push(`  - OWASP: ${ref.owasp}`);
      if (ref?.cwe) lines.push(`  - CWE: ${ref.cwe}`);
      if (ref?.cvss) lines.push(`  - CVSS: ${ref.cvss.score.toFixed(1)} (${ref.cvss.severity}) — Vector: \`${ref.cvss.vector}\``);
    }
    lines.push('');
  }

  // User Enumeration
  lines.push('## 👤 Enumeración de Usuarios');
  lines.push('');
  lines.push(`| Campo | Valor |`);
  lines.push(`|---|---|`);
  lines.push(`| **Estado** | ${r.userEnumeration.found ? '❌ VULNERABLE' : '✅ PROTEGIDO'} |`);
  lines.push(`| **Método** | ${r.userEnumeration.method} |`);
  if (r.userEnumeration.protectionDetails) {
    lines.push(`| **Detalles** | ${r.userEnumeration.protectionDetails} |`);
  }
  if (r.userEnumeration.reference?.owasp) {
    lines.push(`| **OWASP** | ${r.userEnumeration.reference.owasp} |`);
  }
  if (r.userEnumeration.reference?.cwe) {
    lines.push(`| **CWE** | ${r.userEnumeration.reference.cwe} |`);
  }
  if (r.userEnumeration.reference?.cvss) {
    lines.push(`| **CVSS** | ${r.userEnumeration.reference.cvss.score.toFixed(1)} (${r.userEnumeration.reference.cvss.severity}) |`);
  }
  lines.push('');

  if (r.userEnumeration.found && r.userEnumeration.users.length > 0) {
    lines.push('### Usuarios Detectados');
    lines.push('');
    lines.push(`| ID | Nombre | Slug |`);
    lines.push(`|---|---|---|`);
    for (const u of r.userEnumeration.users) {
      lines.push(`| ${u.id} | ${u.name} | \`@${u.slug}\` |`);
    }
    lines.push('');
  }

  // Raw data for LLM context
  lines.push('## 🧠 Datos Estructurados para Análisis');
  lines.push('');
  lines.push('A continuación se presentan los hallazgos categorizados para facilitar la generación de un plan de acción.');
  lines.push('');

  // Group findings by severity
  const findings: Array<{ category: string; item: string; severity: string; status: string; owasp: string; cwe: string; cvss: string; description: string }> = [];

  // From headers
  for (const h of r.securityHeaders) {
    if (h.status === 'secure') continue;
    findings.push({
      category: 'Cabecera HTTP',
      item: h.name,
      severity: h.status === 'vulnerable' ? 'high' : h.status === 'warning' ? 'medium' : 'low',
      status: h.status,
      owasp: h.reference?.owasp || '—',
      cwe: h.reference?.cwe || '—',
      cvss: h.reference?.cvss ? `${h.reference.cvss.score.toFixed(1)}` : '—',
      description: h.description,
    });
  }

  // From endpoints
  for (const ep of r.endpoints) {
    if (ep.status !== 'accessible') continue;
    findings.push({
      category: 'Endpoint Expuesto',
      item: ep.name,
      severity: ep.risk,
      status: 'exposed',
      owasp: ep.reference?.owasp || '—',
      cwe: ep.reference?.cwe || '—',
      cvss: ep.reference?.cvss ? `${ep.reference.cvss.score.toFixed(1)}` : '—',
      description: ep.description,
    });
  }

  // User enumeration
  if (r.userEnumeration.found) {
    findings.push({
      category: 'Enumeración de Usuarios',
      item: `${r.userEnumeration.users.length} usuarios expuestos`,
      severity: 'high',
      status: 'vulnerable',
      owasp: r.userEnumeration.reference?.owasp || '—',
      cwe: r.userEnumeration.reference?.cwe || '—',
      cvss: r.userEnumeration.reference?.cvss ? `${r.userEnumeration.reference.cvss.score.toFixed(1)}` : '—',
      description: `Usuarios expuestos vía ${r.userEnumeration.method}: ${r.userEnumeration.users.map(u => u.name).join(', ')}`,
    });
  }

  // Version disclosure
  if (r.wordpressInfo.version) {
    findings.push({
      category: 'Exposición de Información',
      item: `WordPress ${r.wordpressInfo.version}`,
      severity: 'medium',
      status: 'exposed',
      owasp: 'A05:2021-Security Misconfiguration',
      cwe: 'CWE-200',
      cvss: '2.0',
      description: `La versión ${r.wordpressInfo.version} de WordPress es visible públicamente.`,
    });
  }

  if (r.wordpressInfo.generator) {
    findings.push({
      category: 'Exposición de Información',
      item: 'Meta Generator expuesta',
      severity: 'low',
      status: 'exposed',
      owasp: 'A05:2021-Security Misconfiguration',
      cwe: 'CWE-200',
      cvss: '2.0',
      description: 'La etiqueta meta generator revela que el sitio usa WordPress.',
    });
  }

  // Sort by severity
  const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5));

  if (findings.length > 0) {
    lines.push(`### Todos los Hallazgos (${findings.length} total)`);
    lines.push('');
    lines.push(`| # | Categoría | Hallazgo | Severidad | OWASP | CWE | CVSS | Descripción |`);
    lines.push(`|---|---|---|---|---|---|---|---|`);
    findings.forEach((f, i) => {
      const sev = riskEmoji(f.severity) + ' ' + f.severity.toUpperCase();
      lines.push(`| ${i + 1} | ${f.category} | ${f.item} | ${sev} | ${f.owasp} | ${f.cwe} | ${f.cvss} | ${f.description} |`);
    });
    lines.push('');
  } else {
    lines.push('> ✅ No se encontraron hallazgos de seguridad significativos.');
    lines.push('');
  }

  // Prompt for LLM
  lines.push('---');
  lines.push('');
  lines.push('## 🤖 Instrucciones para Análisis LLM');
  lines.push('');
  lines.push('Con los datos anteriores, genera un plan de remediación en formato de lista de tareas con:');
  lines.push('');
  lines.push('1. **Checkbox** (`- [ ]`) por cada tarea');
  lines.push('2. **Prioridad**: Crítica / Alta / Media / Baja');
  lines.push('3. **Tiempo estimado** de implementación');
  lines.push('4. **Impacto** si no se corrige');
  lines.push('5. **Pasos de remediación** concretos con código cuando aplique');
  lines.push('6. **Orden de ejecución** recomendado (las más críticas primero)');
  lines.push('');
  lines.push('Agrupa las tareas por criticidad y proporciona un resumen ejecutivo al inicio.');
  lines.push('');

  // Footer
  lines.push('---');
  lines.push(`*Generado por WPSentry v2.0 · Auditoría pasiva · Uso ético y educativo*  `);
  lines.push(`*${date}*`);

  return lines.join('\n');
}

export function ExportMarkdownButton({ result }: { result: AuditResult }) {
  const handleExport = () => {
    const md = buildMarkdown(result);
    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const host = (() => { try { return new URL(result.url).hostname.replace(/[^a-z0-9]/gi, '-'); } catch { return 'report'; } })();
    a.href = url;
    a.download = `wpsentry-${host}-${new Date().toISOString().split('T')[0]}.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <button
      onClick={handleExport}
      className="btn-icon flex items-center gap-2 px-4 w-auto text-xs font-semibold text-white/50 hover:text-white/80"
    >
      <FileText size={13} />
      Exportar MD
    </button>
  );
}
