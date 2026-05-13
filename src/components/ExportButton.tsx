import type { AuditResult } from '@/types/wordpress-audit';
import { Download } from 'lucide-react';

function scoreColor(s: number) {
  if (s >= 80) return { hex: '#10b981', label: 'Seguro' };
  if (s >= 60) return { hex: '#f59e0b', label: 'Moderado' };
  if (s >= 40) return { hex: '#f97316', label: 'Vulnerable' };
  return { hex: '#ef4444', label: 'Critico' };
}

function riskColor(r: string) {
  return { critical:'#ef4444', high:'#f97316', medium:'#eab308', low:'#3b82f6', info:'#6b7280' }[r] || '#6b7280';
}

function statusColor(s: string) {
  return s === 'secure' ? '#10b981' : s === 'warning' ? '#eab308' : s === 'vulnerable' ? '#ef4444' : '#3b82f6';
}

function buildHTML(r: AuditResult): string {
  const sc = scoreColor(r.overallScore);
  const date = new Date(r.timestamp).toLocaleString('es-ES');
  const circ = 2 * Math.PI * 52;
  const offset = circ - (r.overallScore / 100) * circ;

  const headersRows = r.securityHeaders.map(h => {
    const c = statusColor(h.status);
    const icon = h.status === 'secure' ? '✓' : h.status === 'warning' ? '⚠' : h.status === 'info' ? 'ℹ' : '✗';
    return `<tr>
      <td style="padding:10px 14px;border-bottom:1px solid #1a1a2e;font-family:monospace;font-size:12px;color:#e2e8f0">${h.name}</td>
      <td style="padding:10px 14px;border-bottom:1px solid #1a1a2e;text-align:center">
        <span style="color:${c};font-weight:700;font-size:13px">${icon}</span>
      </td>
      <td style="padding:10px 14px;border-bottom:1px solid #1a1a2e">
        <span style="background:${c}18;color:${c};border:1px solid ${c}40;border-radius:4px;padding:2px 8px;font-size:10px;font-family:monospace;font-weight:700;text-transform:uppercase">${h.status}</span>
      </td>
      <td style="padding:10px 14px;border-bottom:1px solid #1a1a2e;font-size:11px;color:#94a3b8">${h.description}</td>
      ${h.reference?.owasp ? `<td style="padding:10px 14px;border-bottom:1px solid #1a1a2e;font-family:monospace;font-size:10px;color:#64748b">${h.reference.owasp}</td>` : '<td style="border-bottom:1px solid #1a1a2e"></td>'}
    </tr>`;
  }).join('');

  const endpointRows = r.endpoints.map(ep => {
    const acc = ep.status === 'accessible';
    const rc = riskColor(ep.risk);
    const path = (() => { try { const u = new URL(ep.url); return u.pathname + u.search; } catch { return ep.url; } })();
    return `<tr style="${acc ? 'background:rgba(239,68,68,0.04)' : ''}">
      <td style="padding:10px 14px;border-bottom:1px solid #1a1a2e">
        <div style="font-size:12px;font-weight:600;color:#e2e8f0;margin-bottom:2px">${ep.name}</div>
        ${acc
          ? `<a href="${ep.url}" target="_blank" style="font-family:monospace;font-size:10px;color:#f87171;text-decoration:none">${path} ↗</a>`
          : `<span style="font-family:monospace;font-size:10px;color:#475569">${path}</span>`}
      </td>
      <td style="padding:10px 14px;border-bottom:1px solid #1a1a2e;text-align:center">
        <span style="background:${rc}18;color:${rc};border:1px solid ${rc}40;border-radius:4px;padding:2px 8px;font-size:10px;font-family:monospace;font-weight:700;text-transform:uppercase">${ep.risk}</span>
      </td>
      <td style="padding:10px 14px;border-bottom:1px solid #1a1a2e;text-align:center">
        ${ep.statusCode && ep.statusCode > 0 ? `<span style="font-family:monospace;font-size:11px;color:#64748b">HTTP ${ep.statusCode}</span>` : '—'}
      </td>
      <td style="padding:10px 14px;border-bottom:1px solid #1a1a2e;text-align:center">
        ${acc
          ? '<span style="background:#ef444418;color:#ef4444;border:1px solid #ef444440;border-radius:4px;padding:2px 10px;font-size:10px;font-family:monospace;font-weight:700">EXPOSED</span>'
          : '<span style="background:#10b98118;color:#10b981;border:1px solid #10b98140;border-radius:4px;padding:2px 10px;font-size:10px;font-family:monospace;font-weight:700">OK</span>'}
      </td>
      <td style="padding:10px 14px;border-bottom:1px solid #1a1a2e;font-size:11px;color:#94a3b8">${ep.description}</td>
    </tr>`;
  }).join('');

  const usersBlock = r.userEnumeration.found && r.userEnumeration.users.length > 0
    ? r.userEnumeration.users.map(u => `
      <div style="display:flex;align-items:center;gap:10px;padding:8px 12px;background:#1a1a2e;border-radius:6px;margin-bottom:6px">
        <div style="width:28px;height:28px;border-radius:50%;background:#7c3aed40;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;color:#a78bfa">${u.name?.[0]?.toUpperCase()||'?'}</div>
        <div>
          <div style="font-size:12px;font-weight:600;color:#e2e8f0">${u.name}</div>
          <div style="font-family:monospace;font-size:10px;color:#64748b">@${u.slug}</div>
        </div>
      </div>`).join('')
    : '<p style="color:#64748b;font-size:12px;margin:0">No se detectaron usuarios expuestos.</p>';

  const recsBlock = (() => {
    const items: string[] = [];
    const xmlrpc = r.endpoints.find(e => e.url.includes('xmlrpc') && e.status === 'accessible');
    if (xmlrpc) items.push(`<div style="background:#0f172a;border:1px solid #1e293b;border-left:3px solid #ef4444;border-radius:8px;padding:14px 16px;margin-bottom:10px">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
        <span style="background:#ef444418;color:#ef4444;border:1px solid #ef444440;border-radius:4px;padding:1px 7px;font-size:9px;font-family:monospace;font-weight:700">CRITICO</span>
        <span style="font-size:13px;font-weight:700;color:#f1f5f9">Deshabilitar XML-RPC</span>
      </div>
      <p style="font-size:11px;color:#94a3b8;margin:0 0 8px">XML-RPC expuesto puede usarse para ataques de fuerza bruta y DDoS amplificado.</p>
      <code style="display:block;background:#020617;border-radius:4px;padding:8px 10px;font-size:10px;color:#10b981;font-family:monospace">add_filter('xmlrpc_enabled', '__return_false');</code>
    </div>`);
    const missing = r.securityHeaders.filter(h => h.status === 'vulnerable' && ['content-security-policy','strict-transport-security','x-frame-options','x-content-type-options'].includes(h.name));
    if (missing.length > 0) items.push(`<div style="background:#0f172a;border:1px solid #1e293b;border-left:3px solid #f97316;border-radius:8px;padding:14px 16px;margin-bottom:10px">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
        <span style="background:#f9731618;color:#f97316;border:1px solid #f9731640;border-radius:4px;padding:1px 7px;font-size:9px;font-family:monospace;font-weight:700">ALTO</span>
        <span style="font-size:13px;font-weight:700;color:#f1f5f9">Cabeceras de seguridad criticas ausentes</span>
      </div>
      <p style="font-size:11px;color:#94a3b8;margin:0 0 8px">Faltan: ${missing.map(h=>h.name).join(', ')}</p>
      <code style="display:block;background:#020617;border-radius:4px;padding:8px 10px;font-size:10px;color:#10b981;font-family:monospace">Header always set X-Frame-Options "SAMEORIGIN"<br>Header always set X-Content-Type-Options "nosniff"<br>Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"</code>
    </div>`);
    if (r.userEnumeration.found) items.push(`<div style="background:#0f172a;border:1px solid #1e293b;border-left:3px solid #f97316;border-radius:8px;padding:14px 16px;margin-bottom:10px">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
        <span style="background:#f9731618;color:#f97316;border:1px solid #f9731640;border-radius:4px;padding:1px 7px;font-size:9px;font-family:monospace;font-weight:700">ALTO</span>
        <span style="font-size:13px;font-weight:700;color:#f1f5f9">Enumeracion de usuarios expuesta</span>
      </div>
      <p style="font-size:11px;color:#94a3b8;margin:0 0 8px">La REST API expone nombres de usuario validos.</p>
      <code style="display:block;background:#020617;border-radius:4px;padding:8px 10px;font-size:10px;color:#10b981;font-family:monospace">add_filter('rest_endpoints', function($e) { unset($e['/wp/v2/users']); return $e; });</code>
    </div>`);
    if (r.wordpressInfo.version) items.push(`<div style="background:#0f172a;border:1px solid #1e293b;border-left:3px solid #eab308;border-radius:8px;padding:14px 16px;margin-bottom:10px">
      <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
        <span style="background:#eab30818;color:#eab308;border:1px solid #eab30840;border-radius:4px;padding:1px 7px;font-size:9px;font-family:monospace;font-weight:700">MEDIO</span>
        <span style="font-size:13px;font-weight:700;color:#f1f5f9">Version de WordPress visible (${r.wordpressInfo.version})</span>
      </div>
      <p style="font-size:11px;color:#94a3b8;margin:0 0 8px">La version expuesta facilita ataques dirigidos a vulnerabilidades conocidas.</p>
      <code style="display:block;background:#020617;border-radius:4px;padding:8px 10px;font-size:10px;color:#10b981;font-family:monospace">remove_action('wp_head', 'wp_generator');</code>
    </div>`);
    return items.length ? items.join('') : '<p style="color:#64748b;font-size:12px">No se encontraron vulnerabilidades criticas.</p>';
  })();

  return `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>WPSentry Report — ${r.url}</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#020617;color:#f1f5f9;font-family:'Segoe UI',system-ui,sans-serif;min-height:100vh;padding:0}
  table{width:100%;border-collapse:collapse}
  @media print{body{background:#fff;color:#000}.no-print{display:none}}
</style>
</head>
<body>
<!-- HEADER -->
<div style="background:linear-gradient(135deg,#0a0a1a 0%,#0f0a2a 100%);border-bottom:1px solid #1e1b4b;padding:32px 40px">
  <div style="max-width:900px;margin:0 auto">
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:20px">
      <svg width="36" height="36" viewBox="0 0 30 30" fill="none">
        <polygon points="15,1 28,8.5 28,21.5 15,29 2,21.5 2,8.5" fill="rgba(139,92,246,0.2)" stroke="#a78bfa" stroke-width="0.8"/>
        <polygon points="15,7 23,11.5 23,18.5 15,23 7,18.5 7,11.5" fill="rgba(139,92,246,0.35)" stroke="#a78bfa" stroke-width="0.5"/>
        <circle cx="15" cy="15" r="3" fill="#a78bfa"/><circle cx="15" cy="15" r="1.2" fill="white"/>
      </svg>
      <div>
        <div style="font-size:20px;font-weight:800;letter-spacing:-0.5px">WP<span style="color:#8b5cf6">Sentry</span></div>
        <div style="font-family:monospace;font-size:9px;color:rgba(255,255,255,0.3);letter-spacing:2px;text-transform:uppercase">security audit report</div>
      </div>
    </div>
    <div style="display:flex;align-items:flex-start;justify-content:space-between;flex-wrap:wrap;gap:16px">
      <div>
        <div style="font-family:monospace;font-size:10px;color:rgba(255,255,255,0.3);letter-spacing:2px;text-transform:uppercase;margin-bottom:4px">Sitio auditado</div>
        <a href="${r.url}" target="_blank" style="font-size:18px;font-weight:700;color:#8b5cf6;text-decoration:none">${r.url}</a>
        <div style="font-family:monospace;font-size:10px;color:rgba(255,255,255,0.25);margin-top:4px">${date}</div>
      </div>
      <div style="display:flex;align-items:center;gap:6px;padding:6px 14px;background:rgba(139,92,246,0.1);border:1px solid rgba(139,92,246,0.25);border-radius:6px">
        <div style="width:6px;height:6px;border-radius:50%;background:#8b5cf6"></div>
        <span style="font-family:monospace;font-size:10px;color:#a78bfa;letter-spacing:1px">AUDITORIA PASIVA · SIN INTRUSIONES</span>
      </div>
    </div>
  </div>
</div>

<!-- SCORE STRIP -->
<div style="background:#0a0a18;border-bottom:1px solid #1a1a2e;padding:28px 40px">
  <div style="max-width:900px;margin:0 auto;display:flex;align-items:center;gap:40px;flex-wrap:wrap">
    <!-- SVG gauge -->
    <div style="position:relative;width:120px;height:120px;flex-shrink:0">
      <svg width="120" height="120" viewBox="0 0 120 120" style="transform:rotate(-90deg)">
        <circle cx="60" cy="60" r="52" fill="none" stroke="#1e293b" stroke-width="10"/>
        <circle cx="60" cy="60" r="52" fill="none" stroke="${sc.hex}" stroke-width="10"
          stroke-dasharray="${circ.toFixed(1)}" stroke-dashoffset="${offset.toFixed(1)}"
          stroke-linecap="round" style="filter:drop-shadow(0 0 8px ${sc.hex}60)"/>
      </svg>
      <div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center">
        <span style="font-size:28px;font-weight:800;color:${sc.hex};letter-spacing:-1px">${r.overallScore}</span>
        <span style="font-family:monospace;font-size:9px;color:rgba(255,255,255,0.25)">/100</span>
      </div>
    </div>
    <div>
      <div style="font-size:22px;font-weight:800;color:${sc.hex};margin-bottom:4px">${sc.label}</div>
      ${r.cvssOverall ? `<div style="font-family:monospace;font-size:12px;color:rgba(255,255,255,0.4)">CVSS 3.1: <span style="color:${sc.hex};font-weight:700">${r.cvssOverall.score.toFixed(1)} — ${r.cvssOverall.severity}</span></div>
      <div style="font-family:monospace;font-size:9px;color:rgba(255,255,255,0.2);margin-top:3px">${r.cvssOverall.vector||''}</div>` : ''}
    </div>
    <!-- mini stats -->
    <div style="display:flex;gap:20px;margin-left:auto;flex-wrap:wrap">
      ${[
        {n: r.securityHeaders.filter(h=>h.status==='vulnerable').length, l:'headers fail', c:'#ef4444'},
        {n: r.endpoints.filter(e=>e.status==='accessible').length, l:'endpoints expuestos', c:'#f97316'},
        {n: r.userEnumeration.found ? r.userEnumeration.users.length : 0, l:'usuarios expuestos', c:'#eab308'},
      ].map(s=>`<div style="text-align:center">
        <div style="font-size:24px;font-weight:800;font-family:monospace;color:${s.c}">${s.n}</div>
        <div style="font-family:monospace;font-size:9px;color:rgba(255,255,255,0.25);text-transform:uppercase;letter-spacing:1px">${s.l}</div>
      </div>`).join('')}
    </div>
  </div>
</div>

<div style="max-width:900px;margin:0 auto;padding:32px 40px">

<!-- SITE INFO -->
<div style="background:#0a0a18;border:1px solid #1a1a2e;border-radius:12px;padding:20px;margin-bottom:24px">
  <div style="font-size:13px;font-weight:700;color:#e2e8f0;margin-bottom:14px;display:flex;align-items:center;gap:8px">
    <span style="color:#8b5cf6">■</span> Informacion del sitio
  </div>
  <div style="display:grid;grid-template-columns:1fr 1fr;gap:0">
    ${[
      {l:'WordPress detectado', v: r.isWordPress ? 'Si' : 'No', good: r.isWordPress},
      {l:'Version WordPress', v: r.wordpressInfo.version || 'Oculta', good: !r.wordpressInfo.version},
      {l:'Tema activo', v: r.wordpressInfo.theme || 'No detectado', good: null},
      {l:'Cabecera Generator', v: r.wordpressInfo.generator ? 'Expuesta' : 'Oculta', good: !r.wordpressInfo.generator},
      {l:'readme.html', v: r.wordpressInfo.readme ? 'Accesible' : 'Bloqueado', good: !r.wordpressInfo.readme},
      {l:'WAF detectado', v: r.wordpressInfo.wafDetected || 'No detectado', good: !!r.wordpressInfo.wafDetected},
      {l:'SSL / HTTPS', v: r.wordpressInfo.sslInfo?.valid ? 'Valido' : 'No seguro', good: r.wordpressInfo.sslInfo?.valid},
    ].map(row=>`<div style="display:flex;justify-content:space-between;align-items:center;padding:9px 12px;border-bottom:1px solid #1a1a2e">
      <span style="font-family:monospace;font-size:10px;color:#64748b">${row.l}</span>
      <span style="font-family:monospace;font-size:11px;font-weight:600;color:${row.good===null?'#94a3b8':row.good?'#10b981':'#ef4444'}">${row.v}</span>
    </div>`).join('')}
  </div>
</div>

<!-- SECURITY HEADERS -->
<div style="background:#0a0a18;border:1px solid #1a1a2e;border-radius:12px;overflow:hidden;margin-bottom:24px">
  <div style="padding:14px 20px;border-bottom:1px solid #1a1a2e;display:flex;align-items:center;justify-content:space-between">
    <div style="font-size:13px;font-weight:700;color:#e2e8f0;display:flex;align-items:center;gap:8px"><span style="color:#8b5cf6">■</span> Cabeceras HTTP de seguridad</div>
    <div style="font-family:monospace;font-size:10px;color:#64748b">
      <span style="color:#10b981">${r.securityHeaders.filter(h=>h.status==='secure').length} ok</span>
      &nbsp;·&nbsp;<span style="color:#eab308">${r.securityHeaders.filter(h=>h.status==='warning').length} warn</span>
      &nbsp;·&nbsp;<span style="color:#ef4444">${r.securityHeaders.filter(h=>h.status==='vulnerable').length} fail</span>
    </div>
  </div>
  <table>
    <thead>
      <tr style="background:#060612">
        <th style="padding:8px 14px;text-align:left;font-family:monospace;font-size:9px;color:#475569;font-weight:600;letter-spacing:1px;text-transform:uppercase">CABECERA</th>
        <th style="padding:8px 14px;text-align:center;font-family:monospace;font-size:9px;color:#475569;font-weight:600;letter-spacing:1px;text-transform:uppercase">ESTADO</th>
        <th style="padding:8px 14px;font-family:monospace;font-size:9px;color:#475569;font-weight:600;letter-spacing:1px;text-transform:uppercase">NIVEL</th>
        <th style="padding:8px 14px;font-family:monospace;font-size:9px;color:#475569;font-weight:600;letter-spacing:1px;text-transform:uppercase">DESCRIPCION</th>
        <th style="padding:8px 14px;font-family:monospace;font-size:9px;color:#475569;font-weight:600;letter-spacing:1px;text-transform:uppercase">REF</th>
      </tr>
    </thead>
    <tbody>${headersRows}</tbody>
  </table>
</div>

<!-- ENDPOINTS -->
<div style="background:#0a0a18;border:1px solid #1a1a2e;border-radius:12px;overflow:hidden;margin-bottom:24px">
  <div style="padding:14px 20px;border-bottom:1px solid #1a1a2e;display:flex;align-items:center;justify-content:space-between">
    <div style="font-size:13px;font-weight:700;color:#e2e8f0;display:flex;align-items:center;gap:8px"><span style="color:#3b82f6">■</span> Endpoints sensibles</div>
    <span style="background:${r.endpoints.filter(e=>e.status==='accessible').length>0?'#ef444418':'#10b98118'};color:${r.endpoints.filter(e=>e.status==='accessible').length>0?'#ef4444':'#10b981'};border:1px solid ${r.endpoints.filter(e=>e.status==='accessible').length>0?'#ef444440':'#10b98140'};border-radius:4px;padding:2px 10px;font-size:10px;font-family:monospace;font-weight:700">
      ${r.endpoints.filter(e=>e.status==='accessible').length} expuestos
    </span>
  </div>
  <table>
    <thead>
      <tr style="background:#060612">
        <th style="padding:8px 14px;text-align:left;font-family:monospace;font-size:9px;color:#475569;font-weight:600;letter-spacing:1px;text-transform:uppercase">ENDPOINT</th>
        <th style="padding:8px 14px;text-align:center;font-family:monospace;font-size:9px;color:#475569;font-weight:600;letter-spacing:1px;text-transform:uppercase">RIESGO</th>
        <th style="padding:8px 14px;text-align:center;font-family:monospace;font-size:9px;color:#475569;font-weight:600;letter-spacing:1px;text-transform:uppercase">HTTP</th>
        <th style="padding:8px 14px;text-align:center;font-family:monospace;font-size:9px;color:#475569;font-weight:600;letter-spacing:1px;text-transform:uppercase">ESTADO</th>
        <th style="padding:8px 14px;font-family:monospace;font-size:9px;color:#475569;font-weight:600;letter-spacing:1px;text-transform:uppercase">DESCRIPCION</th>
      </tr>
    </thead>
    <tbody>${endpointRows}</tbody>
  </table>
</div>

<!-- USER ENUM -->
<div style="background:#0a0a18;border:1px solid #1a1a2e;border-radius:12px;padding:20px;margin-bottom:24px">
  <div style="font-size:13px;font-weight:700;color:#e2e8f0;margin-bottom:14px;display:flex;align-items:center;justify-content:space-between">
    <div style="display:flex;align-items:center;gap:8px"><span style="color:#10b981">■</span> Enumeracion de usuarios</div>
    <span style="background:${r.userEnumeration.found?'#ef444418':'#10b98118'};color:${r.userEnumeration.found?'#ef4444':'#10b981'};border:1px solid ${r.userEnumeration.found?'#ef444440':'#10b98140'};border-radius:4px;padding:2px 10px;font-size:10px;font-family:monospace;font-weight:700">
      ${r.userEnumeration.found ? 'VULNERABLE' : 'PROTEGIDO'}
    </span>
  </div>
  <div style="font-family:monospace;font-size:10px;color:#64748b;margin-bottom:12px">Metodo: ${r.userEnumeration.method}</div>
  ${usersBlock}
</div>

<!-- RECOMMENDATIONS -->
<div style="background:#0a0a18;border:1px solid #1a1a2e;border-radius:12px;padding:20px;margin-bottom:24px">
  <div style="font-size:13px;font-weight:700;color:#e2e8f0;margin-bottom:14px;display:flex;align-items:center;gap:8px">
    <span style="color:#eab308">■</span> Recomendaciones de seguridad
  </div>
  ${recsBlock}
</div>

</div>

<!-- FOOTER -->
<div style="border-top:1px solid #1a1a2e;padding:16px 40px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
  <div style="font-family:monospace;font-size:9px;color:rgba(255,255,255,0.15);letter-spacing:1px">
    WPSENTRY v2.0 · AUDITORIA PASIVA · USO ETICO Y EDUCATIVO
  </div>
  <div style="display:flex;gap:16px">
    <a href="https://github.com/ccyl13" target="_blank" style="font-family:monospace;font-size:9px;color:rgba(255,255,255,0.2);text-decoration:none">github/ccyl13</a>
    <a href="https://www.linkedin.com/in/thomasoneil%C3%A1lvarez/" target="_blank" style="font-family:monospace;font-size:9px;color:rgba(255,255,255,0.2);text-decoration:none">Thomas Oneil Alvarez</a>
  </div>
</div>
</body>
</html>`;
}

export function ExportButton({ result }: { result: AuditResult }) {
  const handleExport = () => {
    const html = buildHTML(result);
    const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const host = (() => { try { return new URL(result.url).hostname.replace(/[^a-z0-9]/gi,'-'); } catch { return 'report'; } })();
    a.href = url;
    a.download = 'wpsentry-' + host + '-' + new Date().toISOString().split('T')[0] + '.html';
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
      <Download size={13}/>
      Exportar HTML
    </button>
  );
}
