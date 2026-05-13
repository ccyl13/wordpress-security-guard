import { fetchWithProxy } from './cors-proxy';
import type { AuditResult, SecurityHeader, EndpointCheck, UserEnumeration, WordPressInfo, CvssScore } from '@/types/wordpress-audit';
import { HEADER_REFERENCES } from './security-references';

export interface AuditProgress {
  step: string; current: number; total: number; percentage: number;
}
type ProgressCallback = (p: AuditProgress) => void;

interface EndpointDef {
  path: string;
  name: string;
  risk: 'critical'|'high'|'medium'|'low'|'info';
  description: string;
  bodyMustContain?: string;
  bodyMustNotContain?: string;
}

const SENSITIVE_ENDPOINTS: EndpointDef[] = [
  { path: '/xmlrpc.php',                 name: 'XML-RPC',       risk: 'critical', description: 'Permite ataques de fuerza bruta y DDoS amplificado',        bodyMustContain: 'XML-RPC' },
  { path: '/wp-login.php',               name: 'WP Login',      risk: 'high',     description: 'Login expuesto a ataques de fuerza bruta',                  bodyMustContain: 'wp-login' },
  { path: '/wp-admin/',                  name: 'WP Admin',      risk: 'high',     description: 'Panel de administracion accesible publicamente',            bodyMustContain: 'wp-admin' },
  { path: '/?rest_route=/wp/v2/users',   name: 'REST Users',    risk: 'high',     description: 'API REST expone lista de usuarios registrados',             bodyMustContain: '"slug"' },
  { path: '/wp-json/',                   name: 'REST API',      risk: 'medium',   description: 'API REST habilitada y accesible',                           bodyMustContain: 'namespaces' },
  { path: '/readme.html',                name: 'Readme',        risk: 'medium',   description: 'Revela la version exacta de WordPress',                     bodyMustContain: 'WordPress' },
  { path: '/license.txt',               name: 'License',        risk: 'low',      description: 'Revela informacion de la instalacion de WordPress',         bodyMustContain: 'WordPress' },
  { path: '/wp-content/debug.log',       name: 'Debug Log',     risk: 'critical', description: 'Log de errores con rutas internas expuesto',                bodyMustNotContain: '<!DOCTYPE' },
  { path: '/wp-config.php.bak',          name: 'Config Backup', risk: 'critical', description: 'Backup de configuracion con credenciales de BD',            bodyMustNotContain: '<!DOCTYPE' },
  { path: '/.env',                       name: 'ENV File',      risk: 'critical', description: 'Variables de entorno con credenciales',                     bodyMustNotContain: '<!DOCTYPE' },
  { path: '/.git/HEAD',                  name: 'Git Repo',      risk: 'critical', description: 'Repositorio Git expuesto — codigo fuente filtrable',        bodyMustContain: 'ref:' },
  { path: '/wp-content/uploads/',        name: 'Uploads Dir',   risk: 'medium',   description: 'Directorio de uploads con listado habilitado',              bodyMustContain: 'Index of' },
  { path: '/sitemap.xml',               name: 'Sitemap',        risk: 'info',     description: 'Sitemap publico — puede revelar estructura interna',        bodyMustContain: '<urlset' },
  { path: '/robots.txt',                name: 'Robots.txt',     risk: 'info',     description: 'Puede revelar rutas ocultas o sensibles',                   bodyMustContain: 'User-agent' },
];

const HEADERS_LIST = [
  'content-security-policy','strict-transport-security','x-frame-options',
  'x-content-type-options','referrer-policy','permissions-policy',
  'cross-origin-opener-policy','cross-origin-resource-policy','x-xss-protection',
];

function normalizeUrl(url: string): string {
  try { const u = new URL(url.startsWith('http') ? url : 'https://' + url); return u.origin; }
  catch { return url; }
}

function detectWAF(h: Record<string,string>, body: string): string | null {
  if (h['x-sucuri-id'] || body.includes('Sucuri')) return 'Sucuri';
  if (h['cf-ray'] || body.includes('Cloudflare')) return 'Cloudflare';
  if (h['x-wordfence-blocked']) return 'Wordfence';
  if (body.includes('ModSecurity')) return 'ModSecurity';
  return null;
}

function extractWPVersion(body: string): string | null {
  const patterns = [/content="WordPress ([\d.]+)"/i, /\?ver=([\d.]+)/, /generator.*?WordPress ([\d.]+)/i];
  for (const p of patterns) { const m = body.match(p); if (m?.[1]?.match(/^\d+\.\d/)) return m[1]; }
  return null;
}

function extractTheme(body: string): string | null {
  const m = body.match(/wp-content\/themes\/([^/"']+)/); return m?.[1] || null;
}

function tryParseUsers(text: string): Array<{id:number;name:string;slug:string}> {
  try {
    // Find start of JSON array, ignore any leading content (proxies sometimes prepend stuff)
    const start = text.indexOf('[');
    if (start === -1) return [];
    const parsed = JSON.parse(text.slice(start));
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter((u: any) => u && (u.id || u.slug))
      .map((u: any) => ({ id: Number(u.id)||0, name: String(u.name||u.slug||''), slug: String(u.slug||'') }));
  } catch { return []; }
}

function analyzeHeaders(headers: Record<string,string>): SecurityHeader[] {
  return HEADERS_LIST.map(name => {
    const value = headers[name] || null;
    const ref = HEADER_REFERENCES[name];
    let status: 'secure'|'warning'|'vulnerable'|'info' = 'vulnerable';
    let description = '';
    if (name === 'content-security-policy') {
      if (!value) { status='vulnerable'; description='CSP ausente: riesgo de XSS'; }
      else if (value.includes("'unsafe-inline'") || value.includes("'unsafe-eval'")) { status='warning'; description='CSP debilitada por unsafe-inline/eval'; }
      else { status='secure'; description=value; }
    } else if (name === 'strict-transport-security') {
      if (!value) { status='vulnerable'; description='HSTS ausente: vulnerable a downgrade'; }
      else if (parseInt(value.match(/max-age=(\d+)/)?.[1]||'0') < 15768000) { status='warning'; description='HSTS con max-age demasiado corto'; }
      else { status='secure'; description=value; }
    } else if (name === 'x-frame-options') {
      if (!value) { status='vulnerable'; description='Ausente: vulnerable a clickjacking'; }
      else { status='secure'; description=value; }
    } else if (name === 'x-content-type-options') {
      if (!value) { status='vulnerable'; description='Ausente: MIME sniffing habilitado'; }
      else { status='secure'; description=value; }
    } else if (name === 'x-xss-protection') {
      status='info'; description=value||'No configurada (deprecada en navegadores modernos)';
    } else {
      if (!value) { status='warning'; description=name+' no configurada'; }
      else { status='secure'; description=value; }
    }
    return { name, value, status, description, reference: ref };
  });
}

function calcCVSS(sh: SecurityHeader[], ep: EndpointCheck[], ue: UserEnumeration): CvssScore {
  let score = 0;
  score += sh.filter(h=>h.status==='vulnerable').length * 0.4;
  score += sh.filter(h=>h.status==='warning').length * 0.2;
  score += ep.filter(e=>e.status==='accessible'&&e.risk==='critical').length * 1.8;
  score += ep.filter(e=>e.status==='accessible'&&e.risk==='high').length * 1.2;
  if (ue.found) score += 1.5;
  score = Math.min(10, score);
  const severity = score>=9?'Critical':score>=7?'High':score>=4?'Medium':score>0?'Low':'None';
  const crit = ep.filter(e=>e.status==='accessible'&&e.risk==='critical').length;
  const vector = 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:'+(score>7?'H':score>4?'L':'N')+'/I:'+(crit>0?'H':'L')+'/A:N';
  return { score: Math.round(score*10)/10, severity: severity as any, vector };
}

function calcScore(sh: SecurityHeader[], ep: EndpointCheck[], ue: UserEnumeration): number {
  let s=100;
  sh.forEach(h=>{ if(h.status==='vulnerable') s-=8; else if(h.status==='warning') s-=3; });
  ep.forEach(e=>{ if(e.status!=='accessible') return; if(e.risk==='critical') s-=15; else if(e.risk==='high') s-=10; else if(e.risk==='medium') s-=5; else s-=2; });
  if(ue.found) s-=10;
  return Math.max(0, Math.min(100, Math.round(s)));
}

async function checkEndpointSmart(baseUrl: string, ep: EndpointDef): Promise<EndpointCheck> {
  const url = baseUrl + ep.path;
  try {
    const result = await fetchWithProxy(url);
    if (!result.ok || result.status === 0) {
      return { url, name: ep.name, risk: ep.risk, description: ep.description, status: 'not_accessible', statusCode: result.status };
    }
    const body = result.text || '';
    if (ep.bodyMustContain && !body.includes(ep.bodyMustContain)) {
      return { url, name: ep.name, risk: ep.risk, description: ep.description, status: 'not_accessible', statusCode: result.status };
    }
    if (ep.bodyMustNotContain && body.includes(ep.bodyMustNotContain)) {
      return { url, name: ep.name, risk: ep.risk, description: ep.description, status: 'not_accessible', statusCode: result.status };
    }
    return { url, name: ep.name, risk: ep.risk, description: ep.description, status: 'accessible', statusCode: result.status };
  } catch {
    return { url, name: ep.name, risk: ep.risk, description: ep.description, status: 'not_accessible', statusCode: 0 };
  }
}

// Try multiple user enumeration vectors
async function detectUserEnumeration(baseUrl: string): Promise<UserEnumeration> {
  const method = 'REST API /?rest_route=/wp/v2/users';
  const ref = { owasp:'OWASP A07:2021', cvss:{ score:5.3, severity:'Medium' as const, vector:'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N' } };
  const notFound: UserEnumeration = { found:false, status:'protected', method, users:[], protectionDetails:'Enumeracion de usuarios no detectada', reference: ref };

  // Try both REST API variants in parallel
  const urls = [
    baseUrl + '/?rest_route=/wp/v2/users&per_page=10',
    baseUrl + '/wp-json/wp/v2/users?per_page=10',
  ];

  try {
    const results = await Promise.all(urls.map(u => fetchWithProxy(u).catch(() => null)));
    for (const r of results) {
      if (!r || !r.ok) continue;
      const text = r.text || '';
      // Must look like a JSON array with user objects
      if (!text.includes('"slug"') && !text.includes('"name"')) continue;
      const users = tryParseUsers(text);
      if (users.length > 0) {
        return { found:true, status:'vulnerable', method, users, reference: ref };
      }
    }
  } catch { /* ignore */ }

  return notFound;
}

export async function auditWordPress(rawUrl: string, onProgress: ProgressCallback): Promise<AuditResult> {
  const baseUrl = normalizeUrl(rawUrl);
  const report = (step:string,current:number,total=4) =>
    onProgress({ step, current, total, percentage: Math.round((current/total)*100) });

  report('Analizando cabeceras HTTP...', 0);
  const mainPage = await fetchWithProxy(baseUrl);
  const headers = mainPage.headers;
  const body = mainPage.text;

  const isWordPress = body.includes('wp-content') || body.includes('wp-includes') ||
    body.includes('WordPress') || !!headers['x-powered-by']?.includes('WordPress');

  const securityHeaders = analyzeHeaders(headers);
  report('Escaneando endpoints y usuarios en paralelo...', 1);

  const [endpointResults, userEnumResult] = await Promise.all([
    Promise.all(SENSITIVE_ENDPOINTS.map(ep => checkEndpointSmart(baseUrl, ep))),
    detectUserEnumeration(baseUrl),
  ]);

  report('Calculando puntuacion de seguridad...', 3);

  const cvssOverall = calcCVSS(securityHeaders, endpointResults, userEnumResult);
  const overallScore = calcScore(securityHeaders, endpointResults, userEnumResult);
  const readmeEp = endpointResults.find(e => e.url.includes('/readme.html'));

  const wordpressInfo: WordPressInfo = {
    version: extractWPVersion(body) || undefined,
    theme: extractTheme(body) || undefined,
    generator: body.includes('<meta name="generator"') && body.includes('WordPress'),
    readme: readmeEp?.status === 'accessible',
    wafDetected: detectWAF(headers, body) || undefined,
    sslInfo: { valid: baseUrl.startsWith('https://'), issuer: baseUrl.startsWith('https://') ? 'Valid SSL' : undefined },
  };

  report('Auditoria completada', 4);

  return {
    url: baseUrl,
    timestamp: new Date().toISOString(),
    isWordPress,
    wpDetection: isWordPress ? 'detected' : 'not_detected',
    wordpressInfo,
    securityHeaders,
    endpoints: endpointResults,
    userEnumeration: userEnumResult,
    overallScore,
    cvssOverall,
  };
}