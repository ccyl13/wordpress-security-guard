import type { AuditResult, SecurityHeader, EndpointCheck, UserEnumeration, WordPressInfo } from '@/types/wordpress-audit';
import { fetchWithProxy, checkEndpointsBatch } from './cors-proxy';

const SECURITY_HEADERS_TO_CHECK = [
  { name: 'Content-Security-Policy', critical: true },
  { name: 'X-Frame-Options', critical: true },
  { name: 'X-Content-Type-Options', critical: true },
  { name: 'Strict-Transport-Security', critical: true },
  { name: 'X-XSS-Protection', critical: false },
  { name: 'Referrer-Policy', critical: false },
  { name: 'Permissions-Policy', critical: false },
  { name: 'Cross-Origin-Embedder-Policy', critical: false },
  { name: 'Cross-Origin-Opener-Policy', critical: false },
];

const WP_ENDPOINTS = [
  { path: '/xmlrpc.php', name: 'XML-RPC', risk: 'critical' as const, description: 'Puede usarse para ataques de fuerza bruta y DDoS' },
  { path: '/wp-login.php', name: 'WP Login', risk: 'medium' as const, description: 'Página de login expuesta' },
  { path: '/wp-admin/', name: 'WP Admin', risk: 'medium' as const, description: 'Panel de administración accesible' },
  { path: '/wp-json/', name: 'REST API', risk: 'info' as const, description: 'API REST activa' },
  { path: '/wp-content/debug.log', name: 'Debug Log', risk: 'critical' as const, description: 'Archivo de debug con info sensible' },
  { path: '/wp-config.php.bak', name: 'Config Backup', risk: 'critical' as const, description: 'Backup con credenciales' },
  { path: '/.git/', name: 'Git Exposed', risk: 'critical' as const, description: 'Repositorio Git expuesto' },
  { path: '/readme.html', name: 'Readme', risk: 'low' as const, description: 'Revela versión de WordPress' },
  { path: '/wp-includes/', name: 'WP Includes', risk: 'info' as const, description: 'Directorio includes accesible' },
  { path: '/wp-content/uploads/', name: 'Uploads', risk: 'low' as const, description: 'Directorio uploads listable' },
];

function normalizeUrl(url: string): string {
  let normalized = url.trim();
  if (!normalized.startsWith('http://') && !normalized.startsWith('https://')) {
    normalized = 'https://' + normalized;
  }
  return normalized.replace(/\/+$/, '');
}

function getHeaderStatus(name: string, value: string | null): 'secure' | 'warning' | 'vulnerable' {
  if (!value) return 'vulnerable';
  
  const lowerValue = value.toLowerCase();
  
  switch (name.toLowerCase()) {
    case 'content-security-policy':
      if (lowerValue.includes('unsafe-inline') || lowerValue.includes('unsafe-eval')) {
        return 'warning';
      }
      return 'secure';
    case 'x-frame-options':
      return (lowerValue === 'deny' || lowerValue === 'sameorigin') ? 'secure' : 'warning';
    case 'strict-transport-security':
      const maxAge = parseInt(lowerValue.match(/max-age=(\d+)/)?.[1] || '0');
      if (maxAge >= 31536000) return 'secure';
      if (maxAge > 0) return 'warning';
      return 'vulnerable';
    case 'x-content-type-options':
      return lowerValue === 'nosniff' ? 'secure' : 'warning';
    default:
      return 'secure';
  }
}

function getHeaderDescription(name: string, value: string | null): string {
  if (!value) {
    return `${name} no configurada - expone el sitio a ataques`;
  }
  
  const descriptions: Record<string, string> = {
    'content-security-policy': 'Define recursos permitidos en la página',
    'x-frame-options': 'Protege contra clickjacking',
    'strict-transport-security': 'Fuerza conexiones HTTPS',
    'x-content-type-options': 'Previene MIME-sniffing',
    'x-xss-protection': 'Filtro XSS del navegador',
    'referrer-policy': 'Controla información de referrer',
    'permissions-policy': 'Controla APIs del navegador',
  };
  
  return descriptions[name.toLowerCase()] || `Configurado: ${value.substring(0, 50)}...`;
}

async function checkSecurityHeaders(baseUrl: string): Promise<SecurityHeader[]> {
  const headers: SecurityHeader[] = [];
  
  try {
    const response = await fetchWithProxy(baseUrl);
    
    for (const header of SECURITY_HEADERS_TO_CHECK) {
      const value = response.headers.get(header.name);
      headers.push({
        name: header.name,
        value,
        status: getHeaderStatus(header.name, value),
        description: getHeaderDescription(header.name, value),
      });
    }
    
    // Check for information disclosure headers
    const serverHeader = response.headers.get('Server');
    if (serverHeader) {
      headers.push({
        name: 'Server',
        value: serverHeader,
        status: 'warning',
        description: 'Revela información del servidor',
      });
    }
    
    const poweredBy = response.headers.get('X-Powered-By');
    if (poweredBy) {
      headers.push({
        name: 'X-Powered-By',
        value: poweredBy,
        status: 'warning',
        description: 'Revela tecnología del backend',
      });
    }
  } catch {
    // Headers check failed silently
  }
  
  return headers;
}

async function checkEndpoints(baseUrl: string): Promise<EndpointCheck[]> {
  const urls = WP_ENDPOINTS.map(ep => baseUrl + ep.path);
  const results = await checkEndpointsBatch(urls, 6);
  
  return WP_ENDPOINTS.map((endpoint) => {
    const fullUrl = baseUrl + endpoint.path;
    const result = results.get(fullUrl) || { exists: false, statusCode: 0 };
    
    return {
      name: endpoint.name,
      url: fullUrl,
      status: result.exists ? 'accessible' : 'blocked',
      statusCode: result.statusCode,
      description: endpoint.description,
      risk: endpoint.risk,
    };
  });
}

// Detect WordPress subdirectories from HTML
function detectWpPaths(html: string): string[] {
  const paths = new Set<string>(['']); // Always include root
  
  // Look for wp-content paths that might reveal subdirectories
  const wpContentMatches = html.matchAll(/["'](\/[^"']*?)?\/wp-content\//g);
  for (const match of wpContentMatches) {
    if (match[1]) {
      paths.add(match[1]);
    }
  }
  
  // Look for wp-json paths
  const wpJsonMatches = html.matchAll(/["'](\/[^"']*?)\/wp-json/g);
  for (const match of wpJsonMatches) {
    if (match[1]) {
      paths.add(match[1]);
    }
  }
  
  // Common WordPress subdirectory names
  const commonPaths = ['/blog', '/wordpress', '/wp', '/site', '/web'];
  commonPaths.forEach(p => paths.add(p));
  
  return Array.from(paths);
}

async function checkUserEnumeration(baseUrl: string, wpPaths: string[] = ['']): Promise<UserEnumeration> {
  const result: UserEnumeration = { found: false, users: [], method: '' };
  
  // Try each path
  for (const wpPath of wpPaths) {
    const pathBase = baseUrl + wpPath;
    
    // Method 1: REST API (most common)
    try {
      const apiUrl = pathBase + '/wp-json/wp/v2/users';
      const response = await fetchWithProxy(apiUrl);
      if (response.ok) {
        const text = await response.text();
        try {
          const users = JSON.parse(text);
          if (Array.isArray(users) && users.length > 0) {
            result.found = true;
            result.method = `REST API (${wpPath || '/'}/wp-json/wp/v2/users)`;
            result.users = users.slice(0, 10).map((u: any) => ({
              id: u.id,
              name: u.name || u.slug,
              slug: u.slug,
            }));
            return result;
          }
        } catch { /* not JSON */ }
      }
    } catch { /* continue */ }
    
    // Method 2: rest_route parameter (works when wp-json is blocked)
    try {
      const routeUrl = pathBase + '/?rest_route=/wp/v2/users';
      const response = await fetchWithProxy(routeUrl);
      const text = await response.text();
      
      // Check if response looks like JSON
      if (text.trim().startsWith('[') || text.trim().startsWith('{')) {
        try {
          const users = JSON.parse(text);
          if (Array.isArray(users) && users.length > 0) {
            result.found = true;
            result.method = `REST Route (${wpPath}/?rest_route=/wp/v2/users)`;
            result.users = users.slice(0, 10).map((u: any) => ({
              id: u.id,
              name: u.name || u.slug,
              slug: u.slug,
            }));
            return result;
          }
        } catch { /* not valid JSON */ }
      }
    } catch { /* continue */ }
  }
  
  // Method 3: Author enumeration on root (fallback)
  try {
    const authorChecks = await Promise.all(
      [1, 2, 3].map(async (i) => {
        try {
          const response = await fetchWithProxy(baseUrl + `/?author=${i}`);
          const html = await response.text();
          const authorMatch = html.match(/author\/([^\/\"]+)/);
          if (authorMatch) {
            return { id: i, name: authorMatch[1], slug: authorMatch[1] };
          }
        } catch { /* ignore */ }
        return null;
      })
    );
    
    const foundUsers = authorChecks.filter(Boolean);
    if (foundUsers.length > 0) {
      result.found = true;
      result.method = 'Author Parameter (?author=N)';
      result.users = foundUsers as any[];
    }
  } catch { /* ignore */ }
  
  return result;
}

async function getWordPressInfo(baseUrl: string, html: string): Promise<WordPressInfo> {
  const info: WordPressInfo = {
    version: null,
    theme: null,
    generator: false,
    readme: false,
  };
  
  // Check for generator meta tag
  const generatorMatch = html.match(/<meta[^>]*name=["']generator["'][^>]*content=["']WordPress\s*([\d.]+)?["']/i);
  if (generatorMatch) {
    info.generator = true;
    info.version = generatorMatch[1] || 'Unknown';
  }
  
  // Check for version in scripts/styles
  if (!info.version) {
    const versionMatch = html.match(/ver=([\d.]+)/);
    if (versionMatch) info.version = versionMatch[1];
  }
  
  // Check for theme
  const themeMatch = html.match(/wp-content\/themes\/([^\/\"]+)/);
  if (themeMatch) info.theme = themeMatch[1];
  
  return info;
}

function calculateOverallScore(result: Partial<AuditResult>): number {
  let score = 100;
  let issuesFound = 0;
  
  const criticalHeaders = ['Content-Security-Policy', 'X-Frame-Options', 'Strict-Transport-Security', 'X-Content-Type-Options'];
  
  // Security headers analysis
  for (const header of result.securityHeaders || []) {
    if (header.status === 'vulnerable') {
      const deduction = criticalHeaders.includes(header.name) ? 8 : 4;
      score -= deduction;
      issuesFound++;
    } else if (header.status === 'warning') {
      score -= 2;
      issuesFound++;
    }
  }
  
  // Endpoint accessibility analysis
  for (const endpoint of result.endpoints || []) {
    if (endpoint.status === 'accessible') {
      const deductions = { critical: 12, high: 8, medium: 4, low: 2, info: 0 };
      score -= deductions[endpoint.risk] || 0;
      if (endpoint.risk !== 'info') issuesFound++;
    }
  }
  
  // User enumeration (major issue)
  if (result.userEnumeration?.found) {
    score -= 12;
    issuesFound++;
  }
  
  // Version disclosure
  if (result.wordpressInfo?.generator) {
    score -= 4;
    issuesFound++;
  }
  
  // Ensure minimum score of 10 if there are issues but site loaded
  const hasValidData = (result.securityHeaders?.length || 0) > 0 || (result.endpoints?.length || 0) > 0;
  if (hasValidData && score < 10) {
    score = 10;
  }
  
  // If no issues found, it's a good score
  if (issuesFound === 0 && hasValidData) {
    score = 95;
  }
  
  return Math.max(0, Math.min(100, Math.round(score)));
}

export interface AuditProgress {
  step: string;
  current: number;
  total: number;
  percentage: number;
}

export async function auditWordPress(
  url: string, 
  onProgress?: (progress: AuditProgress) => void
): Promise<AuditResult> {
  const baseUrl = normalizeUrl(url);
  const totalSteps = 4;
  
  const updateProgress = (step: string, current: number) => {
    onProgress?.({
      step,
      current,
      total: totalSteps,
      percentage: Math.round((current / totalSteps) * 100),
    });
  };
  
  updateProgress('Verificando conexión...', 0);
  
  let isWordPress = false;
  let homeHtml = '';
  
  try {
    const response = await fetchWithProxy(baseUrl);
    homeHtml = await response.text();
    
    // WordPress detection - check multiple indicators with different weights
    const wpIndicators = [
      // Strong indicators (definitely WordPress)
      { pattern: 'wp-content', strong: true },
      { pattern: 'wp-includes', strong: true },
      { pattern: 'wp-json', strong: true },
      { pattern: 'generator" content="WordPress', strong: true },
      { pattern: 'name="generator" content="WordPress', strong: true },
      { pattern: '/wp-admin/', strong: true },
      { pattern: 'woocommerce', strong: true },
      { pattern: 'xmlrpc.php', strong: true },
      { pattern: 'wp-login.php', strong: true },
      { pattern: 'wp-block', strong: true },
      // Weak indicators 
      { pattern: 'wordpress', strong: false },
      { pattern: 'WordPress', strong: false },
      { pattern: 'wp-emoji', strong: false },
      { pattern: '/themes/', strong: false },
      { pattern: '/plugins/', strong: false },
      { pattern: 'has-sidebar', strong: false },
    ];
    
    const strongMatches = wpIndicators.filter(i => i.strong && homeHtml.includes(i.pattern));
    const weakMatches = wpIndicators.filter(i => !i.strong && homeHtml.includes(i.pattern));
    
    // WordPress if: 1 strong match OR 2+ weak matches
    isWordPress = strongMatches.length >= 1 || weakMatches.length >= 2;
    
  } catch {
    throw new Error('No se pudo conectar con el sitio web. Los proxies CORS pueden estar bloqueados.');
  }
  
  // Detect WordPress paths from HTML
  const wpPaths = detectWpPaths(homeHtml);
  
  // Run checks in parallel where possible
  updateProgress('Analizando seguridad...', 1);
  
  const [securityHeaders, endpoints, userEnumeration, wordpressInfo] = await Promise.all([
    checkSecurityHeaders(baseUrl).then(r => { updateProgress('Verificando endpoints...', 2); return r; }),
    checkEndpoints(baseUrl),
    checkUserEnumeration(baseUrl, wpPaths).then(r => { updateProgress('Finalizando análisis...', 3); return r; }),
    getWordPressInfo(baseUrl, homeHtml),
  ]);
  
  updateProgress('Completado', 4);
  
  const result: AuditResult = {
    url: baseUrl,
    timestamp: new Date(),
    isWordPress,
    securityHeaders,
    endpoints,
    userEnumeration,
    wordpressInfo,
    overallScore: 0,
  };
  
  result.overallScore = calculateOverallScore(result);
  
  return result;
}
