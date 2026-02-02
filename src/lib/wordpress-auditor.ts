import type { AuditResult, SecurityHeader, EndpointCheck, UserEnumeration, WordPressInfo, CvssScore } from '@/types/wordpress-audit';
import { getCvssSeverity } from '@/types/wordpress-audit';
import { fetchWithProxy, checkEndpointsBatch } from './cors-proxy';
import { 
  HEADER_REFERENCES, 
  WP_ENDPOINTS, 
  USER_ENUMERATION_REFERENCE,
  detectWaf,
  calculateOverallCvss
} from './security-references';

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

async function checkSecurityHeaders(baseUrl: string): Promise<{ headers: SecurityHeader[]; wafDetected: string | null }> {
  const headers: SecurityHeader[] = [];
  let wafDetected: string | null = null;
  
  try {
    const response = await fetchWithProxy(baseUrl);
    
    // Detect WAF
    wafDetected = detectWaf(response.headers);
    
    for (const header of SECURITY_HEADERS_TO_CHECK) {
      const value = response.headers.get(header.name);
      const status = getHeaderStatus(header.name, value);
      headers.push({
        name: header.name,
        value,
        status,
        description: getHeaderDescription(header.name, value),
        reference: status === 'vulnerable' ? HEADER_REFERENCES[header.name] : undefined,
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
        reference: HEADER_REFERENCES['Server'],
      });
    }
    
    const poweredBy = response.headers.get('X-Powered-By');
    if (poweredBy) {
      headers.push({
        name: 'X-Powered-By',
        value: poweredBy,
        status: 'warning',
        description: 'Revela tecnología del backend',
        reference: HEADER_REFERENCES['X-Powered-By'],
      });
    }
  } catch {
    // Headers check failed silently
  }
  
  return { headers, wafDetected };
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
      reference: result.exists ? endpoint.reference : undefined,
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
  
  // Look for links to blog or WordPress paths
  const linkMatches = html.matchAll(/href=["'](\/[^"']+?)\/(?:wp-admin|wp-login|feed)/gi);
  for (const match of linkMatches) {
    if (match[1]) {
      paths.add(match[1]);
    }
  }
  
  // Common WordPress subdirectory names - check these FIRST before root
  const commonPaths = ['/blog', '/wordpress', '/wp', '/site', '/web', '/news', '/articles'];
  commonPaths.forEach(p => paths.add(p));
  
  // Return with common paths first (more likely to be WordPress subdirectories)
  const result = Array.from(paths);
  return result.sort((a, b) => {
    if (a === '') return 1; // Root last
    if (b === '') return -1;
    if (commonPaths.includes(a)) return -1; // Common paths first
    if (commonPaths.includes(b)) return 1;
    return 0;
  });
}

async function checkUserEnumeration(baseUrl: string, wpPaths: string[] = ['']): Promise<UserEnumeration> {
  const result: UserEnumeration = { 
    found: false, 
    users: [], 
    method: '',
    reference: USER_ENUMERATION_REFERENCE,
  };
  
  // Ensure common WordPress paths are checked first
  const pathsToCheck = new Set(wpPaths);
  ['/blog', '/wordpress', '/wp', ''].forEach(p => pathsToCheck.add(p));
  const orderedPaths = Array.from(pathsToCheck).sort((a, b) => {
    if (a === '') return 1; // Root last
    if (b === '') return -1;
    return 0;
  });
  
  // Try each path
  for (const wpPath of orderedPaths) {
    const pathBase = baseUrl + wpPath;
    
    // Method 1: rest_route parameter FIRST (works more reliably, especially for subdirectories)
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
            result.method = `REST Route (${wpPath || '/'}?rest_route=/wp/v2/users)`;
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
    
    // Method 2: REST API endpoint
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
  }
  
  // Method 3: Author enumeration (fallback) - try on all paths
  for (const wpPath of orderedPaths) {
    const pathBase = baseUrl + wpPath;
    try {
      const authorChecks = await Promise.all(
        [1, 2, 3].map(async (i) => {
          try {
            const response = await fetchWithProxy(pathBase + `/?author=${i}`);
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
        result.method = `Author Parameter (${wpPath || '/'}?author=N)`;
        result.users = foundUsers as any[];
        return result;
      }
    } catch { /* ignore */ }
  }
  
  return result;
}

async function getWordPressInfo(baseUrl: string, html: string): Promise<WordPressInfo> {
  const info: WordPressInfo = {
    version: null,
    theme: null,
    generator: false,
    readme: false,
    wafDetected: null,
    sslInfo: null,
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
  
  // Check SSL (basic - just verify HTTPS works)
  if (baseUrl.startsWith('https://')) {
    info.sslInfo = { valid: true };
  }
  
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
  let detectedWpPath = '';
  
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
    
    // If not detected on homepage, check common subdirectories
    if (!isWordPress) {
      const commonWpPaths = ['/blog', '/wordpress', '/wp', '/news'];
      for (const path of commonWpPaths) {
        try {
          const subResponse = await fetchWithProxy(baseUrl + path);
          const subHtml = await subResponse.text();
          const subStrongMatches = wpIndicators.filter(i => i.strong && subHtml.includes(i.pattern));
          const subWeakMatches = wpIndicators.filter(i => !i.strong && subHtml.includes(i.pattern));
          
          if (subStrongMatches.length >= 1 || subWeakMatches.length >= 2) {
            isWordPress = true;
            detectedWpPath = path;
            homeHtml = subHtml; // Use this for path detection
            break;
          }
        } catch { /* continue checking */ }
      }
    }
    
  } catch {
    throw new Error('No se pudo conectar con el sitio web. Los proxies CORS pueden estar bloqueados.');
  }
  
  // Detect WordPress paths from HTML
  const wpPaths = detectWpPaths(homeHtml);
  
  // Run checks in parallel where possible
  updateProgress('Analizando seguridad...', 1);
  
  const [headersResult, endpoints, userEnumeration, wordpressInfo] = await Promise.all([
    checkSecurityHeaders(baseUrl).then(r => { updateProgress('Verificando endpoints...', 2); return r; }),
    checkEndpoints(baseUrl),
    checkUserEnumeration(baseUrl, wpPaths).then(r => { updateProgress('Finalizando análisis...', 3); return r; }),
    getWordPressInfo(baseUrl, homeHtml),
  ]);
  
  // Add WAF detection to wordpressInfo
  wordpressInfo.wafDetected = headersResult.wafDetected;
  
  updateProgress('Completado', 4);
  
  // Calculate CVSS overall
  const cvssOverall = calculateOverallCvss(
    headersResult.headers,
    endpoints,
    userEnumeration.found,
    wordpressInfo.generator
  );
  
  const result: AuditResult = {
    url: baseUrl,
    timestamp: new Date(),
    isWordPress,
    securityHeaders: headersResult.headers,
    endpoints,
    userEnumeration,
    wordpressInfo,
    overallScore: 0,
    cvssOverall,
  };
  
  result.overallScore = calculateOverallScore(result);
  
  return result;
}
