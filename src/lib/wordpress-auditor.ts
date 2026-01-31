import type { AuditResult, SecurityHeader, EndpointCheck, UserEnumeration, WordPressInfo } from '@/types/wordpress-audit';
import { fetchWithProxy, checkEndpointExists } from './cors-proxy';

const SECURITY_HEADERS_TO_CHECK = [
  { name: 'Content-Security-Policy', critical: true },
  { name: 'X-Frame-Options', critical: true },
  { name: 'X-Content-Type-Options', critical: true },
  { name: 'Strict-Transport-Security', critical: true },
  { name: 'X-XSS-Protection', critical: false },
  { name: 'Referrer-Policy', critical: false },
  { name: 'Permissions-Policy', critical: false },
  { name: 'X-Permitted-Cross-Domain-Policies', critical: false },
  { name: 'Cross-Origin-Embedder-Policy', critical: false },
  { name: 'Cross-Origin-Opener-Policy', critical: false },
  { name: 'Cross-Origin-Resource-Policy', critical: false },
];

const WP_ENDPOINTS = [
  { path: '/xmlrpc.php', name: 'XML-RPC', risk: 'critical' as const, description: 'XML-RPC puede usarse para ataques de fuerza bruta y DDoS amplificado' },
  { path: '/wp-login.php', name: 'WP Login', risk: 'medium' as const, description: 'Página de login expuesta públicamente' },
  { path: '/wp-admin/', name: 'WP Admin', risk: 'medium' as const, description: 'Panel de administración accesible' },
  { path: '/wp-json/', name: 'REST API', risk: 'info' as const, description: 'API REST de WordPress activa' },
  { path: '/wp-content/debug.log', name: 'Debug Log', risk: 'critical' as const, description: 'Archivo de debug expuesto con información sensible' },
  { path: '/wp-config.php.bak', name: 'Config Backup', risk: 'critical' as const, description: 'Backup de configuración con credenciales' },
  { path: '/wp-config.php~', name: 'Config Temp', risk: 'critical' as const, description: 'Archivo temporal de configuración' },
  { path: '/.git/', name: 'Git Exposed', risk: 'critical' as const, description: 'Repositorio Git expuesto' },
  { path: '/readme.html', name: 'Readme', risk: 'low' as const, description: 'Archivo readme revela versión de WordPress' },
  { path: '/license.txt', name: 'License', risk: 'low' as const, description: 'Archivo de licencia de WordPress' },
  { path: '/wp-includes/', name: 'WP Includes', risk: 'info' as const, description: 'Directorio de includes accesible' },
  { path: '/wp-content/uploads/', name: 'Uploads Dir', risk: 'low' as const, description: 'Directorio de uploads listable' },
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
      if (lowerValue === 'deny' || lowerValue === 'sameorigin') {
        return 'secure';
      }
      return 'warning';
    case 'strict-transport-security':
      const maxAge = parseInt(lowerValue.match(/max-age=(\d+)/)?.[1] || '0');
      if (maxAge >= 31536000) return 'secure';
      if (maxAge > 0) return 'warning';
      return 'vulnerable';
    case 'x-content-type-options':
      return lowerValue === 'nosniff' ? 'secure' : 'warning';
    default:
      return value ? 'secure' : 'vulnerable';
  }
}

function getHeaderDescription(name: string, value: string | null): string {
  if (!value) {
    return `Cabecera ${name} no configurada. Esto puede exponer el sitio a ataques.`;
  }
  
  switch (name.toLowerCase()) {
    case 'content-security-policy':
      return 'Define qué recursos pueden cargarse en la página.';
    case 'x-frame-options':
      return 'Protege contra ataques de clickjacking.';
    case 'strict-transport-security':
      return 'Fuerza conexiones HTTPS.';
    case 'x-content-type-options':
      return 'Previene MIME-sniffing.';
    case 'x-xss-protection':
      return 'Filtro XSS del navegador (legacy).';
    case 'referrer-policy':
      return 'Controla información de referrer enviada.';
    case 'permissions-policy':
      return 'Controla qué APIs del navegador pueden usarse.';
    default:
      return `Cabecera de seguridad: ${value}`;
  }
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
    
    // Check for server header (information disclosure)
    const serverHeader = response.headers.get('Server');
    if (serverHeader) {
      headers.push({
        name: 'Server',
        value: serverHeader,
        status: serverHeader.toLowerCase().includes('apache') || serverHeader.toLowerCase().includes('nginx') ? 'warning' : 'info',
        description: 'Revela información del servidor web.',
      });
    }
    
    // Check for X-Powered-By
    const poweredBy = response.headers.get('X-Powered-By');
    if (poweredBy) {
      headers.push({
        name: 'X-Powered-By',
        value: poweredBy,
        status: 'warning',
        description: 'Revela tecnología del backend (debería eliminarse).',
      });
    }
  } catch (error) {
    console.error('Error checking headers:', error);
  }
  
  return headers;
}

async function checkEndpoints(baseUrl: string): Promise<EndpointCheck[]> {
  const results: EndpointCheck[] = [];
  
  const checks = await Promise.all(
    WP_ENDPOINTS.map(async (endpoint) => {
      const fullUrl = baseUrl + endpoint.path;
      const result = await checkEndpointExists(fullUrl);
      
      return {
        name: endpoint.name,
        url: fullUrl,
        status: result.exists ? 'accessible' : 'blocked',
        statusCode: result.statusCode,
        description: endpoint.description,
        risk: endpoint.risk,
      } as EndpointCheck;
    })
  );
  
  return checks;
}

async function checkUserEnumeration(baseUrl: string): Promise<UserEnumeration> {
  const result: UserEnumeration = {
    found: false,
    users: [],
    method: '',
  };
  
  // Method 1: REST API
  try {
    const restApiUrl = baseUrl + '/wp-json/wp/v2/users';
    const response = await fetchWithProxy(restApiUrl);
    if (response.ok) {
      const users = await response.json();
      if (Array.isArray(users) && users.length > 0) {
        result.found = true;
        result.method = 'REST API (/wp-json/wp/v2/users)';
        result.users = users.map((u: any) => ({
          id: u.id,
          name: u.name,
          slug: u.slug,
        }));
        return result;
      }
    }
  } catch {
    // Continue to next method
  }
  
  // Method 2: rest_route parameter
  try {
    const restRouteUrl = baseUrl + '/?rest_route=/wp/v2/users';
    const response = await fetchWithProxy(restRouteUrl);
    if (response.ok) {
      const users = await response.json();
      if (Array.isArray(users) && users.length > 0) {
        result.found = true;
        result.method = 'REST Route (/?rest_route=/wp/v2/users)';
        result.users = users.map((u: any) => ({
          id: u.id,
          name: u.name,
          slug: u.slug,
        }));
        return result;
      }
    }
  } catch {
    // Continue to next method
  }
  
  // Method 3: Author enumeration via ?author=N
  try {
    for (let i = 1; i <= 5; i++) {
      const authorUrl = baseUrl + `/?author=${i}`;
      const response = await fetchWithProxy(authorUrl);
      const html = await response.text();
      
      // Check for author redirect or author page
      const authorMatch = html.match(/author\/([^\/\"]+)/);
      if (authorMatch) {
        result.found = true;
        result.method = 'Author Parameter (?author=N)';
        result.users.push({
          id: i,
          name: authorMatch[1],
          slug: authorMatch[1],
        });
      }
    }
  } catch {
    // Enumeration failed
  }
  
  return result;
}

async function getWordPressInfo(baseUrl: string): Promise<WordPressInfo> {
  const info: WordPressInfo = {
    version: null,
    theme: null,
    generator: false,
    readme: false,
  };
  
  try {
    const response = await fetchWithProxy(baseUrl);
    const html = await response.text();
    
    // Check for generator meta tag
    const generatorMatch = html.match(/<meta[^>]*name=["']generator["'][^>]*content=["']WordPress\s*([\d.]+)?["']/i);
    if (generatorMatch) {
      info.generator = true;
      info.version = generatorMatch[1] || 'Unknown';
    }
    
    // Check for version in scripts/styles
    const versionMatch = html.match(/ver=([\d.]+)/);
    if (versionMatch && !info.version) {
      info.version = versionMatch[1];
    }
    
    // Check for theme
    const themeMatch = html.match(/wp-content\/themes\/([^\/\"]+)/);
    if (themeMatch) {
      info.theme = themeMatch[1];
    }
  } catch {
    // Failed to get info
  }
  
  // Check readme
  const readmeCheck = await checkEndpointExists(baseUrl + '/readme.html');
  info.readme = readmeCheck.exists;
  
  return info;
}

function calculateOverallScore(result: Partial<AuditResult>): number {
  let score = 100;
  
  // Deduct for missing security headers
  const criticalHeaders = ['Content-Security-Policy', 'X-Frame-Options', 'Strict-Transport-Security', 'X-Content-Type-Options'];
  for (const header of result.securityHeaders || []) {
    if (header.status === 'vulnerable') {
      score -= criticalHeaders.includes(header.name) ? 10 : 5;
    } else if (header.status === 'warning') {
      score -= 3;
    }
  }
  
  // Deduct for exposed endpoints
  for (const endpoint of result.endpoints || []) {
    if (endpoint.status === 'accessible') {
      switch (endpoint.risk) {
        case 'critical': score -= 15; break;
        case 'high': score -= 10; break;
        case 'medium': score -= 5; break;
        case 'low': score -= 2; break;
      }
    }
  }
  
  // Deduct for user enumeration
  if (result.userEnumeration?.found) {
    score -= 15;
  }
  
  // Deduct for exposed version/generator
  if (result.wordpressInfo?.generator) {
    score -= 5;
  }
  
  return Math.max(0, Math.min(100, score));
}

export async function auditWordPress(url: string, onProgress?: (message: string) => void): Promise<AuditResult> {
  const baseUrl = normalizeUrl(url);
  
  onProgress?.('Verificando conexión...');
  
  // Check if it's WordPress
  let isWordPress = false;
  try {
    const response = await fetchWithProxy(baseUrl);
    const html = await response.text();
    isWordPress = html.includes('wp-content') || html.includes('wp-includes') || html.includes('WordPress');
  } catch (error) {
    throw new Error('No se pudo conectar con el sitio web');
  }
  
  onProgress?.('Analizando cabeceras de seguridad...');
  const securityHeaders = await checkSecurityHeaders(baseUrl);
  
  onProgress?.('Comprobando endpoints sensibles...');
  const endpoints = await checkEndpoints(baseUrl);
  
  onProgress?.('Verificando enumeración de usuarios...');
  const userEnumeration = await checkUserEnumeration(baseUrl);
  
  onProgress?.('Recopilando información de WordPress...');
  const wordpressInfo = await getWordPressInfo(baseUrl);
  
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
