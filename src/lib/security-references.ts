import type { SecurityReference, CvssScore, OwaspCategory, CweId } from '@/types/wordpress-audit';
import { getCvssSeverity } from '@/types/wordpress-audit';

// Helper to create CVSS scores
function cvss(score: number, vector: string): CvssScore {
  return { score, severity: getCvssSeverity(score), vector };
}

// Security headers reference mapping
export const HEADER_REFERENCES: Record<string, SecurityReference> = {
  'Content-Security-Policy': {
    owasp: 'A05:2021-Security Misconfiguration',
    cwe: 'CWE-693',
    cvss: cvss(4.3, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N'),
  },
  'X-Frame-Options': {
    owasp: 'A05:2021-Security Misconfiguration',
    cwe: 'CWE-693',
    cvss: cvss(4.3, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N'),
  },
  'X-Content-Type-Options': {
    owasp: 'A05:2021-Security Misconfiguration',
    cwe: 'CWE-693',
    cvss: cvss(3.1, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N'),
  },
  'Strict-Transport-Security': {
    owasp: 'A02:2021-Cryptographic Failures',
    cwe: 'CWE-319',
    cvss: cvss(5.3, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'),
  },
  'X-XSS-Protection': {
    owasp: 'A03:2021-Injection',
    cwe: 'CWE-693',
    cvss: cvss(2.1, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N'),
  },
  'Referrer-Policy': {
    owasp: 'A05:2021-Security Misconfiguration',
    cwe: 'CWE-200',
    cvss: cvss(3.1, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N'),
  },
  'Permissions-Policy': {
    owasp: 'A05:2021-Security Misconfiguration',
    cwe: 'CWE-693',
    cvss: cvss(2.1, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N'),
  },
  'Cross-Origin-Embedder-Policy': {
    owasp: 'A05:2021-Security Misconfiguration',
    cwe: 'CWE-942',
    cvss: cvss(3.1, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N'),
  },
  'Cross-Origin-Opener-Policy': {
    owasp: 'A05:2021-Security Misconfiguration',
    cwe: 'CWE-942',
    cvss: cvss(3.1, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N'),
  },
  'Server': {
    owasp: 'A05:2021-Security Misconfiguration',
    cwe: 'CWE-200',
    cvss: cvss(2.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'),
  },
  'X-Powered-By': {
    owasp: 'A05:2021-Security Misconfiguration',
    cwe: 'CWE-200',
    cvss: cvss(2.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'),
  },
};

// Endpoint reference mapping
export interface EndpointDefinition {
  path: string;
  name: string;
  risk: 'critical' | 'high' | 'medium' | 'low' | 'info';
  description: string;
  reference: SecurityReference;
}

export const WP_ENDPOINTS: EndpointDefinition[] = [
  {
    path: '/xmlrpc.php',
    name: 'XML-RPC',
    risk: 'critical',
    description: 'Puede usarse para ataques de fuerza bruta y DDoS',
    reference: {
      owasp: 'A01:2021-Broken Access Control',
      cwe: 'CWE-749',
      cvss: cvss(7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H'),
    },
  },
  {
    path: '/wp-login.php',
    name: 'WP Login',
    risk: 'medium',
    description: 'Página de login expuesta',
    reference: {
      owasp: 'A07:2021-Auth Failures',
      cwe: 'CWE-522',
      cvss: cvss(5.3, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'),
    },
  },
  {
    path: '/wp-admin/',
    name: 'WP Admin',
    risk: 'medium',
    description: 'Panel de administración accesible',
    reference: {
      owasp: 'A01:2021-Broken Access Control',
      cwe: 'CWE-284',
      cvss: cvss(5.3, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'),
    },
  },
  {
    path: '/wp-json/',
    name: 'REST API',
    risk: 'info',
    description: 'API REST activa',
    reference: {
      owasp: 'A01:2021-Broken Access Control',
      cwe: 'CWE-284',
      cvss: cvss(0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'),
    },
  },
  {
    path: '/wp-content/debug.log',
    name: 'Debug Log',
    risk: 'critical',
    description: 'Archivo de debug con info sensible',
    reference: {
      owasp: 'A09:2021-Logging Failures',
      cwe: 'CWE-532',
      cvss: cvss(7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'),
    },
  },
  {
    path: '/wp-config.php.bak',
    name: 'Config Backup',
    risk: 'critical',
    description: 'Backup con credenciales',
    reference: {
      owasp: 'A05:2021-Security Misconfiguration',
      cwe: 'CWE-200',
      cvss: cvss(9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
    },
  },
  {
    path: '/.git/',
    name: 'Git Exposed',
    risk: 'critical',
    description: 'Repositorio Git expuesto',
    reference: {
      owasp: 'A05:2021-Security Misconfiguration',
      cwe: 'CWE-527',
      cvss: cvss(7.5, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N'),
    },
  },
  {
    path: '/readme.html',
    name: 'Readme',
    risk: 'low',
    description: 'Revela versión de WordPress',
    reference: {
      owasp: 'A05:2021-Security Misconfiguration',
      cwe: 'CWE-200',
      cvss: cvss(2.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'),
    },
  },
  {
    path: '/wp-includes/',
    name: 'WP Includes',
    risk: 'info',
    description: 'Directorio includes accesible',
    reference: {
      owasp: 'A05:2021-Security Misconfiguration',
      cwe: 'CWE-200',
      cvss: cvss(0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N'),
    },
  },
  {
    path: '/wp-content/uploads/',
    name: 'Uploads',
    risk: 'low',
    description: 'Directorio uploads listable',
    reference: {
      owasp: 'A01:2021-Broken Access Control',
      cwe: 'CWE-200',
      cvss: cvss(3.1, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'),
    },
  },
  // New endpoints
  {
    path: '/wp-cron.php',
    name: 'WP Cron',
    risk: 'medium',
    description: 'Cron de WordPress expuesto, puede causar DoS',
    reference: {
      owasp: 'A05:2021-Security Misconfiguration',
      cwe: 'CWE-749',
      cvss: cvss(5.3, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L'),
    },
  },
  {
    path: '/wp-admin/install.php',
    name: 'Install Script',
    risk: 'critical',
    description: 'Script de instalación accesible',
    reference: {
      owasp: 'A05:2021-Security Misconfiguration',
      cwe: 'CWE-749',
      cvss: cvss(9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
    },
  },
  {
    path: '/backup.sql',
    name: 'SQL Backup',
    risk: 'critical',
    description: 'Backup de base de datos expuesto',
    reference: {
      owasp: 'A05:2021-Security Misconfiguration',
      cwe: 'CWE-200',
      cvss: cvss(9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
    },
  },
  {
    path: '/database.sql',
    name: 'DB Backup',
    risk: 'critical',
    description: 'Backup de base de datos expuesto',
    reference: {
      owasp: 'A05:2021-Security Misconfiguration',
      cwe: 'CWE-200',
      cvss: cvss(9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
    },
  },
  {
    path: '/.env',
    name: 'Env File',
    risk: 'critical',
    description: 'Archivo de entorno con secretos',
    reference: {
      owasp: 'A05:2021-Security Misconfiguration',
      cwe: 'CWE-200',
      cvss: cvss(9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
    },
  },
  {
    path: '/wp-config.php~',
    name: 'Config Temp',
    risk: 'critical',
    description: 'Archivo temporal de config',
    reference: {
      owasp: 'A05:2021-Security Misconfiguration',
      cwe: 'CWE-200',
      cvss: cvss(9.8, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'),
    },
  },
  {
    path: '/.htaccess',
    name: 'htaccess',
    risk: 'high',
    description: 'Configuración de servidor expuesta',
    reference: {
      owasp: 'A05:2021-Security Misconfiguration',
      cwe: 'CWE-200',
      cvss: cvss(5.3, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'),
    },
  },
  {
    path: '/phpinfo.php',
    name: 'PHP Info',
    risk: 'high',
    description: 'Información de PHP expuesta',
    reference: {
      owasp: 'A05:2021-Security Misconfiguration',
      cwe: 'CWE-200',
      cvss: cvss(5.3, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'),
    },
  },
  {
    path: '/wp-content/plugins/',
    name: 'Plugins Dir',
    risk: 'low',
    description: 'Listado de plugins visible',
    reference: {
      owasp: 'A06:2021-Vulnerable Components',
      cwe: 'CWE-200',
      cvss: cvss(3.1, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'),
    },
  },
];

// User enumeration reference
export const USER_ENUMERATION_REFERENCE: SecurityReference = {
  owasp: 'A01:2021-Broken Access Control',
  cwe: 'CWE-200',
  cvss: cvss(5.3, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'),
};

// Version disclosure reference
export const VERSION_DISCLOSURE_REFERENCE: SecurityReference = {
  owasp: 'A05:2021-Security Misconfiguration',
  cwe: 'CWE-200',
  cvss: cvss(2.0, 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N'),
};

// WAF Detection patterns
export const WAF_PATTERNS: Array<{ name: string; patterns: string[] }> = [
  { name: 'Cloudflare', patterns: ['cloudflare', 'cf-ray', '__cfduid'] },
  { name: 'Sucuri', patterns: ['sucuri', 'x-sucuri'] },
  { name: 'Wordfence', patterns: ['wordfence', 'wfwaf'] },
  { name: 'ModSecurity', patterns: ['mod_security', 'modsecurity'] },
  { name: 'Imperva', patterns: ['imperva', 'incapsula'] },
  { name: 'AWS WAF', patterns: ['awswaf', 'x-amz-cf'] },
  { name: 'Akamai', patterns: ['akamai', 'akamai-'] },
  { name: 'F5 BIG-IP', patterns: ['bigip', 'f5-'] },
];

// Detect WAF from response headers
export function detectWaf(headers: Headers): string | null {
  const headerEntries: string[] = [];
  headers.forEach((value, key) => {
    headerEntries.push(`${key.toLowerCase()}:${value.toLowerCase()}`);
  });
  const headerStr = headerEntries.join(' ');

  for (const waf of WAF_PATTERNS) {
    for (const pattern of waf.patterns) {
      if (headerStr.includes(pattern.toLowerCase())) {
        return waf.name;
      }
    }
  }
  return null;
}

// Calculate overall CVSS from findings
export function calculateOverallCvss(
  headers: Array<{ status: string; reference?: SecurityReference }>,
  endpoints: Array<{ status: string; reference?: SecurityReference }>,
  userEnumFound: boolean,
  versionDisclosed: boolean
): CvssScore {
  let maxScore = 0;
  const scores: number[] = [];

  // Collect scores from headers
  for (const h of headers) {
    if (h.status === 'vulnerable' && h.reference?.cvss) {
      scores.push(h.reference.cvss.score);
      maxScore = Math.max(maxScore, h.reference.cvss.score);
    }
  }

  // Collect scores from accessible endpoints
  for (const e of endpoints) {
    if (e.status === 'accessible' && e.reference?.cvss) {
      scores.push(e.reference.cvss.score);
      maxScore = Math.max(maxScore, e.reference.cvss.score);
    }
  }

  // Add user enumeration
  if (userEnumFound) {
    scores.push(USER_ENUMERATION_REFERENCE.cvss!.score);
    maxScore = Math.max(maxScore, USER_ENUMERATION_REFERENCE.cvss!.score);
  }

  // Add version disclosure
  if (versionDisclosed) {
    scores.push(VERSION_DISCLOSURE_REFERENCE.cvss!.score);
  }

  // Calculate weighted average with max score influence
  const avgScore = scores.length > 0 
    ? scores.reduce((a, b) => a + b, 0) / scores.length 
    : 0;
  
  // Overall = 60% max + 40% average (prioritize worst finding)
  const overallScore = Math.round((maxScore * 0.6 + avgScore * 0.4) * 10) / 10;

  return {
    score: overallScore,
    severity: getCvssSeverity(overallScore),
    vector: `Max: ${maxScore}, Issues: ${scores.length}`,
  };
}
