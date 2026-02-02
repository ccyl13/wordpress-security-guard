// OWASP Top 10 2021 Categories
export type OwaspCategory = 
  | 'A01:2021-Broken Access Control'
  | 'A02:2021-Cryptographic Failures'
  | 'A03:2021-Injection'
  | 'A04:2021-Insecure Design'
  | 'A05:2021-Security Misconfiguration'
  | 'A06:2021-Vulnerable Components'
  | 'A07:2021-Auth Failures'
  | 'A08:2021-Data Integrity Failures'
  | 'A09:2021-Logging Failures'
  | 'A10:2021-SSRF';

// CWE (Common Weakness Enumeration) IDs
export type CweId = 
  | 'CWE-16'   // Configuration
  | 'CWE-200'  // Information Exposure
  | 'CWE-284'  // Improper Access Control
  | 'CWE-311'  // Missing Encryption
  | 'CWE-319'  // Cleartext Transmission
  | 'CWE-352'  // CSRF
  | 'CWE-444'  // HTTP Request Smuggling
  | 'CWE-522'  // Weak Credentials
  | 'CWE-523'  // Unprotected Transport
  | 'CWE-524'  // Cache Info Leak
  | 'CWE-525'  // Browser Cache Weakness
  | 'CWE-527'  // CVS/Git Repo Info Leak
  | 'CWE-532'  // Log File Info Leak
  | 'CWE-539'  // Session Info Leak
  | 'CWE-614'  // HTTPS Session Cookie
  | 'CWE-693'  // Protection Mechanism Failure
  | 'CWE-749'  // Exposed Dangerous Method
  | 'CWE-829'  // Untrusted Control Sphere
  | 'CWE-942'; // CORS Misconfiguration

// CVSS 3.1 Base Score and Vector
export interface CvssScore {
  score: number;           // 0.0 - 10.0
  severity: 'None' | 'Low' | 'Medium' | 'High' | 'Critical';
  vector: string;          // CVSS:3.1/AV:N/AC:L/...
}

// Security reference linking to standards
export interface SecurityReference {
  owasp?: OwaspCategory;
  cwe?: CweId;
  cvss?: CvssScore;
}

export interface SecurityHeader {
  name: string;
  value: string | null;
  status: 'secure' | 'warning' | 'vulnerable' | 'info';
  description: string;
  reference?: SecurityReference;
}

export interface EndpointCheck {
  name: string;
  url: string;
  status: 'accessible' | 'blocked' | 'error' | 'checking';
  statusCode?: number;
  description: string;
  risk: 'critical' | 'high' | 'medium' | 'low' | 'info';
  reference?: SecurityReference;
}

export interface UserEnumeration {
  found: boolean;
  users: Array<{ id: number; name: string; slug: string }>;
  method: string;
  reference?: SecurityReference;
}

export interface WordPressInfo {
  version: string | null;
  theme: string | null;
  generator: boolean;
  readme: boolean;
  wafDetected?: string | null;
  sslInfo?: SslInfo | null;
}

export interface SslInfo {
  valid: boolean;
  issuer?: string;
  expiresAt?: string;
  protocol?: string;
}

export interface AuditResult {
  url: string;
  timestamp: Date;
  isWordPress: boolean;
  securityHeaders: SecurityHeader[];
  endpoints: EndpointCheck[];
  userEnumeration: UserEnumeration;
  wordpressInfo: WordPressInfo;
  overallScore: number;
  cvssOverall?: CvssScore;
}

// Helper to calculate CVSS severity from score
export function getCvssSeverity(score: number): CvssScore['severity'] {
  if (score === 0) return 'None';
  if (score < 4.0) return 'Low';
  if (score < 7.0) return 'Medium';
  if (score < 9.0) return 'High';
  return 'Critical';
}

// Helper to get color for CVSS severity
export function getCvssColor(severity: CvssScore['severity']): string {
  switch (severity) {
    case 'Critical': return 'text-red-600 bg-red-100 dark:bg-red-900/30';
    case 'High': return 'text-orange-600 bg-orange-100 dark:bg-orange-900/30';
    case 'Medium': return 'text-yellow-600 bg-yellow-100 dark:bg-yellow-900/30';
    case 'Low': return 'text-blue-600 bg-blue-100 dark:bg-blue-900/30';
    default: return 'text-green-600 bg-green-100 dark:bg-green-900/30';
  }
}
