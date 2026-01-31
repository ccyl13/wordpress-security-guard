export interface SecurityHeader {
  name: string;
  value: string | null;
  status: 'secure' | 'warning' | 'vulnerable' | 'info';
  description: string;
}

export interface EndpointCheck {
  name: string;
  url: string;
  status: 'accessible' | 'blocked' | 'error' | 'checking';
  statusCode?: number;
  description: string;
  risk: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

export interface UserEnumeration {
  found: boolean;
  users: Array<{ id: number; name: string; slug: string }>;
  method: string;
}

export interface WordPressInfo {
  version: string | null;
  theme: string | null;
  generator: boolean;
  readme: boolean;
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
}
