// WPSentry CORS proxy
// Live test results:
// corsproxy.io => real HTTP status + body (best option)
// allorigins   => always HTTP 200, sometimes times out

const CORSPROXY_TIMEOUT = 6000;
const ALLORIGINS_TIMEOUT = 5000;

function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  return Promise.race([
    p,
    new Promise<never>((_, r) => setTimeout(() => r(new Error(label + ' timeout')), ms))
  ]);
}

export interface ProxyResponse {
  ok: boolean;
  status: number;
  text: string;
  headers: Record<string, string>;
  url: string;
}

async function fetchCorsproxy(url: string): Promise<ProxyResponse> {
  const proxyUrl = 'https://corsproxy.io/?' + encodeURIComponent(url);
  const r = await withTimeout(
    fetch(proxyUrl, { headers: { Accept: 'text/html,application/json,*/*' } }),
    CORSPROXY_TIMEOUT, 'corsproxy'
  );
  const text = await r.text();
  const headers: Record<string, string> = {};
  r.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
  return { ok: r.ok, status: r.status, text, headers, url };
}

async function fetchAllorigins(url: string): Promise<ProxyResponse> {
  const proxyUrl = 'https://api.allorigins.win/raw?url=' + encodeURIComponent(url);
  const r = await withTimeout(fetch(proxyUrl), ALLORIGINS_TIMEOUT, 'allorigins');
  const text = await r.text();
  const headers: Record<string, string> = {};
  r.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
  // allorigins always returns 200 regardless of real status — use ok=true but status=200
  return { ok: true, status: 200, text, headers, url };
}

// Main fetch: try corsproxy (gives real status), fall back to allorigins
export async function fetchWithProxy(url: string): Promise<ProxyResponse> {
  // Try both in parallel, return first successful corsproxy response
  // If corsproxy fails/times out, use allorigins
  const corspromise = fetchCorsproxy(url).catch(() => null);
  const allopromise = fetchAllorigins(url).catch(() => null);

  // Wait for corsproxy first (it's more reliable)
  const cors = await corspromise;
  if (cors && cors.text.length > 10) return cors;

  // Fall back to allorigins
  const allo = await allopromise;
  if (allo && allo.text.length > 10) return allo;

  return { ok: false, status: 0, text: '', headers: {}, url };
}

// For endpoint existence check: use corsproxy status (real), allorigins just for body content
export async function fetchEndpoint(url: string): Promise<ProxyResponse> {
  // Race both proxies — corsproxy has real status, allorigins has always-200
  const [cors, allo] = await Promise.all([
    fetchCorsproxy(url).catch(() => null),
    fetchAllorigins(url).catch(() => null),
  ]);

  // Prefer corsproxy result (real HTTP status)
  if (cors && cors.text.length > 0) return cors;
  if (allo && allo.text.length > 0) return allo;
  return { ok: false, status: 0, text: '', headers: {}, url };
}
