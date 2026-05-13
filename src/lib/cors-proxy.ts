// WPSentry CORS proxy layer
// corsproxy.io => returns real HTTP status codes (reliable for 401, 403, 404 detection)
// allorigins   => always returns 200 but good for body content
// Strategy: race both, prefer corsproxy status, use allorigins body as fallback

const TIMEOUT_MS = 6000;

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return Promise.race([p, new Promise<never>((_, r) => setTimeout(() => r(new Error('timeout')), ms))]);
}

export interface ProxyResponse {
  ok: boolean;
  status: number;
  text: string;
  headers: Record<string, string>;
  url: string;
}

async function tryCorsproxy(url: string): Promise<ProxyResponse | null> {
  try {
    const proxyUrl = 'https://corsproxy.io/?' + encodeURIComponent(url);
    const r = await withTimeout(fetch(proxyUrl, {
      headers: { Accept: 'text/html,application/json,*/*' }
    }), TIMEOUT_MS);
    const text = await r.text();
    const headers: Record<string, string> = {};
    r.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    return { ok: r.ok, status: r.status, text, headers, url };
  } catch { return null; }
}

async function tryAllorigins(url: string): Promise<ProxyResponse | null> {
  try {
    const proxyUrl = 'https://api.allorigins.win/raw?url=' + encodeURIComponent(url);
    const r = await withTimeout(fetch(proxyUrl), TIMEOUT_MS);
    const text = await r.text();
    const headers: Record<string, string> = {};
    r.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });
    // allorigins always returns 200 — don't trust its status for existence checks
    return { ok: true, status: 200, text, headers, url };
  } catch { return null; }
}

// Main fetch: get best response from both proxies
export async function fetchWithProxy(url: string): Promise<ProxyResponse> {
  const [corsproxy, allorigins] = await Promise.all([
    tryCorsproxy(url),
    tryAllorigins(url),
  ]);

  // Prefer corsproxy because it gives real status codes
  if (corsproxy && corsproxy.text.length > 0) return corsproxy;
  if (allorigins && allorigins.text.length > 0) return allorigins;
  return { ok: false, status: 0, text: '', headers: {}, url };
}

// Endpoint check: uses corsproxy status (real) + body validation
// allorigins as body-only fallback when corsproxy is slow/blocked
export async function checkEndpoint(url: string): Promise<{ accessible: boolean; status: number }> {
  const [corsproxy, allorigins] = await Promise.all([
    tryCorsproxy(url),
    tryAllorigins(url),
  ]);

  // corsproxy gives real status — trust it for 404/403/401
  if (corsproxy) {
    const accessible = corsproxy.status > 0 && corsproxy.status < 400;
    return { accessible, status: corsproxy.status };
  }
  // allorigins fallback — only use body, can't trust status
  if (allorigins) {
    return { accessible: true, status: 200 }; // unknown, assume exists
  }
  return { accessible: false, status: 0 };
}
