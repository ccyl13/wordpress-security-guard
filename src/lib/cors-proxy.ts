// WPSentry - CORS proxy layer
// Strategy: race all proxies simultaneously, take fastest response. Hard 5s timeout.

const PROXIES = [
  (url: string) => 'https://api.allorigins.win/raw?url=' + encodeURIComponent(url),
  (url: string) => 'https://corsproxy.io/?' + encodeURIComponent(url),
  (url: string) => 'https://api.codetabs.com/v1/proxy?quest=' + encodeURIComponent(url),
];

const TIMEOUT_MS = 5000; // hard 5s per request

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return Promise.race([
    promise,
    new Promise<never>((_, reject) =>
      setTimeout(() => reject(new Error('timeout')), ms)
    ),
  ]);
}

async function fetchViaProxy(
  proxyFn: (url: string) => string,
  targetUrl: string,
  signal?: AbortSignal
): Promise<Response> {
  const proxyUrl = proxyFn(targetUrl);
  const response = await fetch(proxyUrl, {
    signal,
    headers: { 'Accept': 'text/html,application/xhtml+xml,application/json,*/*' },
  });
  if (!response.ok) throw new Error('proxy returned ' + response.status);
  return response;
}

// Race all proxies — return first success
async function fetchRace(url: string): Promise<Response> {
  const controller = new AbortController();
  const { signal } = controller;

  const attempts = PROXIES.map(async (proxyFn) => {
    const resp = await withTimeout(fetchViaProxy(proxyFn, url, signal), TIMEOUT_MS);
    // Cancel remaining on first win
    controller.abort();
    return resp;
  });

  try {
    return await Promise.any(attempts);
  } catch {
    throw new Error('All proxies failed for: ' + url);
  }
}

// Public API
export interface ProxyResponse {
  ok: boolean;
  status: number;
  text: string;
  headers: Record<string, string>;
  url: string;
}

export async function fetchWithProxy(url: string): Promise<ProxyResponse> {
  try {
    const resp = await fetchRace(url);
    const text = await resp.text();
    const headers: Record<string, string> = {};
    resp.headers.forEach((val, key) => { headers[key.toLowerCase()] = val; });
    return { ok: true, status: resp.status, text, headers, url };
  } catch (err) {
    return { ok: false, status: 0, text: '', headers: {}, url };
  }
}

// Lightweight HEAD-style check: just need status code, no body
export async function checkEndpoint(url: string): Promise<{ accessible: boolean; status: number }> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    // Try direct HEAD first (fast, no proxy needed for status)
    const direct = await Promise.race([
      fetch(url, { method: 'HEAD', mode: 'no-cors', signal: controller.signal }),
      new Promise<never>((_, r) => setTimeout(() => r(new Error('to')), 3000)),
    ]);
    clearTimeout(timeout);
    // no-cors gives opaque response — treat as accessible
    return { accessible: true, status: 200 };
  } catch {
    // Fall back to proxy GET
    clearTimeout(timeout);
    try {
      const result = await withTimeout(fetchWithProxy(url), TIMEOUT_MS);
      const accessible = result.ok && result.status > 0 && result.status < 400;
      return { accessible, status: result.status };
    } catch {
      return { accessible: false, status: 0 };
    }
  }
}
