// CORS proxies for making requests from the browser
// Ordered by reliability and speed
const CORS_PROXIES = [
  { url: 'https://api.allorigins.win/raw?url=', name: 'AllOrigins' },
  { url: 'https://corsproxy.io/?', name: 'CorsProxy.io' },
  { url: 'https://api.codetabs.com/v1/proxy?quest=', name: 'CodeTabs' },
];

let currentProxyIndex = 0;
const requestCache = new Map<string, { data: Response; timestamp: number }>();
const CACHE_TTL = 60000; // 1 minute cache

// Track which proxies are working
const proxyHealth = new Map<string, { failures: number; lastSuccess: number }>();

function getHealthyProxies(): typeof CORS_PROXIES {
  const now = Date.now();
  // Reset proxy health every 2 minutes
  return CORS_PROXIES.filter(proxy => {
    const health = proxyHealth.get(proxy.name);
    if (!health) return true;
    // Allow retry after 2 minutes even if failed before
    if (now - health.lastSuccess > 120000) return true;
    // Block proxies with 2+ consecutive failures
    return health.failures < 2;
  });
}

export async function fetchWithProxy(url: string, useCache = true): Promise<Response> {
  const encodedUrl = encodeURIComponent(url);
  
  // Check cache first
  if (useCache) {
    const cached = requestCache.get(url);
    if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
      return cached.data.clone();
    }
  }
  
  const errors: string[] = [];
  const healthyProxies = getHealthyProxies();
  const proxiesToTry = healthyProxies.length > 0 ? healthyProxies : CORS_PROXIES;
  
  for (let i = 0; i < proxiesToTry.length; i++) {
    const proxyIndex = (currentProxyIndex + i) % proxiesToTry.length;
    const proxy = proxiesToTry[proxyIndex];
    const proxyUrl = proxy.url + encodedUrl;
    
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000);
      
      const response = await fetch(proxyUrl, {
        method: 'GET',
        headers: {
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
          'Accept-Language': 'es-ES,es;q=0.9,en;q=0.8',
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        },
        signal: controller.signal,
      });
      
      clearTimeout(timeoutId);
      
      // Check if response is actually successful and has content
      if (!response.ok && response.status !== 403 && response.status !== 401) {
        errors.push(`${proxy.name}: HTTP ${response.status}`);
        continue;
      }
      
      // Clone response to check content length
      const cloned = response.clone();
      const text = await cloned.text();
      
      // Reject empty or too short responses (proxy error pages)
      if (text.length < 100) {
        errors.push(`${proxy.name}: Empty response`);
        continue;
      }
      
      // Success! Update health
      proxyHealth.set(proxy.name, { failures: 0, lastSuccess: Date.now() });
      currentProxyIndex = proxyIndex;
      
      // Create a new response with the text content
      const successResponse = new Response(text, {
        status: response.status,
        statusText: response.statusText,
        headers: response.headers,
      });
      
      // Cache successful responses
      if (useCache && response.ok) {
        requestCache.set(url, { data: successResponse.clone(), timestamp: Date.now() });
      }
      
      return successResponse;
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      
      // Update health tracking
      const health = proxyHealth.get(proxy.name) || { failures: 0, lastSuccess: 0 };
      proxyHealth.set(proxy.name, { ...health, failures: health.failures + 1 });
      
      errors.push(`${proxy.name}: ${errorMsg}`);
      continue;
    }
  }
  
  throw new Error(`No se pudo conectar. Los proxies CORS pueden estar bloqueados por el sitio. Errores: ${errors.join(', ')}`);
}

export async function checkEndpointExists(url: string): Promise<{ exists: boolean; statusCode: number }> {
  try {
    const response = await fetchWithProxy(url);
    return {
      exists: response.ok || response.status === 403 || response.status === 401,
      statusCode: response.status,
    };
  } catch {
    return { exists: false, statusCode: 0 };
  }
}

// Batch check multiple endpoints in parallel with concurrency limit
export async function checkEndpointsBatch(
  urls: string[],
  concurrency = 4
): Promise<Map<string, { exists: boolean; statusCode: number }>> {
  const results = new Map<string, { exists: boolean; statusCode: number }>();
  
  for (let i = 0; i < urls.length; i += concurrency) {
    const batch = urls.slice(i, i + concurrency);
    const batchResults = await Promise.all(
      batch.map(async (url) => {
        const result = await checkEndpointExists(url);
        return { url, result };
      })
    );
    
    batchResults.forEach(({ url, result }) => {
      results.set(url, result);
    });
  }
  
  return results;
}

export function clearCache(): void {
  requestCache.clear();
}
