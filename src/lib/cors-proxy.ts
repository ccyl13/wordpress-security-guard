// CORS proxies for making requests from the browser
const CORS_PROXIES = [
  'https://api.allorigins.win/raw?url=',
  'https://corsproxy.io/?',
  'https://proxy.cors.sh/',
];

let currentProxyIndex = 0;
const requestCache = new Map<string, { data: Response; timestamp: number }>();
const CACHE_TTL = 60000; // 1 minute cache

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
  
  for (let i = 0; i < CORS_PROXIES.length; i++) {
    const proxyIndex = (currentProxyIndex + i) % CORS_PROXIES.length;
    const proxy = CORS_PROXIES[proxyIndex];
    const proxyUrl = proxy + encodedUrl;
    
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 8000);
      
      console.log(`[CORS] Trying proxy ${proxyIndex}: ${proxy.substring(0, 30)}...`);
      
      const response = await fetch(proxyUrl, {
        method: 'GET',
        headers: {
          'Accept': 'text/html,application/json,*/*',
        },
        signal: controller.signal,
      });
      
      clearTimeout(timeoutId);
      
      // Check if response is actually successful
      if (!response.ok && response.status !== 403 && response.status !== 401) {
        console.log(`[CORS] Proxy ${proxyIndex} returned status ${response.status}`);
        errors.push(`Proxy ${proxyIndex}: HTTP ${response.status}`);
        continue;
      }
      
      currentProxyIndex = proxyIndex;
      console.log(`[CORS] Success with proxy ${proxyIndex}`);
      
      // Cache successful responses
      if (useCache && response.ok) {
        requestCache.set(url, { data: response.clone(), timestamp: Date.now() });
      }
      
      return response;
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      console.log(`[CORS] Proxy ${proxyIndex} failed: ${errorMsg}`);
      errors.push(`Proxy ${proxyIndex}: ${errorMsg}`);
      continue;
    }
  }
  
  throw new Error(`Todos los proxies CORS fallaron. Esto puede ocurrir si el sitio bloquea peticiones externas. Errores: ${errors.join(', ')}`);
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
