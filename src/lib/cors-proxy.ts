// CORS proxies for making requests from the browser
const CORS_PROXIES = [
  'https://api.allorigins.win/raw?url=',
  'https://corsproxy.org/?',
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
    const proxyUrl = CORS_PROXIES[proxyIndex] + encodedUrl;
    
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 6000);
      
      const response = await fetch(proxyUrl, {
        method: 'GET',
        headers: {
          'Accept': 'text/html,application/json,*/*',
        },
        signal: controller.signal,
      });
      
      clearTimeout(timeoutId);
      currentProxyIndex = proxyIndex;
      
      // Cache successful responses
      if (useCache && response.ok) {
        requestCache.set(url, { data: response.clone(), timestamp: Date.now() });
      }
      
      return response;
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      errors.push(`Proxy ${proxyIndex}: ${errorMsg}`);
      continue;
    }
  }
  
  throw new Error(`Proxies CORS fallaron: ${errors.join(', ')}`);
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
