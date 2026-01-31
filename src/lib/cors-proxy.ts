// CORS proxies for making requests from the browser
const CORS_PROXIES = [
  'https://api.allorigins.win/raw?url=',
  'https://corsproxy.org/?',
];

let currentProxyIndex = 0;

export async function fetchWithProxy(url: string): Promise<Response> {
  const encodedUrl = encodeURIComponent(url);
  const errors: string[] = [];
  
  for (let i = 0; i < CORS_PROXIES.length; i++) {
    const proxyIndex = (currentProxyIndex + i) % CORS_PROXIES.length;
    const proxyUrl = CORS_PROXIES[proxyIndex] + encodedUrl;
    
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 15000); // 15s timeout
      
      const response = await fetch(proxyUrl, {
        method: 'GET',
        headers: {
          'Accept': 'text/html,application/json,*/*',
        },
        signal: controller.signal,
      });
      
      clearTimeout(timeoutId);
      currentProxyIndex = proxyIndex;
      return response;
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      errors.push(`Proxy ${proxyIndex}: ${errorMsg}`);
      console.warn(`Proxy ${proxyIndex} failed:`, errorMsg);
      continue;
    }
  }
  
  throw new Error(`All CORS proxies failed: ${errors.join(', ')}`);
}

export async function fetchHeadersWithProxy(url: string): Promise<Headers> {
  const response = await fetchWithProxy(url);
  return response.headers;
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
