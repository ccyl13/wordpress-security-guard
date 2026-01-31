// CORS proxies for making requests from the browser
// These are free public proxies - some may be unreliable
const CORS_PROXIES = [
  {
    url: 'https://api.allorigins.win/get?url=',
    parseResponse: async (response: Response) => {
      const data = await response.json();
      return new Response(data.contents, {
        status: data.status?.http_code || 200,
        headers: new Headers(),
      });
    },
  },
  {
    url: 'https://corsproxy.org/?',
    parseResponse: async (response: Response) => response,
  },
  {
    url: 'https://proxy.cors.sh/',
    parseResponse: async (response: Response) => response,
  },
];

let currentProxyIndex = 0;

export async function fetchWithProxy(url: string): Promise<Response> {
  const errors: string[] = [];
  
  for (let i = 0; i < CORS_PROXIES.length; i++) {
    const proxyIndex = (currentProxyIndex + i) % CORS_PROXIES.length;
    const proxy = CORS_PROXIES[proxyIndex];
    const proxyUrl = proxy.url + encodeURIComponent(url);
    
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10000); // 10s timeout
      
      const response = await fetch(proxyUrl, {
        method: 'GET',
        headers: {
          'Accept': 'text/html,application/json,*/*',
        },
        signal: controller.signal,
      });
      
      clearTimeout(timeoutId);
      
      if (!response.ok && response.status !== 404 && response.status !== 403) {
        throw new Error(`HTTP ${response.status}`);
      }
      
      currentProxyIndex = proxyIndex;
      return await proxy.parseResponse(response);
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
