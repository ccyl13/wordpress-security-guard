// CORS proxies for making requests from the browser
const CORS_PROXIES = [
  'https://api.allorigins.win/raw?url=',
  'https://corsproxy.io/?',
  'https://api.codetabs.com/v1/proxy?quest=',
];

let currentProxyIndex = 0;

export async function fetchWithProxy(url: string): Promise<Response> {
  const encodedUrl = encodeURIComponent(url);
  
  for (let i = 0; i < CORS_PROXIES.length; i++) {
    const proxyIndex = (currentProxyIndex + i) % CORS_PROXIES.length;
    const proxyUrl = CORS_PROXIES[proxyIndex] + encodedUrl;
    
    try {
      const response = await fetch(proxyUrl, {
        method: 'GET',
        headers: {
          'Accept': 'text/html,application/json,*/*',
        },
      });
      
      currentProxyIndex = proxyIndex;
      return response;
    } catch (error) {
      console.warn(`Proxy ${proxyIndex} failed, trying next...`);
      continue;
    }
  }
  
  throw new Error('All CORS proxies failed');
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
