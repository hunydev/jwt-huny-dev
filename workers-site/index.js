import { getAssetFromKV } from '@cloudflare/kv-asset-handler';

addEventListener('fetch', event => {
  event.respondWith(handleEvent(event));
});

async function handleEvent(event) {
  try {
    const response = await getAssetFromKV(event, {
      cacheControl: {
        browserTTL: 31536000, // 1 year for immutable assets
        edgeTTL: 31536000,
        bypassCache: false,
      },
    });
    
    // Add cache headers
    const headers = new Headers(response.headers);
    const url = new URL(event.request.url);
    
    // Set cache based on file type
    if (url.pathname.match(/\.(js|css|woff2?|ttf|eot|svg|png|jpg|jpeg|gif|webp|ico)$/)) {
      headers.set('Cache-Control', 'public, max-age=31536000, immutable');
    } else if (url.pathname.endsWith('.html') || url.pathname === '/') {
      headers.set('Cache-Control', 'public, max-age=3600, must-revalidate');
    } else {
      headers.set('Cache-Control', 'public, max-age=86400');
    }
    
    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers,
    });
  } catch (e) {
    let pathname = new URL(event.request.url).pathname;
    return new Response(`"${pathname}" not found`, {
      status: 404,
      statusText: 'not found',
    });
  }
}
