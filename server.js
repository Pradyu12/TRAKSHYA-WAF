const http = require('http');

const PORT = process.env.UPSTREAM_PORT || 3000;

const pages = {
  '/': '<html><head><title>My Website</title></head><body><h1>Welcome to My Website</h1><p>This site is protected by TRAKSHYA-WAF</p><ul><li><a href="/about">About</a></li><li><a href="/api/users">Users API</a></li><li><a href="/api/products">Products API</a></li><li><a href="/login">Login</a></li></ul></body></html>',
  '/about': '<html><head><title>About</title></head><body><h1>About Us</h1><p>We are a company that cares about security.</p></body></html>',
  '/login': '<html><head><title>Login</title></head><body><h1>Login</h1><form method="POST" action="/api/auth/login"><input name="username" placeholder="Username"><input name="password" type="password" placeholder="Password"><button type="submit">Login</button></form></body></html>',
  '/api/users': JSON.stringify({ users: [{ id: 1, name: 'Alice' }, { id: 2, name: 'Bob' }] }),
  '/api/products': JSON.stringify({ products: [{ id: 1, name: 'Widget', price: 9.99 }, { id: 2, name: 'Gadget', price: 19.99 }] }),
  '/api/health': JSON.stringify({ status: 'ok', service: 'upstream-server' }),
  '/dashboard': '<html><head><title>Admin Dashboard</title></head><body><h1>Admin Dashboard</h1><p>Only accessible if WAF lets you through.</p></body></html>',
};

const server = http.createServer((req, res) => {
  const userAgent = req.headers['user-agent'] || 'unknown';
  console.log(`[UPSTREAM] ${req.method} ${req.url} from ${req.socket.remoteAddress} UA: ${userAgent}`);

  // CORS headers so the dashboard can fetch through the WAF proxy
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Forwarded-For');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  const body = pages[req.url] || pages['/'];
  const contentType = req.url.startsWith('/api/') ? 'application/json' : 'text/html';

  res.writeHead(200, { 'Content-Type': contentType });
  res.end(body);
});

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`[UPSTREAM] Port ${PORT} is already in use. Kill the existing process or set UPSTREAM_PORT to use a different port.`);
  } else {
    console.error(`[UPSTREAM] Server error:`, err.message);
  }
  process.exit(1);
});

server.listen(PORT, () => {
  console.log(`[UPSTREAM] Sample backend server running on http://localhost:${PORT}`);
  console.log('[UPSTREAM] This server is protected by TRAKSHYA-WAF proxy on port 8080');
});
