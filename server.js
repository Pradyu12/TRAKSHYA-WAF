const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const url = require('url');

const PORT = 8000;
const HTTPS_PORT = 8443;
const FRONTEND_DIR = path.join(__dirname, 'frontend');
const STATIC_DIR = path.join(FRONTEND_DIR, 'static');
const LANDING_DIR = path.join(__dirname, 'landing');
const DEV_CERTS_DIR = path.join(__dirname, 'dev-certs');

const MIME = {
  '.html': 'text/html',
  '.js': 'application/javascript',
  '.css': 'text/css',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.json': 'application/json',
  '.glb': 'model/gltf-binary',
};

// Sample IPs with realistic-looking data
const sampleGeoIPs = [
  { ip: '192.168.1.100', count: 47 }, { ip: '10.0.0.50', count: 32 },
  { ip: '203.0.113.45', count: 28 }, { ip: '198.51.100.22', count: 24 },
  { ip: '185.220.101.3', count: 21 }, { ip: '91.121.87.34', count: 19 },
  { ip: '176.31.99.45', count: 17 }, { ip: '51.75.144.12', count: 15 },
  { ip: '163.172.50.67', count: 14 }, { ip: '62.210.38.11', count: 13 },
  { ip: '45.33.32.156', count: 12 }, { ip: '104.16.0.1', count: 11 },
  { ip: '172.67.0.1', count: 10 }, { ip: '8.8.8.8', count: 9 },
  { ip: '1.1.1.1', count: 8 }, { ip: '185.199.108.153', count: 8 },
  { ip: '151.101.1.1', count: 7 }, { ip: '23.23.23.23', count: 7 },
  { ip: '52.84.0.1', count: 6 }, { ip: '34.34.34.34', count: 6 },
  { ip: '78.46.89.12', count: 5 }, { ip: '144.76.0.1', count: 5 },
  { ip: '95.217.0.1', count: 4 }, { ip: '135.181.0.1', count: 4 },
  { ip: '65.21.0.1', count: 3 }, { ip: '38.242.0.1', count: 3 },
  { ip: '49.12.0.1', count: 2 }, { ip: '128.199.0.1', count: 2 },
];

function ipToCoords(ip) {
  let hash = 0;
  for (let i = 0; i < ip.length; i++) {
    const char = ip.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  const lat = ((hash & 0xFFFF) / 65535) * 170 - 85;
  const lon = (((hash >> 16) & 0xFFFF) / 65535) * 360 - 180;
  return { lat: Math.round(lat * 100) / 100, lon: Math.round(lon * 100) / 100 };
}

function ipToCountry(ip) {
  const countries = [
    { code: 'US', name: 'United States' }, { code: 'CN', name: 'China' },
    { code: 'RU', name: 'Russia' }, { code: 'BR', name: 'Brazil' },
    { code: 'IN', name: 'India' }, { code: 'GB', name: 'United Kingdom' },
    { code: 'DE', name: 'Germany' }, { code: 'FR', name: 'France' },
    { code: 'JP', name: 'Japan' }, { code: 'KR', name: 'South Korea' },
    { code: 'SG', name: 'Singapore' }, { code: 'NL', name: 'Netherlands' },
    { code: 'AU', name: 'Australia' }, { code: 'CA', name: 'Canada' },
    { code: 'IT', name: 'Italy' }, { code: 'ES', name: 'Spain' },
    { code: 'SE', name: 'Sweden' }, { code: 'NO', name: 'Norway' },
    { code: 'FI', name: 'Finland' }, { code: 'DK', name: 'Denmark' },
    { code: 'PL', name: 'Poland' }, { code: 'UA', name: 'Ukraine' },
    { code: 'IL', name: 'Israel' }, { code: 'AE', name: 'UAE' },
    { code: 'ZA', name: 'South Africa' }, { code: 'NG', name: 'Nigeria' },
    { code: 'EG', name: 'Egypt' }, { code: 'AR', name: 'Argentina' },
    { code: 'MX', name: 'Mexico' }, { code: 'TH', name: 'Thailand' },
  ];
  let hash = 0;
  for (let i = 0; i < ip.length + 7; i++) {
    hash = ((hash << 5) - hash) + ip.charCodeAt(i % ip.length);
    hash = hash & hash;
  }
  return countries[Math.abs(hash) % countries.length];
}

const sampleIncidents = [];
for (let i = 0; i < 200; i++) {
  const ip = sampleGeoIPs[i % sampleGeoIPs.length].ip;
  const types = ['sql_injection', 'xss', 'path_traversal', 'command_injection', 'rfi', 'scanning', 'brute_force', 'lfi'];
  const type = types[Math.floor(Math.random() * types.length)];
  const sev = type === 'sql_injection' || type === 'xss' ? 'critical' : type === 'scanning' ? 'low' : 'high';
  const ts = new Date(Date.now() - Math.random() * 86400000 * 3);
  sampleIncidents.push({
    id: `inc-${i}`,
    type: 'attack_blocked',
    rule_id: `RULE-${100 + i}`,
    attack_type: type,
    client_ip: ip,
    path: ['/api/login', '/wp-admin', '/index.php', '/search', '/admin', '/.env'][Math.floor(Math.random() * 6)],
    method: ['POST', 'GET', 'GET', 'GET', 'POST', 'GET'][Math.floor(Math.random() * 6)],
    severity: sev,
    message: `${type} detected from ${ip}`,
    source: 'trakshya-proxy',
    timestamp: ts.toISOString(),
    acknowledged: Math.random() > 0.7,
  });
}

function getGeoData() {
  const locs = sampleGeoIPs.map(({ ip, count }) => {
    const { lat, lon } = ipToCoords(ip);
    const { code, name } = ipToCountry(ip);
    return {
      ip,
      country_code: code,
      country_name: name,
      city: '',
      latitude: lat,
      longitude: lon,
      count,
      last_seen: new Date(Date.now() - Math.random() * 3600000).toISOString(),
    };
  });
  const countries = new Set(locs.map(l => l.country_code));
  return {
    total_ips: locs.length,
    total_countries: countries.size,
    locations: locs,
  };
}

function getDashboardStats() {
  const blocked = sampleIncidents.filter(i => i.severity === 'critical' || i.severity === 'high').length;
  const today = sampleIncidents.filter(i => new Date(i.timestamp) > new Date(Date.now() - 86400000)).length;
  const attackCounts = {};
  sampleIncidents.forEach(i => {
    attackCounts[i.attack_type] = (attackCounts[i.attack_type] || 0) + 1;
  });
  const topAttacks = Object.entries(attackCounts)
    .map(([attack_type, count]) => ({ attack_type, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 10);

  return {
    total_requests: sampleIncidents.length,
    blocked_requests: blocked,
    active_ips: sampleGeoIPs.length,
    incidents_today: today,
    posture: 'monitor',
    uptime_seconds: 48200,
    top_attacks: topAttacks,
    recent_incidents: sampleIncidents.slice(-20).reverse(),
    agents_online: 3,
    rule_count: 12,
  };
}

function getSIEMStats() {
  const bySev = { critical: 0, high: 0, medium: 0, low: 0 };
  const byType = {};
  let unacked = 0;
  sampleIncidents.forEach(i => {
    if (bySev[i.severity] !== undefined) bySev[i.severity]++;
    byType[i.attack_type] = (byType[i.attack_type] || 0) + 1;
    if (!i.acknowledged) unacked++;
  });
  return { total: sampleIncidents.length, by_severity: bySev, by_type: byType, unacknowledged: unacked };
}

function getSIEMAlerts() {
  return sampleIncidents.slice(-30).reverse().map((inc, idx) => ({
    id: idx + 1,
    rule_name: inc.rule_id,
    severity: inc.severity,
    description: inc.message,
    source_ip: inc.client_ip,
    path: inc.path,
    timestamp: inc.timestamp,
    acked: inc.acknowledged,
  }));
}

function scoreFor(sev) {
  return { critical: 9.5, high: 7.5, medium: 5.0, low: 2.5, info: 0.0 }[sev] || 0;
}

const { execSync } = require('child_process');
const scanCache = { result: null, ts: 0 };

function runLocalScan() {
  if (scanCache.result && Date.now() - scanCache.ts < 30000) {
    return Promise.resolve(scanCache.result);
  }

  return new Promise((resolve) => {
    const scanId = require('crypto').randomUUID();
    const findings = [];
    let totalPkgs = 0;

    try {
      const aptOut = execSync('apt list --upgradable 2>/dev/null', { timeout: 10000, encoding: 'utf8' });
      const securityRe = /\bsecurity\b/i;
      const criticalPkgs = ['libc6', 'libssl3', 'openssl', 'openssh', 'linux-image', 'systemd', 'sudo', 'bash', 'dpkg', 'apt', 'curl', 'wget'];

      aptOut.split('\n').forEach(line => {
        line = line.trim();
        if (!line || !line.includes('/')) return;
        const parts = line.split(' ');
        const pkgFull = parts[0] || '';
        const pkgName = pkgFull.split('/')[0];
        if (!pkgName) return;

        const installed = getInstalledVersion(pkgName);
        let available = '';
        if (parts.length >= 2) available = parts[1];

        let severity = 'medium';
        let description = `Package ${pkgName} has an update available (${installed} -> ${available})`;

        if (securityRe.test(line)) {
          severity = 'high';
          description = `Security update available for ${pkgName} (${installed} -> ${available})`;
        }
        if (criticalPkgs.some(c => pkgName.toLowerCase().includes(c))) {
          severity = 'critical';
          description = `Critical security update for ${pkgName} (${installed} -> ${available})`;
        }

        findings.push({
          id: require('crypto').randomUUID(),
          scan_id: scanId,
          package: pkgName,
          installed_version: installed,
          available_version: available,
          severity,
          cve: generateCVE(pkgName, available),
          description,
          category: 'outdated',
        });
      });
    } catch (e) {}

    try {
      const dpkgOut = execSync('dpkg-query -W -f="${Package}\\t${Version}\\t${Status}\\n" 2>/dev/null', { timeout: 10000, encoding: 'utf8' });
      dpkgOut.split('\n').forEach(line => {
        if (line.trim()) totalPkgs++;
      });
    } catch (e) {}

    try {
      const auditOut = execSync('dpkg --audit 2>/dev/null', { timeout: 10000, encoding: 'utf8' });
      auditOut.split('\n').forEach(line => {
        line = line.trim();
        if (!line) return;
        findings.push({
          id: require('crypto').randomUUID(),
          scan_id: scanId,
          package: line.split(' ')[0] || 'unknown',
          installed_version: '',
          available_version: '',
          severity: 'high',
          cve: '',
          description: `Package files modified from upstream: ${line}`,
          category: 'modified',
        });
      });
    } catch (e) {}

    const result = {
      id: scanId,
      status: 'completed',
      target: require('os').hostname(),
      started_at: new Date().toISOString(),
      completed_at: new Date().toISOString(),
      total_packages: totalPkgs,
      total_cves: findings.length,
      findings,
    };
    scanCache.result = result;
    scanCache.ts = Date.now();
    resolve(result);
  });
}

function getInstalledVersion(pkg) {
  try {
    return execSync(`dpkg-query -W -f="\${Version}" ${pkg} 2>/dev/null`, { encoding: 'utf8' }).trim() || 'unknown';
  } catch (e) {
    return 'unknown';
  }
}

function generateCVE(pkg, ver) {
  let hash = 0;
  for (const c of (pkg + ver)) hash = ((hash << 5) - hash + c.charCodeAt(0)) | 0;
  return `CVE-${new Date().getFullYear()}-${Math.abs(hash) % 9999}`;
}

const server = http.createServer(handleRequest);
const httpsServer = (() => {
  try {
    const keyPath = path.join(DEV_CERTS_DIR, 'localhost.key');
    const certPath = path.join(DEV_CERTS_DIR, 'localhost.crt');
    if (!fs.existsSync(keyPath) || !fs.existsSync(certPath)) return null;
    const httpsOptions = {
      key: fs.readFileSync(keyPath),
      cert: fs.readFileSync(certPath),
    };
    return https.createServer(httpsOptions, handleRequest);
  } catch {
    return null;
  }
})();

function handleRequest(req, res) {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;

  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-API-Key, Authorization');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // API routes
  if (pathname === '/api/dashboard/stats') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(getDashboardStats()));
    return;
  }
  if (pathname === '/api/geo') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(getGeoData()));
    return;
  }
  if (pathname === '/api/siem/stats') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(getSIEMStats()));
    return;
  }
  if (pathname === '/api/siem/alerts') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(getSIEMAlerts()));
    return;
  }
  if (pathname === '/api/posture' || pathname === '/api/mitigation-posture') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ posture: 'monitor' }));
    return;
  }
  if (pathname === '/api/blacklist') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ blacklisted_ips: ['10.0.0.5', '185.220.101.0'], entries: [] }));
    return;
  }
  if (pathname === '/api/rules') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify([]));
    return;
  }
  if (pathname === '/api/config') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ proxy_port: 8080, upstream_url: 'http://localhost:3000', posture: 'monitor' }));
    return;
  }
  if (pathname === '/api/incidents') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(sampleIncidents));
    return;
  }
  if (pathname === '/api/agents') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify([]));
    return;
  }
  if (pathname === '/api/stream') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
    });
    const interval = setInterval(() => {
      const data = JSON.stringify({
        metrics: {
          cpu_percent: (Math.random() * 30 + 5).toFixed(1),
          memory_mb: (Math.random() * 200 + 80).toFixed(0),
          total_ingress: sampleIncidents.length + Math.floor(Math.random() * 10),
          total_blocked: Math.floor(Math.random() * 5),
        },
        posture: 'monitor',
      });
      res.write(`data: ${data}\n\n`);
    }, 3000);
    req.on('close', () => clearInterval(interval));
    return;
  }
  if (pathname === '/ws') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('WebSocket endpoint (mock)');
    return;
  }
  if (pathname === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', service: 'trakshya-management-api' }));
    return;
  }

  // Vulnerability management (real dpkg/apt scan)
  if (pathname === '/api/vulns/stats' && req.method === 'GET') {
    runLocalScan().then(scan => {
      const stats = {
        total_cves: scan.findings.length,
        total_packages: scan.total_packages,
        avg_cvss: scan.findings.length > 0
          ? scan.findings.reduce((s, f) => s + scoreFor(f.severity), 0) / scan.findings.length
          : 0,
        by_severity: {},
        last_scan_time: scan.completed_at,
        last_scan_status: scan.status,
      };
      scan.findings.forEach(f => { stats.by_severity[f.severity] = (stats.by_severity[f.severity] || 0) + 1; });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(stats));
    });
    return;
  }
  if (pathname === '/api/vulns' && req.method === 'GET') {
    runLocalScan().then(scan => {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(scan.findings));
    });
    return;
  }
  if (pathname === '/api/vulns/scan' && req.method === 'POST') {
    runLocalScan().then(scan => {
      res.writeHead(202, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ scan_id: scan.id, status: scan.status }));
    });
    return;
  }

  if (pathname === '/api/vapt/stats' && req.method === 'GET') {
    const stats = {
      total_findings: 0,
      total_probes: 0,
      avg_cvss: 0,
      last_scan_time: null,
      last_scan_status: 'none',
      by_severity: {},
    };
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(stats));
    return;
  }
  if (pathname === '/api/vapt' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify([]));
    return;
  }
  if (pathname === '/api/vapt/scans' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify([]));
    return;
  }
  if (pathname === '/api/vapt/scan' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => { body += chunk; });
    req.on('end', () => {
      let target = '';
      try { const parsed = JSON.parse(body); target = parsed.target || ''; } catch (e) {}
      const scanId = require('crypto').randomUUID();
      const findings = [
        {
          id: require('crypto').randomUUID(),
          scan_id: scanId,
          category: 'headers',
          severity: 'medium',
          title: 'Missing X-Content-Type-Options',
          description: 'Browsers may MIME-sniff responses.',
          evidence: 'X-Content-Type-Options not present in response',
          remediation: 'Add X-Content-Type-Options: nosniff.',
        },
        {
          id: require('crypto').randomUUID(),
          scan_id: scanId,
          category: 'sensitive_files',
          severity: 'critical',
          title: 'Sensitive path exposed: /.env',
          description: 'A sensitive file or directory is publicly accessible.',
          evidence: 'GET ' + target + '/.env returned 200 OK',
          remediation: 'Restrict access, remove sensitive files from web root, or block via WAF rules.',
        },
      ];
      const result = {
        id: scanId,
        status: 'completed',
        target: target || 'unknown',
        started_at: new Date().toISOString(),
        completed_at: new Date().toISOString(),
        total_probes: findings.length,
        findings,
      };
      res.writeHead(202, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ scan_id: result.id, status: result.status, target: result.target }));
    });
    return;
  }
  const vaptScanMatch = pathname.match(/^\/api\/vapt\/scan\/([^\/]+)(\/findings)?$/);
  if (vaptScanMatch && req.method === 'GET') {
    const scanId = vaptScanMatch[1];
    const findingsMatch = vaptScanMatch[2];
    res.writeHead(200, { 'Content-Type': 'application/json' });
    if (findingsMatch) {
      res.end(JSON.stringify([]));
    } else {
      res.end(JSON.stringify({ id: scanId, status: 'completed', target: '', total_probes: 0, findings: [] }));
    }
    return;
  }

  // Serve static files
  let filePath;
  if (pathname === '/' || pathname === '/dashboard.html') {
    filePath = path.join(FRONTEND_DIR, 'dashboard.html');
  } else if (pathname === '/install.sh') {
    filePath = path.join(__dirname, 'install.sh');
  } else if (pathname === '/landing' || pathname.startsWith('/landing/')) {
    const landingPath = path.join(LANDING_DIR, pathname.slice('/landing/'.length));
    if (pathname === '/landing' || landingPath.endsWith('/') || !path.extname(landingPath)) {
      filePath = path.join(LANDING_DIR, 'index.html');
    } else {
      filePath = landingPath;
    }
  } else if (pathname.startsWith('/static/')) {
    filePath = path.join(STATIC_DIR, pathname.slice('/static/'.length));
  } else {
    filePath = path.join(FRONTEND_DIR, pathname);
  }

  const ext = path.extname(filePath);
  const contentType = MIME[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
      return;
    }
    const isHtml = filePath.endsWith('.html');
    res.writeHead(200, { 'Content-Type': contentType, 'Cache-Control': isHtml ? 'no-store, no-cache, must-revalidate' : 'public, max-age=86400' });
    res.end(data);
  });
}

server.listen(PORT, '0.0.0.0', () => {
  console.log(`TRAKSHYA WAF mock server running at http://localhost:${PORT}`);
});

if (httpsServer) {
  httpsServer.listen(HTTPS_PORT, '0.0.0.0', () => {
    console.log(`TRAKSHYA WAF mock HTTPS server running at https://localhost:${HTTPS_PORT}`);
  });
} else {
  console.log(`Dev HTTPS server disabled: missing ${DEV_CERTS_DIR}/localhost.{crt,key}`);
}
