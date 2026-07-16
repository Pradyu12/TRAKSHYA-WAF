#!/usr/bin/env node

/**
 * TRAKSHYA WAF — production-ready installer and controller
 *
 * Usage:
 *   trakshya-install install [--mode=local|systemd|docker]
 *   trakshya-install uninstall
 *   trakshya-install start|stop|restart|status
 *   trakshya-install logs [service]
 *   trakshya-install doctor
 *   trakshya-install update
 */

const { execSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

const INSTALL_DIR = '/opt/trakshya-waf';
const BIN_DIR = '/usr/local/bin';
const SERVICE_USER = 'trakshya';
const DASHBOARD_PORT = 8000;
const PROXY_PORT = 8080;
const API_PORT = 8001;

function red(msg) {
  return `\u001b[31m${msg}\u001b[0m`;
}
function green(msg) {
  return `\u001b[32m${msg}\u001b[0m`;
}
function cyan(msg) {
  return `\u001b[36m${msg}\u001b[0m`;
}
function yellow(msg) {
  return `\u001b[33m${msg}\u001b[0m`;
}

function usage(exitCode = 0) {
  console.log(`
${cyan('TRAKSHYA WAF — Installer CLI')}

Usage:
  trakshya-install <command> [options]

Commands:
  install [--mode=local|systemd|docker]  Install the firewall
  uninstall                              Remove services and files
  start                                  Start all services
  stop                                   Stop all services
  restart                                Restart all services
  status                                 Show service status
  logs [service]                         Tail logs
  doctor                                 Diagnose installation
  update                                 Pull latest release
  help                                   Show this help

Options:
  --mode         Install mode: local (user), systemd (requires sudo), docker
  --user         Service user for systemd mode (default: ${SERVICE_USER})
  --port-dashboard  Dashboard port (default: ${DASHBOARD_PORT})
  --port-proxy      Proxy port (default: ${PROXY_PORT})

Examples:
  sudo trakshya-install install --mode=systemd
  trakshya-install status
  trakshya-install logs trakshya-dashboard
  trakshya-install doctor
`);
  process.exit(exitCode);
}

function run(cmd, options = {}) {
  try {
    return execSync(cmd, { encoding: 'utf8', stdio: 'pipe', ...options }).trim();
  } catch (error) {
    const message = error.stdout?.toString() || error.message || String(error);
    throw new Error(message);
  }
}

function runLive(cmd) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, { shell: true, stdio: 'inherit' });
    child.on('close', (code) => {
      if (code === 0) {
        resolve();
      } else {
        reject(new Error(`${cmd} exited with code ${code}`));
      }
    });
  });
}

function detectPackageManager() {
  if (fs.existsSync('/etc/debian_version') || fs.existsSync('/etc/lsb-release')) {
    return 'apt';
  }
  if (fs.existsSync('/etc/redhat-release')) {
    return 'yum';
  }
  if (fs.existsSync('/etc/arch-release')) {
    return 'pacman';
  }
  if (fs.existsSync('/etc/alpine-release')) {
    return 'apk';
  }
  return 'unknown';
}

function installDependencies() {
  const pm = detectPackageManager();
  console.log(yellow(`Detected package manager: ${pm}`));

  const cmds = {
    apt: 'apt-get update && apt-get install -y nginx nodejs npm cargo golang-go cmake build-essential libssl-dev pkg-config curl',
    yum: 'yum install -y nginx nodejs npm golang cargo cmake gcc openssl-devel curl',
    pacman: 'pacman -Sy --noconfirm nginx nodejs npm go cargo cmake base-devel openssl curl',
    apk: 'apk add --no-cache nginx nodejs npm go cargo cmake build-base openssl curl',
    unknown:
      'echo "Unknown distro; install nginx, node, npm, cargo, go, cmake, openssl manually"',
  };

  const cmd = cmds[pm] || cmds.unknown;
  console.log(cyan('Installing system dependencies...'));
  runLive(cmd);
}

function createServiceUser() {
  try {
    run(`id ${SERVICE_USER}`);
  } catch {
    console.log(yellow(`Creating service user: ${SERVICE_USER}`));
    run(`useradd --system --home-dir ${INSTALL_DIR} --shell /usr/sbin/nologin ${SERVICE_USER}`);
  }
}

function buildBinaries(repoRoot) {
  console.log(cyan('Building Rust proxy...'));
  try {
    run(`cd ${repoRoot}/rust && cargo build --release 2>&1 | tail -20`);
  } catch (e) {
    console.log(yellow(`Rust build failed: ${e.message}`));
  }

  console.log(cyan('Building Go API...'));
  try {
    run(`cd ${repoRoot}/go && CGO_ENABLED=1 go build -o ${INSTALL_DIR}/build/trakshya-api ./cmd/trakshya-api/ 2>&1`);
  } catch (e) {
    console.log(yellow(`Go build failed: ${e.message}`));
  }

  run(`mkdir -p ${INSTALL_DIR}/build`);
  if (fs.existsSync(path.join(repoRoot, 'rust/target/release/krsna-proxy'))) {
    run(`install -m 0755 ${repoRoot}/rust/target/release/krsna-proxy ${INSTALL_DIR}/build/trakshya-proxy`);
  }
}

function writeEnv() {
  const apiKey = generateApiKey();
  const env = `TRAKSHYA_MGMT_PORT=8000
TRAKSHYA_PROXY_PORT=8080
TRAKSHYA_FRONTEND_DIR=${INSTALL_DIR}/frontend
TRAKSHYA_DB_PATH=${INSTALL_DIR}/data/trakshya.db
TRAKSHYA_API_KEY=${apiKey}
RUST_LOG=info
NODE_ENV=production
`;
  fs.writeFileSync(path.join(INSTALL_DIR, '.env'), env, { mode: 0o600 });
  console.log(green(`Generated .env with API key: ${apiKey}`));
}

function generateApiKey() {
  const crypto = require('crypto');
  return crypto.randomBytes(32).toString('hex');
}

function writeSystemdUnits() {
  const dashboardUnit = `[Unit]
Description=TRAKSHYA WAF Dashboard
After=network.target

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${INSTALL_DIR}/.env
ExecStartPre=${INSTALL_DIR}/scripts/generate-dev-certs.sh
ExecStart=/usr/bin/node server.js
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`;

  const proxyUnit = `[Unit]
Description=TRAKSHYA WAF Proxy
After=network.target

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${INSTALL_DIR}/.env
ExecStart=${INSTALL_DIR}/build/trakshya-proxy
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`;

  const apiUnit = `[Unit]
Description=TRAKSHYA WAF Management API
After=network.target

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}
EnvironmentFile=${INSTALL_DIR}/.env
ExecStart=${INSTALL_DIR}/build/trakshya-api
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
`;

  fs.writeFileSync('/etc/systemd/system/trakshya-dashboard.service', dashboardUnit);
  fs.writeFileSync('/etc/systemd/system/trakshya-proxy.service', proxyUnit);
  fs.writeFileSync('/etc/systemd/system/trakshya-api.service', apiUnit);
}

function deployFiles(repoRoot) {
  console.log(cyan('Deploying files...'));
  run(`mkdir -p ${INSTALL_DIR}/logs ${INSTALL_DIR}/data ${INSTALL_DIR}/scripts`);
  run(`cp -a ${repoRoot}/server.js ${repoRoot}/package.json ${INSTALL_DIR}/`);
  run(`cp -a ${repoRoot}/frontend ${INSTALL_DIR}/`);
  run(`cp -a ${repoRoot}/landing ${INSTALL_DIR}/`);
  run(`cp -a ${repoRoot}/config ${INSTALL_DIR}/`);
  run(`cp -a ${repoRoot}/scripts/generate-dev-certs.sh ${INSTALL_DIR}/scripts/`);
  run(`cp -a ${repoRoot}/dev-certs ${INSTALL_DIR}/ 2>/dev/null || true`);
}

function enableAndStart() {
  console.log(cyan('Enabling services...'));
  run('systemctl daemon-reload');
  run('systemctl enable trakshya-dashboard trakshya-proxy trakshya-api');
  console.log(cyan('Starting services...'));
  run('systemctl restart trakshya-dashboard trakshya-proxy trakshya-api');
}

function showStatus() {
  try {
    const out = run('systemctl status trakshya-dashboard trakshya-proxy trakshya-api --no-pager');
    console.log(out);
  } catch (e) {
    console.log(yellow(`systemd status failed: ${e.message}`));
  }
}

function showLogs(service) {
  const target = service ? `trakshya-${service}` : 'trakshya-dashboard trakshya-proxy trakshya-api';
  runLive(`journalctl -u ${target} -f`);
}

async function installSystemd(repoRoot) {
  console.log(green('Installing TRAKSHYA WAF in SYSTEMD mode...'));
  console.log(yellow('This requires root privileges. Run with sudo.'));

  if (os.userInfo().username !== 'root') {
    throw new Error('systemd mode must be run with sudo');
  }

  createServiceUser();
  installDependencies();
  deployFiles(repoRoot);
  buildBinaries(repoRoot);
  writeEnv();
  writeSystemdUnits();
  enableAndStart();
  showStatus();

  console.log(green('\n Installation complete.'));
  console.log(` Dashboard:    http://localhost:${DASHBOARD_PORT}`);
  console.log(` Proxy:        http://localhost:${PROXY_PORT}`);
  console.log(` API:          http://localhost:${API_PORT}`);
  console.log(` Logs:         journalctl -u trakshya-dashboard -f`);
  console.log(` Config:       ${INSTALL_DIR}/.env`);
  console.log(`\n Production note: see deploy/PRODUCTION.md`);
}

function installLocal(repoRoot) {
  console.log(green('Installing TRAKSHYA WAF in LOCAL mode...'));
  const binDir = path.join(os.homedir(), '.local', 'bin');
  const binPath = path.join(binDir, 'trakshya-waf');
  fs.mkdirSync(binDir, { recursive: true });

  const launcher = `#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="${repoRoot}"
DASHBOARD_PORT=${DASHBOARD_PORT}
PROXY_PORT=${PROXY_PORT}
RUST_BIN="\\$REPO_ROOT/rust/target/release/krsna-proxy"

echo "Starting TRAKSHYA WAF..."
cd "\$REPO_ROOT"
[ -f "\$REPO_ROOT/scripts/trakshya-ascii.sh" ] && bash "\$REPO_ROOT/scripts/trakshya-ascii.sh" || true

cleanup() {
  [ -n "\${DASHBOARD_PID:-}" ] && kill "\$DASHBOARD_PID" 2>/dev/null || true
  [ -n "\${PROXY_PID:-}" ] && kill "\$PROXY_PID" 2>/dev/null || true
}
trap cleanup EXIT

if [ -x "\$RUST_BIN" ]; then
  echo "  [proxy] http://localhost:\$PROXY_PORT"
  "\$RUST_BIN" --port "\$PROXY_PORT" &
  PROXY_PID=\$!
fi

if command -v node >/dev/null 2>&1; then
  echo "  [dashboard] http://localhost:\$DASHBOARD_PORT"
  node server.js &
  DASHBOARD_PID=\$!
else
  echo "Node.js not found; cannot start dashboard."
  exit 1
fi

echo "Press Ctrl+C to stop."
wait
`;

  fs.writeFileSync(binPath, launcher, { mode: 0o755 });
  console.log(green(`Installed launcher: ${binPath}`));
  console.log(green('Run: trakshya-waf'));
}

function uninstall() {
  console.log(yellow('Uninstalling TRAKSHYA WAF...'));
  try {
    run('systemctl stop trakshya-dashboard trakshya-proxy trakshya-api');
    run('systemctl disable trakshya-dashboard trakshya-proxy trakshya-api');
  } catch {
    console.log(yellow('systemd services not running or unavailable.'));
  }

  const unitPaths = [
    '/etc/systemd/system/trakshya-dashboard.service',
    '/etc/systemd/system/trakshya-proxy.service',
    '/etc/systemd/system/trakshya-api.service',
  ];
  unitPaths.forEach((p) => {
    if (fs.existsSync(p)) {
      fs.unlinkSync(p);
    }
  });

  try {
    run('systemctl daemon-reload');
  } catch {
    // ignore if not root
  }

  if (fs.existsSync(INSTALL_DIR)) {
    run(`rm -rf ${INSTALL_DIR}`);
    console.log(green(`Removed ${INSTALL_DIR}`));
  }

  const binPath = path.join(BIN_DIR, 'trakshya-waf');
  if (fs.existsSync(binPath)) {
    fs.unlinkSync(binPath);
    console.log(green(`Removed ${binPath}`));
  }

  console.log(green('Uninstall complete.'));
}

function doctor() {
  console.log(cyan('Running TRAKSHYA WAF diagnostics...'));
  const checks = [
    { label: 'Node.js', cmd: 'node --version' },
    { label: 'npm', cmd: 'npm --version' },
    { label: 'cargo', cmd: 'cargo --version' },
    { label: 'go', cmd: 'go version' },
    { label: 'nginx', cmd: 'nginx -v 2>&1' },
    { label: 'curl', cmd: 'curl --version' },
    { label: 'install dir', test: () => fs.existsSync(INSTALL_DIR) },
    { label: 'proxy binary', test: () => fs.existsSync(path.join(INSTALL_DIR, 'build/trakshya-proxy')) },
    { label: 'api binary', test: () => fs.existsSync(path.join(INSTALL_DIR, 'build/trakshya-api')) },
    { label: 'env file', test: () => fs.existsSync(path.join(INSTALL_DIR, '.env')) },
    { label: 'dev certs', test: () => fs.existsSync(path.join(INSTALL_DIR, 'dev-certs', 'localhost.crt')) },
  ];

  checks.forEach((check) => {
    let ok = false;
    let detail = '';
    if (check.cmd) {
      try {
        detail = run(check.cmd);
        ok = true;
      } catch {
        ok = false;
        detail = 'missing';
      }
    } else if (typeof check.test === 'function') {
      ok = check.test();
      detail = ok ? 'present' : 'missing';
    }
    console.log(`${ok ? green('✔') : red('✖')} ${check.label}: ${detail}`);
  });

  console.log(cyan('Diagnostics complete.'));
}

async function update() {
  console.log(cyan('Updating TRAKSHYA WAF...'));
  const repoRoot = path.resolve(__dirname, '..', '..');
  try {
    run(`cd ${repoRoot} && git pull --rebase`);
    console.log(green('Updated source. Re-run install if needed.'));
  } catch (e) {
    console.log(red(`Update failed: ${e.message}`));
  }
}

function startServices() {
  console.log(cyan('Starting services...'));
  runLive('systemctl start trakshya-dashboard trakshya-proxy trakshya-api');
  showStatus();
}

function stopServices() {
  console.log(yellow('Stopping services...'));
  run('systemctl stop trakshya-dashboard trakshya-proxy trakshya-api');
}

function main() {
  const args = process.argv.slice(2);
  const command = args[0] || 'help';

  const modeIndex = args.indexOf('--mode');
  const mode = modeIndex !== -1 ? args[modeIndex + 1] : 'systemd';
  const userIndex = args.indexOf('--user');
  const serviceUser = userIndex !== -1 ? args[userIndex + 1] : SERVICE_USER;
  const repoRoot = path.resolve(__dirname, '..', '..');

  switch (command) {
    case 'install':
      if (mode === 'docker') {
        console.log(yellow('Docker mode selected. Use: docker compose -f docker-compose.stack.yml up -d --build'));
        process.exit(0);
      }
      if (mode === 'systemd') {
        installSystemd(path.resolve(repoRoot));
      } else {
        installLocal(path.resolve(repoRoot));
      }
      break;
    case 'uninstall':
      uninstall();
      break;
    case 'start':
      startServices();
      break;
    case 'stop':
      stopServices();
      break;
    case 'restart':
      stopServices();
      startServices();
      break;
    case 'status':
      showStatus();
      break;
    case 'logs':
      showLogs(args[1]);
      break;
    case 'doctor':
      doctor();
      break;
    case 'update':
      update();
      break;
    case 'help':
    case '--help':
    case '-h':
      usage(0);
      break;
    default:
      console.error(red(`Unknown command: ${command}`));
      usage(1);
  }
}

main();
