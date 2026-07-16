#!/usr/bin/env node
const { execSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const os = require('os');

function usage() {
  console.log(`
TRAKSHYA WAF CLI

Usage:
  trakshya-waf-cli <command> [options]
  trakshya-waf-cli --help

Commands:
  start          Start the WAF stack
  stop           Stop the WAF stack
  restart        Restart the WAF stack
  status         Show running services
  ps             Alias for status
  logs [svc]     Tail logs for a service
  scan           Run local vulnerability scan
  test           Run regression tests
  certs          Generate local dev certs
  help           Show this help message

Compose hints:
  - Uses docker-compose.stack.yml when present.
  - Falls back to docker-compose.yml otherwise.
`);
}

function resolveComposeFile() {
  const cwd = process.cwd();
  const stackFile = path.join(cwd, 'docker-compose.stack.yml');
  const localFile = path.join(cwd, 'docker-compose.yml');
  if (fs.existsSync(stackFile)) {
    return ['-f', stackFile];
  }
  if (fs.existsSync(localFile)) {
    return ['-f', localFile];
  }
  throw new Error('missing docker-compose.yml or docker-compose.stack.yml');
}

function compose(...args) {
  const file = resolveComposeFile();
  const cmd = 'docker compose ' + [...file, ...args].join(' ');
  try {
    return execSync(cmd, { encoding: 'utf8', stdio: 'pipe' }).trim();
  } catch (e) {
    const out = (e.stdout?.toString() || '') + (e.stderr?.toString() || '');
    throw new Error(out || e.message);
  }
}

function start() {
  console.log('Starting TRAKSHYA WAF...');
  try {
    compose('up', '-d', '--build');
  } catch (e) {
    console.error('Start failed:', e.message);
    process.exitCode = 1;
    return;
  }
  status();
}

function stop() {
  console.log('Stopping TRAKSHYA WAF...');
  try {
    compose('down');
  } catch (e) {
    console.error('Stop failed:', e.message);
    process.exitCode = 1;
  }
}

function restart() {
  stop();
  start();
}

function status() {
  try {
    console.log(compose('ps'));
  } catch (e) {
    console.error('Status failed:', e.message);
    process.exitCode = 1;
  }
}

function logs(svc = '') {
  const target = svc || '';
  try {
    console.log(compose('logs', '--tail=100', ...(target ? [target] : [])));
  } catch (e) {
    console.error('Logs failed:', e.message);
    process.exitCode = 1;
  }
}

function scan() {
  console.log('Running local scan...');
  const script = path.join(__dirname, '..', 'scripts', 'regression.py');
  if (!fs.existsSync(script)) {
    console.error('Missing regression script:', script);
    process.exitCode = 1;
    return;
  }
  const child = spawn('python3', [script], { stdio: 'inherit' });
  child.on('exit', (code) => {
    if (code !== 0) process.exitCode = 1;
  });
}

function test() {
  scan();
}

function certs() {
  const script = path.join(__dirname, '..', 'scripts', 'generate-dev-certs.sh');
  if (!fs.existsSync(script)) {
    console.error('Missing cert script:', script);
    process.exitCode = 1;
    return;
  }
  try {
    execSync('bash ' + script, { stdio: 'inherit' });
  } catch (e) {
    console.error('Cert generation failed:', e.message);
    process.exitCode = 1;
  }
}

function helpCommand() {
  usage();
}

const cmd = (process.argv[2] || 'help').toLowerCase();
const arg = process.argv[3];

switch (cmd) {
  case 'start':
    start();
    break;
  case 'stop':
    stop();
    break;
  case 'restart':
    restart();
    break;
  case 'status':
  case 'ps':
    status();
    break;
  case 'logs':
    logs(arg);
    break;
  case 'scan':
    scan();
    break;
  case 'test':
    test();
    break;
  case 'certs':
    certs();
    break;
  case 'help':
  case '--help':
  case '-h':
    helpCommand();
    break;
  default:
    console.error('Unknown command:', cmd);
    usage();
    process.exitCode = 1;
    break;
}
