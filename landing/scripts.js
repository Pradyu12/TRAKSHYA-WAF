// Particle background
function initParticles() {
  const canvas = document.createElement('canvas');
  canvas.id = 'particle-canvas';
  document.body.prepend(canvas);
  const ctx = canvas.getContext('2d');
  let w, h, particles = [];
  function resize() { w = canvas.width = window.innerWidth; h = canvas.height = window.innerHeight; }
  resize();
  window.addEventListener('resize', resize);
  for (let i = 0; i < 60; i++) {
    particles.push({
      x: Math.random() * w, y: Math.random() * h,
      vx: (Math.random() - 0.5) * 0.3, vy: (Math.random() - 0.5) * 0.3,
      size: Math.random() * 1.5 + 0.5,
      color: Math.random() > 0.5 ? 'rgba(255,41,117,' : 'rgba(0,240,255,'
    });
  }
  function draw() {
    ctx.clearRect(0, 0, w, h);
    particles.forEach(p => {
      p.x += p.vx; p.y += p.vy;
      if (p.x < 0) p.x = w; if (p.x > w) p.x = 0;
      if (p.y < 0) p.y = h; if (p.y > h) p.y = 0;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
      ctx.fillStyle = p.color + '0.4)';
      ctx.fill();
    });
    requestAnimationFrame(draw);
  }
  draw();
}

// Install tabs
function switchTab(group, tab) {
  const container = tab.closest('[data-tabs]') || tab.parentElement.parentElement;
  container.querySelectorAll('.install-tab').forEach(t => t.classList.remove('active'));
  container.querySelectorAll('.install-panel').forEach(p => p.classList.remove('active'));
  tab.classList.add('active');
  const panel = document.getElementById(tab.dataset.panel);
  if (panel) panel.classList.add('active');
}

// OS tabs
function switchOS(tab) {
  const container = tab.closest('.install-oneliner');
  container.querySelectorAll('.os-tab').forEach(t => t.classList.remove('active'));
  container.querySelectorAll('.os-panel').forEach(p => p.classList.remove('active'));
  tab.classList.add('active');
  const panel = document.getElementById('os-' + tab.dataset.os);
  if (panel) panel.classList.add('active');
}

function detectOS() {
  const ua = navigator.userAgent.toLowerCase();
  if (ua.includes('win')) return 'windows';
  if (ua.includes('mac') || ua.includes('iphone') || ua.includes('ipad')) return 'mac';
  return 'linux';
}

function selectOSTab(os) {
  const tabs = document.querySelectorAll('.os-tab');
  tabs.forEach(t => {
    if (t.dataset.os === os) {
      switchOS(t);
    }
  });
}

// Copy to clipboard
function copyCode(btn) {
  const code = btn.parentElement.querySelector('code') || btn.parentElement;
  const text = (code.textContent || code.innerText).trim();
  navigator.clipboard.writeText(text).then(() => {
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = 'Copy'; }, 2000);
  }).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = text; document.body.appendChild(ta); ta.select(); document.execCommand('copy');
    document.body.removeChild(ta);
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = 'Copy'; }, 2000);
  });
}

// Mobile nav toggle
function toggleMobileNav() {
  document.querySelector('.nav-links').classList.toggle('mobile-open');
}

// Intersection observer for feature cards
function observeCards() {
  const cards = document.querySelectorAll('.feature-card');
  const observer = new IntersectionObserver((entries) => {
    entries.forEach((entry, i) => {
      if (entry.isIntersecting) {
        entry.target.style.opacity = '1';
        entry.target.style.transform = 'translateY(0)';
      }
    });
  }, { threshold: 0.1 });
  cards.forEach((card, i) => {
    card.style.opacity = '0';
    card.style.transform = 'translateY(30px)';
    card.style.transition = `opacity 0.6s ease ${i * 0.1}s, transform 0.6s ease ${i * 0.1}s`;
    observer.observe(card);
  });
}

document.addEventListener('DOMContentLoaded', () => {
  initParticles();
  observeCards();
  selectOSTab(detectOS());
});

// GitHub stats
async function loadGitHubStats() {
  try {
    const res = await fetch('https://api.github.com/repos/Pradyu12/TRAKSHYA-WAF');
    if (!res.ok) return;
    const data = await res.json();
    const el = document.getElementById('github-stars');
    if (el && data.stargazers_count !== undefined) el.textContent = data.stargazers_count;
  } catch (e) {}
}
loadGitHubStats();
