// Particles
function initParticles(){
  const c=document.getElementById('particle-canvas'),x=c.getContext('2d');
  let w,h,p=[];
  function rs(){w=c.width=window.innerWidth;h=c.height=window.innerHeight}
  rs();window.addEventListener('resize',rs);
  for(let i=60;i--;)p.push({x:Math.random()*w,y:Math.random()*h,vx:(Math.random()-.5)*.2,vy:(Math.random()-.5)*.2,s:Math.random()*1.5+.5,c:Math.random()>.5?'rgba(255,41,117,':'rgba(0,240,255,'});
  function dr(){x.clearRect(0,0,w,h);p.forEach(function(q){q.x+=q.vx;q.y+=q.vy;if(q.x<0)q.x=w;if(q.x>w)q.x=0;if(q.y<0)q.y=h;if(q.y>h)q.y=0;x.beginPath();x.arc(q.x,q.y,q.s,0,Math.PI*2);x.fillStyle=q.c+'.35)';x.fill()});requestAnimationFrame(dr)}
  dr()
}

// Terminal typing
function initTerminal(){
  const el=document.getElementById('hero-terminal'),code=el.querySelector('code');
  const lines=[
    {t:'[12:00:01] DETECTED SQLi from 192.168.1.23 — BLOCKED',c:'line-blocked'},
    {t:'[12:00:03] DETECTED XSS probe from 10.0.0.45 — BLOCKED',c:'line-blocked'},
    {t:'[12:00:05] ALLOW GET /index.html — PASS',c:'line-allow'},
    {t:'[12:00:08] ALERT Port scan from 10.0.0.1 — RATE LIMITED',c:'line-alert'},
    {t:'[12:00:12] DETECTED JNDI lookup ldap://malicious — BLOCKED',c:'line-blocked'},
    {t:'[12:00:15] DETECTED CRLF injection in /api/login — BLOCKED',c:'line-blocked'},
    {t:'[12:00:18] ALLOW POST /api/auth — PASS',c:'line-allow'}
  ];
  let i=0,ch=0,run=true;
  function ty(){
    if(!run)return;
      if(i>=lines.length){setTimeout(function(){i=0;ch=0;code.innerHTML='<span class="term-prompt">$</span> <span class="term-cmd">./trakshya --scan --upstream localhost:3000</span><span class="term-cursor"></span>';setTimeout(ty,1500)},4000);return}
    if(ch===0){var l=lines[i];code.innerHTML+='<span class="term-line '+l.c+'"></span>';code.querySelector('span:last-child').textContent=''}
    var sp=code.querySelectorAll('.term-line');
    if(sp.length){var cur=sp[sp.length-1];if(ch<lines[i].t.length){cur.textContent+=lines[i].t[ch];ch++;setTimeout(ty,25)}else{i++;ch=0;setTimeout(ty,400)}}
  }
  ty()
}

// Counters
function animateCounters(){
  const els=document.querySelectorAll('.stat-num[data-target]');
  if(!els.length)return;
  let done=false;
  function go(){
    if(done)return;done=true;
    els.forEach(function(el){
      const t=parseInt(el.dataset.target);if(isNaN(t))return;
      let c=0,st=Math.ceil(t/60);
      function up(){c+=st;if(c>t)c=t;el.textContent=c;if(c<t)setTimeout(up,25)}
      up()
    })
  }
  const ob=new IntersectionObserver(function(es){es.forEach(function(e){if(e.isIntersecting){go();ob.disconnect()}})},{threshold:.5});
  ob.observe(document.querySelector('.stats-bar'))
}

// Tilt
function initTilt(){
  document.querySelectorAll('[data-tilt]').forEach(function(c){
    c.addEventListener('mousemove',function(e){
      const r=c.getBoundingClientRect(),x=e.clientX-r.left,y=e.clientY-r.top;
      const mx=(x/r.width-.5)*8,my=(y/r.height-.5)*8;
      c.style.transform='perspective(600px) rotateX('+(-my)+'deg) rotateY('+mx+'deg)'
    });
    c.addEventListener('mouseleave',function(){c.style.transform='perspective(600px) rotateX(0) rotateY(0)'})
  })
}

// Carousel
function initCarousel(){
  const wrap=document.getElementById('carousel');
  if(!wrap)return;
  const track=wrap.querySelector('.carousel-track'),slides=track.querySelectorAll('.carousel-slide'),dots=wrap.querySelector('.carousel-dots');
  if(!slides.length)return;
  let idx=0,tmr;
  slides.forEach(function(s,i){const d=document.createElement('button');d.className='carousel-dot'+(i===0?' active':'');d.addEventListener('click',function(){go(i)});dots.appendChild(d)});
  function go(i){idx=i;track.style.transform='translateX(-'+(idx*100)+'%)';dots.querySelectorAll('.carousel-dot').forEach(function(d,j){d.className='carousel-dot'+(j===idx?' active':'')})}
  function ad(){tmr=setTimeout(function(){go((idx+1)%slides.length);ad()},4000)}
  ad();
  wrap.addEventListener('mouseenter',function(){clearTimeout(tmr)});
  wrap.addEventListener('mouseleave',ad)
}

// Scroll reveal
function observeSections(){
  document.querySelectorAll('.tl-entry,.feat-card').forEach(function(el){
    el.style.opacity='0';el.style.transform='translateY(24px)';el.style.transition='opacity .6s ease, transform .6s ease'
  });
  const obs=new IntersectionObserver(function(es){es.forEach(function(e){if(e.isIntersecting){e.target.classList.add('visible');obs.unobserve(e.target)}})},{threshold:.1});
  document.querySelectorAll('.tl-entry,.feat-card').forEach(function(el,i){setTimeout(function(){obs.observe(el)},i*80)})
}

// OS tabs
function switchOS(btn){
  const sel=btn.closest('#install');
  sel.querySelectorAll('.os-btn').forEach(function(b){b.classList.remove('active')});
  btn.classList.add('active');
  sel.querySelectorAll('.os-pane').forEach(function(p){p.classList.remove('active')});
  const p=sel.querySelector('[data-pane="'+btn.dataset.os+'"]');if(p)p.classList.add('active')
}
function detectOS(){const u=navigator.userAgent.toLowerCase();if(u.includes('win'))return'windows';if(u.includes('mac'))return'mac';return'linux'}
function initOS(){const os=detectOS();const btn=document.querySelector('.os-btn[data-os="'+os+'"]');if(btn)switchOS(btn)}

// Copy
function copyTerm(btn){
  const lines=btn.closest('.term-body').querySelectorAll('.os-pane.active .term-line .tc,.os-pane.active .term-line .to');
  let t='';
  lines.forEach(function(l){t+=l.textContent+'\n'});
  navigator.clipboard.writeText(t.trim()).then(function(){btn.textContent='Copied!';btn.classList.add('copied');setTimeout(function(){btn.textContent='Copy';btn.classList.remove('copied')},2000)}).catch(function(){btn.textContent='Copy'})
}

// Mobile nav
function toggleNav(){document.querySelector('.nav-links').classList.toggle('open')}

// Init
document.addEventListener('DOMContentLoaded',function(){
  initParticles();
  setTimeout(initTerminal,500);
  animateCounters();
  initTilt();
  initCarousel();
  observeSections();
  initOS();
  document.querySelectorAll('.nav-links a').forEach(function(a){a.addEventListener('click',function(){document.querySelector('.nav-links').classList.remove('open')})})
})
