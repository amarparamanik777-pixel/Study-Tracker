/* Study Squad: code-based friend requests + shared progress (Firebase Realtime Database over REST) */
(function(){
'use strict';
var C=window.FB_CONFIG||{}, DB=(C.databaseURL||'').replace(/\/+$/,''), KEY=C.apiKey||'', ON=!!(DB&&KEY);
var LS='sl_squad_v1', me={}, idTok='', tokExp=0, reqs=[], mem={}, tab='today', isOpen=false, busy=false, err='', editing=false, seen=0;
try{ me=JSON.parse(localStorage.getItem(LS)||'{}')||{}; }catch(e){ me={}; }
var EM=['🦊','🐼','🦁','🐯','🐸','🦉','🐙','🦄','🐧','🐲','🚀','⚡'], pick=me.emoji||EM[0];
var AL='ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function $(i){ return document.getElementById(i); }
function save(){ try{ localStorage.setItem(LS,JSON.stringify(me)); }catch(e){} }
function say(m){ try{ showToast(m,3200); }catch(e){} }
function rnd(n){ var a=new Uint32Array(n), s=''; crypto.getRandomValues(a); for(var i=0;i<n;i++) s+=AL[a[i]%AL.length]; return s; }
function fm(m){ m=Math.round(m||0); var h=Math.floor(m/60); return h?h+'h '+(m%60)+'m':m+'m'; }
function ago(t){ var s=(Date.now()-t)/1000; if(s<90) return 'just now'; if(s<3600) return Math.round(s/60)+'m ago'; if(s<86400) return Math.round(s/3600)+'h ago'; return Math.round(s/86400)+'d ago'; }
function post(u,t,b){ return fetch(u,{method:'POST',headers:{'Content-Type':t},body:b}).then(function(r){ return r.json(); }); }

/* ---- auth (anonymous, REST) + database ---- */
async function tok(){
  if(idTok&&Date.now()<tokExp-60000) return idTok;
  var r;
  if(me.refresh){
    r=await post('https://securetoken.googleapis.com/v1/token?key='+KEY,'application/x-www-form-urlencoded','grant_type=refresh_token&refresh_token='+encodeURIComponent(me.refresh));
    if(r.id_token){ idTok=r.id_token; tokExp=Date.now()+(+r.expires_in)*1000; me.refresh=r.refresh_token; save(); return idTok; }
  }
  r=await post('https://identitytoolkit.googleapis.com/v1/accounts:signUp?key='+KEY,'application/json','{"returnSecureToken":true}');
  if(!r.idToken) throw new Error((r.error&&r.error.message)||'auth');
  idTok=r.idToken; tokExp=Date.now()+(+r.expiresIn)*1000;
  me={name:me.name,emoji:me.emoji,uid:r.localId,refresh:r.refreshToken}; save(); return idTok;
}
async function db(m,p,b){
  var t=await tok(), r=await fetch(DB+'/'+p+'.json?auth='+t,{method:m,body:b===undefined?undefined:JSON.stringify(b)});
  if(!r.ok){ var e=new Error('http '+r.status); e.status=r.status; throw e; }
  return r.json();
}
function explain(e){
  var m=String(e&&e.message||e);
  if(/ADMIN_ONLY|OPERATION_NOT_ALLOWED/.test(m)) return 'Anonymous sign-in is off. Turn it on in Firebase (SETUP step 4).';
  if(e&&(e.status===401||e.status===403)) return 'Permission denied. Publish the rules from SETUP step 3.';
  if(/API.?KEY|INVALID_KEY/i.test(m)) return 'The apiKey in firebase-config.js is not valid.';
  if(/Failed to fetch|NetworkError|Load failed/i.test(m)) return 'No connection. Showing the last squad data.';
  return 'Squad sync failed ('+m+').';
}

/* ---- my progress, read from the app's own sessions ---- */
function mine(){
  var td=todayStr(), d=new Date(); d.setDate(d.getDate()-((d.getDay()+6)%7)); var ws=fmtDate(d), t=0, w=0, a=0;
  var live=timer.phase==='running'&&!timer.isBreak, x=live?Math.floor(timer.elapsedSec/60):0, sb=live&&subjectById(activeSubjectId);
  state.sessions.forEach(function(s){ var m=s.durationMin||0, k=fmtDate(s.start); a+=m; if(k===td) t+=m; if(k>=ws) w+=m; });
  return {n:me.name,e:me.emoji,d:td,td:t+x,wk:w+x,at:a+x,st:calcStreak(),lv:live?Date.now()-timer.elapsedSec*1000:0,sb:sb?sb.name:'',u:Date.now()};
}

/* ---- sync ---- */
async function mkCode(){
  for(var i=0;i<6;i++){
    var c=rnd(6);
    try{ await db('PUT','codes/'+c,me.uid); await db('PUT','users/'+me.uid+'/code',c); me.code=c; save(); return; }
    catch(e){ if(e.status!==401) throw e; }
  }
  var x=new Error('code'); x.status=401; throw x;
}
async function sync(){
  if(!ON||busy||!me.name) return; busy=true;
  try{
    await tok();
    if(!me.code) await mkCode();
    var rq=(await db('GET','reqs/'+me.uid))||{}, g=(await db('GET','users/'+me.uid+'/grp'))||null;
    reqs=Object.keys(rq).map(function(k){ var v=rq[k]; v.uid=k; return v; });
    if(g!==(me.grp||null)){ if(g&&!me.grp) say('You joined a squad 🎉'); me.grp=g; save(); }
    if(me.grp){ await db('PUT','groups/'+me.grp+'/m/'+me.uid,mine()); mem=(await db('GET','groups/'+me.grp+'/m'))||{}; } else mem={};
    if(reqs.length>seen){ say('New squad request 👋'); try{ navigator.vibrate&&navigator.vibrate(60); }catch(e){} }
    seen=reqs.length; err='';
  }catch(e){ err=explain(e); }
  busy=false; badge(); paint();
}

/* ---- actions ---- */
async function addCode(){
  var c=($('frIn').value||'').toUpperCase().replace(/[^A-Z0-9]/g,'');
  if(c.length!==6) return say('Enter the 6-character code');
  if(c===me.code) return say("That's your own code");
  if(me.grp) return say("You're already in a squad. Ask your friend to enter your code instead.");
  try{
    var u=await db('GET','codes/'+c);
    if(!u) return say('No one has that code');
    await db('PUT','reqs/'+u+'/'+me.uid,{n:me.name,e:me.emoji,t:Date.now()});
    $('frIn').value=''; say("Request sent. You'll join once they accept.");
  }catch(e){ say(explain(e)); }
}
async function accept(uid){
  try{
    var g=me.grp, up={};
    if(!g){ g=rnd(14); up['users/'+me.uid+'/grp']=g; }
    up['users/'+uid+'/grp']=g; up['reqs/'+me.uid+'/'+uid]=null;
    await db('PATCH','',up); me.grp=g; save(); say('Added to your squad 🎉');
  }catch(e){ say(e.status===401?'Could not add them. They may already be in a squad.':explain(e)); }
  sync();
}
async function decline(uid){ try{ await db('DELETE','reqs/'+me.uid+'/'+uid); }catch(e){ say(explain(e)); } sync(); }
async function leave(){
  if(!confirm('Leave your squad? You will stop sharing progress with them.')) return;
  try{
    var up={}; up['groups/'+me.grp+'/m/'+me.uid]=null; up['users/'+me.uid+'/grp']=null;
    await db('PATCH','',up); me.grp=null; mem={}; save(); say('You left the squad');
  }catch(e){ say(explain(e)); }
  paint();
}
function link(){ return location.href.split('#')[0].split('?')[0]+'?add='+me.code; }
function copy(t){ (navigator.clipboard?navigator.clipboard.writeText(t):Promise.reject()).then(function(){ say('Copied'); },function(){ say('Copy failed'); }); }
function share(){
  var t='Join my Study Squad on Study Log. My code: '+me.code;
  if(navigator.share) navigator.share({title:'Study Squad',text:t,url:link()}).catch(function(){}); else copy(t+' '+link());
}

/* ---- UI ---- */
function badge(){
  var n=reqs.length, b=$('frBadge'), m=$('menuBtn');
  if(b){ b.textContent=n; b.style.display=n?'inline-block':'none'; }
  if(m) m.classList.toggle('fr-has',n>0);
}
function ems(){ $('frEm').innerHTML=EM.map(function(x){ return '<button data-e="'+x+'" class="'+(x===pick?'on':'')+'">'+x+'</button>'; }).join(''); }
function board(){
  if(!me.grp) return '<div class="fr-card"><h3>No squad yet</h3><p class="fr-note">Share your code, or enter a friend\'s code above. When they accept, you both land in the same squad and see each other\'s progress.</p></div>';
  mem[me.uid]=mine();
  var td=todayStr(), d=new Date(); d.setDate(d.getDate()-((d.getDay()+6)%7)); d.setHours(0,0,0,0); var w0=d.getTime(), now=Date.now(), sum=0, liveN=0;
  var list=Object.keys(mem).map(function(k){
    var e=mem[k], v=tab==='today'?(e.d===td?e.td:0):tab==='week'?(e.u>=w0?e.wk:0):e.at, lv=e.lv&&now-e.u<150000;
    sum+=v||0; if(lv) liveN++; return {id:k,e:e,v:v||0,lv:lv};
  }).sort(function(a,b){ return b.v-a.v; });
  var max=Math.max(1,list[0].v);
  var rows=list.map(function(x,i){
    var e=x.e, medal=x.v>0&&i<3?['🥇','🥈','🥉'][i]:(i+1);
    return '<div class="fr-row'+(x.id===me.uid?' me':'')+(i===0&&x.v>0?' top':'')+'"><div class="fr-rk">'+medal+'</div><div class="fr-av">'+esc(e.e)+'</div><div class="fr-mid"><div class="fr-nm">'+esc(e.n)+(x.id===me.uid?'<i>you</i>':'')+(e.st>1?'<b>🔥 '+e.st+'</b>':'')+'</div><div class="fr-bar"><span style="width:'+(x.v?Math.max(4,x.v/max*100):0)+'%"></span></div><div class="fr-sub">'+(x.lv?'<span class="fr-live">LIVE</span> '+esc(e.sb||'Studying')+' · '+fm((now-e.lv)/60000):'Active '+ago(e.u))+'</div></div><div class="fr-val">'+fm(x.v)+'</div></div>';
  }).join('');
  var tabs=[['today','Today'],['week','This week'],['all','All time']].map(function(t){ return '<button data-t="'+t[0]+'" class="'+(tab===t[0]?'on':'')+'">'+t[1]+'</button>'; }).join('');
  return '<div class="fr-tabs">'+tabs+'</div><div class="fr-sum"><span>Squad total <b>'+fm(sum)+'</b></span><span>'+(liveN?liveN+' studying now':'Nobody live')+'</span></div>'+rows+'<button class="fr-btn g fr-leave" data-a="leave">Leave squad</button>';
}
function paint(){
  if(!$('frPage')) return;
  var onb=ON&&(!me.name||editing), main=ON&&me.name&&!editing;
  $('frSetup').style.display=ON?'none':'block'; $('frOnb').style.display=onb?'block':'none'; $('frMain').style.display=main?'block':'none';
  $('frErr').textContent=err; $('frErr').style.display=err&&ON?'block':'none';
  if(onb) ems();
  if(!main) return;
  $('frMe').textContent=(me.emoji||'')+' '+me.name; $('frCode').textContent=me.code||'······';
  $('frReq').innerHTML=reqs.map(function(r){
    return '<div class="fr-card fr-rq"><div class="fr-av">'+esc(r.e)+'</div><div class="fr-mid"><div class="fr-nm">'+esc(r.n)+'</div><div class="fr-sub">wants to join your squad</div></div><button class="fr-btn" data-a="ok" data-u="'+esc(r.uid)+'">Accept</button><button class="fr-btn g" data-a="no" data-u="'+esc(r.uid)+'">✕</button></div>';
  }).join('');
  $('frBoard').innerHTML=board();
}
function openPage(){ isOpen=true; $('frPage').classList.add('open'); paint(); sync(); }
function closePage(){ isOpen=false; $('frPage').classList.remove('open'); }

function build(){
  var st=document.createElement('style');
  st.textContent='.fr-page{position:fixed;inset:0;z-index:200;background:var(--bg);display:none;overflow-y:auto;-webkit-overflow-scrolling:touch}.fr-page.open{display:block}.fr-shell{max-width:440px;margin:0 auto;padding:0 16px 40px}.fr-head{display:flex;align-items:center;gap:10px;padding:18px 0 14px;position:sticky;top:0;background:var(--bg);z-index:2}.fr-head h2{flex:1;margin:0;font:700 20px Bitter,serif}.fr-ib{width:36px;height:36px;border-radius:10px;background:var(--surface);border:1px solid var(--border-strong);color:var(--text-2);cursor:pointer;font-size:16px}.fr-card{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:16px;margin-bottom:14px}.fr-card h3{margin:0 0 4px;font:700 16px Bitter,serif}.fr-note{font-size:13px;color:var(--text-2);line-height:1.5;margin:6px 0 10px}.fr-err{background:var(--danger-dim);color:var(--danger);border-radius:12px;padding:10px 12px;font-size:13px;margin-bottom:12px}'
  +'.fr-code{position:relative;text-align:center;padding:20px 16px 18px;border-radius:22px;border:1px solid #5a4524;background:radial-gradient(120% 140% at 50% -20%,#5b4217 0%,#2a2118 48%,var(--surface) 85%);margin-bottom:14px}.fr-code small{color:var(--text-2);font-size:13px}.fr-ed{position:absolute;top:10px;right:10px;width:32px;height:32px;border-radius:9px;border:1px solid #5a4524;background:rgba(0,0,0,.25);color:var(--accent);cursor:pointer}.fr-cd{font:700 38px "IBM Plex Mono",monospace;letter-spacing:.28em;margin:8px 0 16px -.28em;color:var(--accent);text-shadow:0 0 26px rgba(232,163,61,.45)}.fr-btns,.fr-add{display:flex;gap:8px;justify-content:center}'
  +'.fr-btn{border:0;border-radius:12px;padding:11px 16px;font:600 14px Inter,sans-serif;background:var(--accent);color:#1a1206;cursor:pointer}.fr-btn.g{background:rgba(255,255,255,.08);color:var(--text)}.fr-card input{flex:1;min-width:0;background:var(--surface-2);border:1px solid var(--border-strong);border-radius:12px;padding:12px;color:var(--text);font:600 16px "IBM Plex Mono",monospace;letter-spacing:.2em;text-transform:uppercase}#frName{text-transform:none;letter-spacing:0;font:500 16px Inter,sans-serif}'
  +'.fr-ems{display:grid;grid-template-columns:repeat(6,1fr);gap:8px;margin:10px 0 12px}.fr-ems button{font-size:24px;padding:8px 0;border-radius:12px;border:2px solid transparent;background:var(--surface-2);cursor:pointer}.fr-ems button.on{border-color:var(--accent);background:var(--accent-dim)}'
  +'.fr-tabs{display:flex;background:var(--surface);border-radius:12px;padding:4px;margin:6px 0 10px}.fr-tabs button{flex:1;border:0;background:none;color:var(--text-2);padding:9px;border-radius:9px;font:600 13px Inter,sans-serif;cursor:pointer}.fr-tabs button.on{background:var(--surface-3);color:var(--text)}.fr-sum{display:flex;justify-content:space-between;font-size:12px;color:var(--text-2);margin:0 4px 10px}.fr-sum b{color:var(--accent);font-family:"IBM Plex Mono",monospace}'
  +'.fr-row,.fr-rq{display:flex;align-items:center;gap:10px}.fr-row{padding:12px 10px;border-radius:14px;margin-bottom:6px;background:var(--surface);border:1px solid transparent}.fr-row.me{border-color:var(--border-strong)}.fr-row.top{background:linear-gradient(90deg,#3a2f1e,var(--surface));border-color:#5a4524}.fr-rk{width:26px;text-align:center;font:600 15px "IBM Plex Mono",monospace;color:var(--text-3)}.fr-av{width:40px;height:40px;border-radius:50%;background:var(--surface-3);display:flex;align-items:center;justify-content:center;font-size:21px;flex:0 0 auto}.fr-mid{flex:1;min-width:0}'
  +'.fr-nm{font-weight:600;font-size:14px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.fr-nm i{font-style:normal;font-size:10px;color:var(--accent);margin-left:6px}.fr-nm b{font-size:11px;font-weight:600;color:var(--text-2);margin-left:8px}.fr-bar{height:5px;border-radius:5px;background:var(--surface-3);margin:6px 0 4px;overflow:hidden}.fr-bar span{display:block;height:100%;border-radius:5px;background:linear-gradient(90deg,#c98a2a,var(--accent))}.fr-sub{font-size:11px;color:var(--text-3)}.fr-val{font:600 14px "IBM Plex Mono",monospace;text-align:right;min-width:60px}'
  +'.fr-live{color:var(--success);font-weight:700;font-size:10px;letter-spacing:.06em}.fr-live:before{content:"";display:inline-block;width:7px;height:7px;border-radius:50%;background:var(--success);margin-right:5px;animation:frp 1.4s infinite}@keyframes frp{50%{opacity:.25}}@media(prefers-reduced-motion:reduce){.fr-live:before{animation:none}}.fr-leave{width:100%;margin-top:12px}'
  +'.fr-badge{margin-left:auto;background:var(--danger);color:#fff;border-radius:10px;font-size:11px;font-weight:700;padding:1px 7px}#menuBtn.fr-has{position:relative}#menuBtn.fr-has:after{content:"";position:absolute;top:4px;right:4px;width:9px;height:9px;border-radius:50%;background:var(--danger)}';
  document.head.appendChild(st);
  var p=document.createElement('div'); p.id='frPage'; p.className='fr-page';
  p.innerHTML='<div class="fr-shell"><div class="fr-head"><button class="fr-ib" id="frBack" aria-label="Back">←</button><h2>Study Squad</h2><button class="fr-ib" id="frSync" aria-label="Refresh">↻</button></div>'
  +'<div id="frErr" class="fr-err" style="display:none"></div>'
  +'<div id="frSetup" class="fr-card" style="display:none"><h3>One-time setup needed</h3><p class="fr-note">Squads use a free Firebase database so friends can see each other. Follow SETUP.md (about 5 minutes), paste two values into firebase-config.js, then upload the files again.</p></div>'
  +'<div id="frOnb" class="fr-card" style="display:none"><h3>Choose your look</h3><p class="fr-note">Your squad sees this name and emoji.</p><div id="frEm" class="fr-ems"></div><div class="fr-add"><input id="frName" maxlength="16" placeholder="Your name" autocomplete="off"><button class="fr-btn" id="frSave">Save</button></div></div>'
  +'<div id="frMain" style="display:none"><div class="fr-code"><button class="fr-ed" id="frEdit" aria-label="Edit profile">✎</button><small id="frMe"></small><div class="fr-cd" id="frCode"></div><div class="fr-btns"><button class="fr-btn" id="frShare">Share invite</button><button class="fr-btn g" id="frCopy">Copy code</button></div></div>'
  +'<div class="fr-card"><p class="fr-note" style="margin-top:0">Got a friend\'s code?</p><div class="fr-add"><input id="frIn" maxlength="6" placeholder="ABC123" autocapitalize="characters" autocomplete="off"><button class="fr-btn" id="frGo">Send request</button></div></div>'
  +'<div id="frReq"></div><div id="frBoard"></div></div></div>';
  document.body.appendChild(p);
  $('frBack').onclick=closePage; $('frSync').onclick=function(){ say('Refreshing…'); sync(); };
  $('frEm').onclick=function(e){ var b=e.target.closest('button[data-e]'); if(b){ pick=b.dataset.e; ems(); } };
  $('frSave').onclick=function(){ me.name=($('frName').value||'').trim().slice(0,16)||'Student'; me.emoji=pick; editing=false; save(); paint(); sync(); };
  $('frEdit').onclick=function(){ editing=true; pick=me.emoji||EM[0]; $('frName').value=me.name||''; paint(); };
  $('frShare').onclick=function(){ if(me.code) share(); }; $('frCopy').onclick=function(){ if(me.code) copy(me.code); };
  $('frGo').onclick=addCode;
  $('frReq').onclick=function(e){ var b=e.target.closest('button[data-a]'); if(b) (b.dataset.a==='ok'?accept:decline)(b.dataset.u); };
  $('frBoard').onclick=function(e){
    var t=e.target.closest('button[data-t]'), a=e.target.closest('button[data-a]');
    if(t){ tab=t.dataset.t; paint(); } else if(a&&a.dataset.a==='leave') leave();
  };
}
function inject(){
  var dr=document.querySelector('#drawerBackdrop .drawer'); if(!dr||$('drawerSquadBtn')) return;
  var b=document.createElement('button'); b.className='drawer-item'; b.id='drawerSquadBtn';
  b.innerHTML='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c0-3.6 2.9-6 6.5-6s6.5 2.4 6.5 6"/><circle cx="17.5" cy="9" r="2.5"/><path d="M17 14c2.6 0 4.5 1.8 4.5 4.5"/></svg>Study Squad<span id="frBadge" class="fr-badge" style="display:none">0</span>';
  var t=dr.querySelector('.drawer-title'); dr.insertBefore(b,t.nextSibling);
  b.addEventListener('click',function(){ closeDrawer(); openPage(); });
}

build(); inject(); paint();
var q=new URLSearchParams(location.search).get('add');
if(q){ history.replaceState(null,'',location.pathname); setTimeout(function(){ openPage(); $('frIn').value=q.toUpperCase().replace(/[^A-Z0-9]/g,'').slice(0,6); },500); }
function sig(){ return timer.phase+(timer.isBreak?1:0)+'-'+state.sessions.length; }
var last=sig();
setInterval(function(){ var s=sig(); if(s!==last){ last=s; if(me.grp) sync(); } },4000);
document.addEventListener('visibilitychange',function(){ if(!document.hidden) sync(); });
(function loop(){ sync(); setTimeout(loop,isOpen?15000:60000); })();
})();
