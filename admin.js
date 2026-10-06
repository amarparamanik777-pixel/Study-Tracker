/* Study Log - Admin Block
   Opens from the slide drawer. Needs the admin password every time.
   The admin password is a real Firebase Authentication account (admin@study-log.app), so it is
   checked by Firebase itself and is never stored in these files. See SETUP.md. */
(function(){
'use strict';
var L=window.SLLock; if(!L) return;
var C=window.FB_CONFIG||{}, DB=(C.databaseURL||'').replace(/\/+$/,''), KEY=C.apiKey||'', ON=!!(DB&&KEY);
var EMAIL='admin@study-log.app', AWAY=5*60*1000;
var esc=L.esc, SV=L.SV;
var A=null, D={u:{},pw:null,at:0}, tab='req', loading=false, isOpen=false, hiddenAt=0, tmr=0, tT=0, busyLogin=false;
function $(i){ return document.getElementById(i); }

/* ---- admin session (memory only) ---- */
function aPost(u,t,b){ return fetch(u,{method:'POST',headers:{'Content-Type':t},body:b}).then(function(r){ return r.json(); }); }
function aSession(r){ return {t:r.idToken,rt:r.refreshToken,exp:Date.now()+(+r.expiresIn||3600)*1000}; }
async function signIn(pw){
  var r=await aPost('https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key='+KEY,'application/json',JSON.stringify({email:EMAIL,password:pw,returnSecureToken:true}));
  if(!r.idToken){ var e=new Error((r.error&&r.error.message)||'auth'); throw e; }
  return aSession(r);
}
async function atok(){
  if(!A) throw new Error('locked');
  if(Date.now()<A.exp-60000) return A.t;
  var r=await aPost('https://securetoken.googleapis.com/v1/token?key='+KEY,'application/x-www-form-urlencoded','grant_type=refresh_token&refresh_token='+encodeURIComponent(A.rt));
  if(!r.id_token){ lockAdmin('Session expired. Enter the password again.'); throw new Error('locked'); }
  A.t=r.id_token; A.rt=r.refresh_token||A.rt; A.exp=Date.now()+(+r.expires_in||3600)*1000;
  return A.t;
}
async function adb(m,p,b){
  var t=await atok(), ctl=window.AbortController?new AbortController():null, to=ctl?setTimeout(function(){ ctl.abort(); },12000):0;
  try{
    var r=await fetch(DB+'/'+p+'.json?auth='+t,{method:m,body:b===undefined?undefined:JSON.stringify(b),signal:ctl?ctl.signal:undefined});
    if(!r.ok){ var e=new Error('http '+r.status); e.status=r.status; throw e; }
    return await r.json();
  }finally{ if(to) clearTimeout(to); }
}
function loginMsg(e){
  var m=String(e&&e.message||'');
  if(/TOO_MANY_ATTEMPTS/.test(m)) return 'Too many tries. Wait a few minutes, then try again.';
  if(/OPERATION_NOT_ALLOWED/.test(m)) return 'Email/Password sign-in is switched off in Firebase (SETUP.md step 4).';
  if(/INVALID_LOGIN_CREDENTIALS|INVALID_PASSWORD|EMAIL_NOT_FOUND|INVALID_EMAIL|MISSING_PASSWORD/.test(m)) return 'Wrong password.';
  if(/USER_DISABLED/.test(m)) return 'This admin account is disabled in Firebase.';
  if(/API key|INVALID_API_KEY/.test(m)) return 'The apiKey in firebase-config.js is not valid.';
  return L.explain(e);
}
function dataMsg(e){
  var m=String(e&&e.message||'');
  if(e&&e.status===401||e&&e.status===403) return 'The database refused this. Publish the latest database_rules.json and create the admin account (SETUP.md steps 3 and 5).';
  return L.explain(e);
}

/* ---- helpers ---- */
function tel(m){ return String(m||'').replace(/[^\d+]/g,''); }
function fmt(t){ try{ return new Date(t).toLocaleString([], {day:'numeric',month:'short',hour:'numeric',minute:'2-digit'}); }catch(e){ return ''; } }
function ago(t){
  if(!t) return '—'; var s=Math.max(0,(Date.now()-t)/1000);
  if(s<60) return 'just now'; if(s<3600) return Math.floor(s/60)+'m ago'; if(s<86400) return Math.floor(s/3600)+'h ago';
  if(s<2592000) return Math.floor(s/86400)+'d ago'; return fmt(t);
}
function hue(s){ var h=0,i; s=String(s); for(i=0;i<s.length;i++) h=(h*31+s.charCodeAt(i))>>>0; return h%360; }
function toast(msg,bad){
  var t=$('abToast'); if(!t) return; t.textContent=msg; t.className='ab-toast show'+(bad?' bad':'');
  clearTimeout(tT); tT=setTimeout(function(){ t.className='ab-toast'; },2600);
}
var IC={
  back:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M15 5l-7 7 7 7"/></svg>',
  ref:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M20 11a8 8 0 1 0-2.3 5.7"/><path d="M20 4v7h-7"/></svg>',
  shield:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l8 3v5c0 5-3.4 8.5-8 10-4.6-1.5-8-5-8-10V6z"/><rect x="9" y="10.5" width="6" height="5" rx="1"/><path d="M10.2 10.5V9a1.8 1.8 0 0 1 3.6 0v1.5"/></svg>',
  eye:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>',
  eyeoff:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3l18 18"/><path d="M10.6 6.1A10 10 0 0 1 12 5c6.4 0 10 7 10 7a17 17 0 0 1-3.2 4.2M6.5 7A17 17 0 0 0 2 12s3.6 7 10 7a9.8 9.8 0 0 0 4.1-.9"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/></svg>',
  call:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 4h4l2 5-2.5 1.5a11 11 0 0 0 5 5L15 13l5 2v4a2 2 0 0 1-2 2A16 16 0 0 1 3 6a2 2 0 0 1 2-2z"/></svg>',
  sms:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a8 8 0 0 1-11.5 7.2L3 21l1.8-5.5A8 8 0 1 1 21 12z"/></svg>',
  ok:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>',
  del:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/></svg>',
  padlock:'<svg class="ab-lk" viewBox="0 0 64 64" aria-hidden="true"><defs><linearGradient id="abG1" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#FFD98A"/><stop offset=".55" stop-color="#E8A33D"/><stop offset="1" stop-color="#C77B1E"/></linearGradient></defs><path d="M21 30v-8a11 11 0 0 1 22 0v8" fill="none" stroke="url(#abG1)" stroke-width="5.5" stroke-linecap="round"/><rect x="12" y="29" width="40" height="28" rx="8" fill="url(#abG1)"/><circle cx="32" cy="41.5" r="4" fill="#1A1409"/><rect x="30.3" y="43" width="3.4" height="8" rx="1.7" fill="#1A1409"/></svg>'
};

/* ---- styles ---- */
var CSS='.ab-page,.ab-page *{box-sizing:border-box}'
+'.ab-page{position:fixed;inset:0;z-index:210;display:flex;flex-direction:column;background:var(--bg,#14151A);color:var(--text,#EDEBE3);font-family:Inter,system-ui,-apple-system,sans-serif;transform:translateX(100%);visibility:hidden;transition:transform .32s cubic-bezier(.2,.8,.2,1),visibility 0s .32s;-webkit-tap-highlight-color:transparent}'
+'.ab-page.open{transform:none;visibility:visible;transition:transform .32s cubic-bezier(.2,.8,.2,1),visibility 0s}'
+'.ab-page:before{content:"";position:absolute;left:0;right:0;top:0;height:260px;background:radial-gradient(90% 100% at 50% 0%,rgba(232,163,61,.2),transparent 70%);pointer-events:none}'
+'.ab-page button,.ab-page input{font-family:inherit}'
+'.ab-head{position:relative;display:flex;align-items:center;gap:10px;padding:calc(env(safe-area-inset-top,0px) + 12px) 14px 10px}'
+'.ab-head h2{flex:1;margin:0;font:700 18px Bitter,Georgia,serif;letter-spacing:.02em}.ab-head h2 span{color:var(--accent,#E8A33D)}'
+'.ab-ib{width:40px;height:40px;border-radius:12px;border:1px solid var(--border,#2E313D);background:var(--surface,#1D1F27);color:var(--text,#EDEBE3);display:grid;place-items:center;cursor:pointer;transition:all .15s}.ab-ib:active{transform:scale(.93)}.ab-ib:hover{border-color:var(--accent,#E8A33D)}.ab-ib svg{width:20px;height:20px}.ab-ib.spin svg{animation:abSpin .8s linear infinite}.ab-ib[hidden]{display:none}'
+'@keyframes abSpin{to{transform:rotate(360deg)}}'
+'.ab-body{position:relative;flex:1;overflow-y:auto;-webkit-overflow-scrolling:touch;padding:6px 16px calc(env(safe-area-inset-bottom,0px) + 30px)}'
+'.ab-w{max-width:560px;margin:0 auto}'
+'.ab-login{padding-top:22px;text-align:center;animation:abUp .5s ease both}'
+'@keyframes abUp{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}'
+'.ab-emb{position:relative;width:92px;height:92px;margin:0 auto 16px;display:grid;place-items:center;border-radius:50%;background:radial-gradient(circle at 32% 26%,#343744,#1a1b22);box-shadow:0 0 44px rgba(232,163,61,.28)}'
+'.ab-emb:before{content:"";position:absolute;inset:-3px;border-radius:50%;background:conic-gradient(#E8A33D,#D9705B,#7EC9E8,#E8A33D);-webkit-mask:radial-gradient(farthest-side,transparent calc(100% - 3px),#000 calc(100% - 2px));mask:radial-gradient(farthest-side,transparent calc(100% - 3px),#000 calc(100% - 2px));animation:abSpin 6s linear infinite}'
+'.ab-emb:after{content:"";position:absolute;inset:-10px;border-radius:50%;border:2px solid rgba(232,163,61,.35);animation:abPulse 2.4s ease-out infinite}'
+'@keyframes abPulse{0%{transform:scale(.88);opacity:.9}100%{transform:scale(1.28);opacity:0}}'
+'.ab-lk{width:46px;height:46px;position:relative;z-index:1;filter:drop-shadow(0 3px 8px rgba(0,0,0,.45))}'
+'.ab-h1{margin:0 0 6px;font:700 22px Bitter,Georgia,serif}.ab-sub{margin:0 0 20px;font-size:13px;line-height:1.55;color:var(--text-2,#9294A3)}'
+'.ab-card{position:relative;border-radius:20px;padding:18px 16px;background:linear-gradient(180deg,rgba(38,40,50,.9),rgba(28,30,38,.92));border:1px solid rgba(232,163,61,.22);box-shadow:0 18px 50px rgba(0,0,0,.4);text-align:left;margin-bottom:14px}'
+'.ab-card:before{content:"";position:absolute;left:20px;right:20px;top:-1px;height:2px;border-radius:2px;background:linear-gradient(90deg,transparent,#E8A33D,#D9705B,#7EC9E8,transparent)}'
+'.ab-card h3{margin:0 0 4px;font:700 15px Bitter,Georgia,serif}.ab-card p{margin:0 0 12px;font-size:12.5px;line-height:1.55;color:var(--text-2,#9294A3)}'
+'.ab-lb{display:block;margin:12px 0 6px 1px;font:600 11px Inter,sans-serif;letter-spacing:.07em;text-transform:uppercase;color:var(--text-2,#9294A3)}'
+'.ab-in{display:block;width:100%;background:#24262F;border:1.5px solid #3A3D4B;border-radius:12px;padding:12px 14px;color:var(--text,#EDEBE3);font:500 16px Inter,sans-serif;outline:none;transition:border-color .2s,box-shadow .2s;-webkit-appearance:none;appearance:none}'
+'.ab-in::placeholder{color:#63656F}.ab-in:focus{border-color:#E8A33D;box-shadow:0 0 0 4px rgba(232,163,61,.16)}.ab-in.bad{border-color:#D9705B}'
+'.ab-pw{position:relative}.ab-pw .ab-in{padding-right:46px}.ab-eye{position:absolute;right:5px;top:50%;transform:translateY(-50%);width:36px;height:36px;border:0;background:none;color:#9294A3;border-radius:10px;cursor:pointer;display:grid;place-items:center}.ab-eye.on,.ab-eye:hover{color:#E8A33D}.ab-eye svg{width:19px;height:19px}'
+'.ab-btn{position:relative;overflow:hidden;display:block;width:100%;margin-top:14px;border:0;border-radius:13px;padding:14px 16px;font:700 14.5px Inter,sans-serif;color:#1A1409;background:linear-gradient(135deg,#F7BE5E,#E8A33D 55%,#D98A25);box-shadow:0 8px 24px rgba(232,163,61,.28);cursor:pointer;transition:transform .15s,opacity .2s}.ab-btn:active:not(:disabled){transform:scale(.98)}.ab-btn:disabled{opacity:.45;cursor:not-allowed;box-shadow:none}'
+'.ab-btn.alt{background:rgba(255,255,255,.05);color:var(--text,#EDEBE3);border:1.5px solid #3A3D4B;box-shadow:none}'
+'.ab-spin{display:inline-block;width:14px;height:14px;margin-right:8px;vertical-align:-2px;border:2.5px solid rgba(26,20,9,.25);border-top-color:#1A1409;border-radius:50%;animation:abSpin .7s linear infinite}'
+'.ab-msg{display:none;margin:12px 0 0;padding:10px 12px;border-radius:12px;font-size:13px;line-height:1.45;text-align:left}.ab-msg.show{display:block;animation:abUp .3s ease both}.ab-msg.err{background:rgba(217,112,91,.13);border:1px solid rgba(217,112,91,.5);color:#F29A85}.ab-msg.ok{background:rgba(127,168,117,.13);border:1px solid rgba(127,168,117,.5);color:#B4DBA9}.ab-msg.info{background:rgba(126,201,232,.1);border:1px solid rgba(126,201,232,.4);color:#9ED7EE}'
+'.ab-msg button{margin-left:8px;border:0;background:none;color:inherit;font-weight:700;text-decoration:underline;cursor:pointer}'
+'.ab-note{margin:12px 2px 0;font-size:11.5px;line-height:1.5;color:#63656F}'
+'.ab-shake{animation:abShake .45s ease}@keyframes abShake{20%,60%{transform:translateX(-8px)}40%,80%{transform:translateX(8px)}}'
+'.ab-stats{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin:6px 0 14px}'
+'.ab-stat{position:relative;overflow:hidden;border-radius:16px;padding:12px 8px 10px;text-align:center;background:var(--surface,#1D1F27);border:1px solid var(--border,#2E313D);animation:abUp .5s ease both}'
+'.ab-stat:before{content:"";position:absolute;inset:0;background:radial-gradient(80% 90% at 50% 0%,var(--g),transparent 75%);opacity:.5}'
+'.ab-stat b{position:relative;display:block;font:700 26px "IBM Plex Mono",monospace;color:var(--c)}.ab-stat span{position:relative;display:block;margin-top:2px;font:600 10px Inter,sans-serif;letter-spacing:.09em;text-transform:uppercase;color:var(--text-2,#9294A3)}'
+'.ab-s1{--c:#F7BE5E;--g:rgba(232,163,61,.3)}.ab-s2{--c:#F29A85;--g:rgba(217,112,91,.3);animation-delay:.06s}.ab-s3{--c:#9ED7EE;--g:rgba(126,201,232,.28);animation-delay:.12s}'
+'.ab-tabs{display:flex;gap:4px;padding:4px;margin:0 0 12px;border-radius:14px;background:var(--surface,#1D1F27);border:1px solid var(--border,#2E313D)}'
+'.ab-tabs button{flex:1;display:flex;align-items:center;justify-content:center;gap:6px;padding:10px 4px;border:0;border-radius:10px;background:none;color:var(--text-2,#9294A3);font:600 13px Inter,sans-serif;cursor:pointer;transition:all .2s}'
+'.ab-tabs button.on{background:linear-gradient(135deg,#F7BE5E,#E8A33D);color:#1A1409;box-shadow:0 4px 14px rgba(232,163,61,.3)}'
+'.ab-tabs i{display:none;min-width:18px;height:18px;padding:0 5px;border-radius:9px;background:#D9705B;color:#fff;font:700 11px/18px Inter,sans-serif;font-style:normal}.ab-tabs i.show{display:inline-block}.ab-tabs button.on i{background:#1A1409;color:#F7BE5E}'
+'.ab-upd{margin:0 2px 10px;font-size:11.5px;color:#63656F;text-align:right}'
+'.ab-p{margin:0 0 14px;position:relative;border-radius:18px;padding:14px;background:linear-gradient(180deg,rgba(38,40,50,.92),rgba(28,30,38,.94));border:1px solid var(--border,#2E313D);animation:abUp .4s ease both}'
+'.ab-p.new{border-color:rgba(232,163,61,.5);box-shadow:0 0 0 1px rgba(232,163,61,.12),0 10px 30px rgba(232,163,61,.08)}'
+'.ab-top{display:flex;align-items:center;gap:12px}'
+'.ab-av{flex:0 0 auto;width:44px;height:44px;border-radius:14px;display:grid;place-items:center;font:700 18px Bitter,serif;color:#fff;background:linear-gradient(135deg,hsl(var(--h) 70% 58%),hsl(calc(var(--h) + 40) 70% 42%));box-shadow:0 4px 14px rgba(0,0,0,.35)}'
+'.ab-nm{flex:1;min-width:0}.ab-nm b{display:block;font:700 15.5px Inter,sans-serif;word-break:break-word}.ab-nm span{display:block;margin-top:2px;font-size:12px;color:var(--text-2,#9294A3)}'
+'.ab-chips{display:flex;flex-wrap:wrap;gap:6px;margin:10px 0 2px}'
+'.ab-chip{display:inline-flex;align-items:center;gap:4px;padding:3px 9px;border-radius:99px;font:600 11px Inter,sans-serif;border:1px solid transparent}'
+'.ab-chip.new{background:rgba(232,163,61,.18);color:#F7BE5E;border-color:rgba(232,163,61,.45)}.ab-chip.key{background:rgba(217,112,91,.16);color:#F29A85;border-color:rgba(217,112,91,.4)}.ab-chip.yes{background:rgba(127,168,117,.15);color:#B4DBA9;border-color:rgba(127,168,117,.4)}.ab-chip.no{background:rgba(217,112,91,.13);color:#F29A85;border-color:rgba(217,112,91,.35)}.ab-chip.ok{background:rgba(126,201,232,.12);color:#9ED7EE;border-color:rgba(126,201,232,.35)}.ab-chip.dim{background:rgba(255,255,255,.05);color:#9294A3;border-color:#3A3D4B}'
+'.ab-kv{display:flex;justify-content:space-between;gap:12px;padding:7px 0;border-bottom:1px dashed rgba(255,255,255,.07);font-size:13px}.ab-kv:last-of-type{border-bottom:0}.ab-kv span{color:var(--text-2,#9294A3);flex:0 0 auto}.ab-kv b{font-weight:600;text-align:right;word-break:break-word}'
+'.ab-bubble{margin:8px 0 2px;padding:10px 12px;border-radius:12px 12px 12px 3px;background:rgba(126,201,232,.09);border:1px solid rgba(126,201,232,.25);font-size:13px;line-height:1.5;white-space:pre-wrap;word-break:break-word}.ab-bubble small{display:block;margin-bottom:3px;font:600 10px Inter,sans-serif;letter-spacing:.08em;text-transform:uppercase;color:#7EC9E8}'
+'.ab-acts{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}'
+'.ab-act{flex:1 1 0;display:inline-flex;align-items:center;justify-content:center;gap:6px;min-width:0;white-space:nowrap;padding:10px 8px;border-radius:12px;border:1.5px solid #3A3D4B;background:rgba(255,255,255,.04);color:var(--text,#EDEBE3);font:600 13px Inter,sans-serif;text-decoration:none;cursor:pointer;transition:all .15s}.ab-act:active{transform:scale(.96)}.ab-act svg{width:16px;height:16px}'
+'.ab-act.call{background:rgba(127,168,117,.14);border-color:rgba(127,168,117,.5);color:#B4DBA9}.ab-act.sms{background:rgba(126,201,232,.12);border-color:rgba(126,201,232,.45);color:#9ED7EE}.ab-act.done{background:rgba(232,163,61,.14);border-color:rgba(232,163,61,.5);color:#F7BE5E}.ab-act:disabled{opacity:.5}'
+'.ab-x{flex:0 0 auto;width:38px;height:38px;border-radius:11px;border:1px solid rgba(217,112,91,.38);background:rgba(217,112,91,.08);color:#F29A85;display:grid;place-items:center;cursor:pointer;transition:all .15s}.ab-x:active{transform:scale(.92)}.ab-x:disabled{opacity:.5}.ab-x svg{width:17px;height:17px}'
+'.ab-empty{text-align:center;padding:34px 16px;color:#63656F;font-size:13.5px;line-height:1.6}.ab-empty b{display:block;margin-bottom:4px;font:700 15px Bitter,serif;color:var(--text-2,#9294A3)}'
+'.ab-more{display:block;width:100%;margin:2px 0 14px;padding:11px;border-radius:12px;border:1px dashed #3A3D4B;background:none;color:var(--text-2,#9294A3);font:600 13px Inter,sans-serif;cursor:pointer}'
+'.ab-chk{display:flex;gap:10px;align-items:flex-start;margin-top:14px;font-size:13px;line-height:1.5;color:#C9C8C2;cursor:pointer}.ab-chk input{margin-top:3px;width:18px;height:18px;accent-color:#E8A33D;flex:0 0 auto}'
+'.ab-toast{position:fixed;left:50%;bottom:calc(env(safe-area-inset-bottom,0px) + 26px);transform:translate(-50%,20px);max-width:88%;padding:11px 16px;border-radius:12px;background:#2A3A27;border:1px solid #7FA875;color:#D5ECCD;font:600 13px Inter,sans-serif;opacity:0;pointer-events:none;transition:all .3s;z-index:5;text-align:center}.ab-toast.show{opacity:1;transform:translate(-50%,0)}.ab-toast.bad{background:#40241F;border-color:#D9705B;color:#F6B8A9}'
+'#abDrawerBtn{margin-top:10px;border-top:1px solid var(--border,#2E313D);border-radius:0 0 8px 8px;padding-top:14px}#abDrawerBtn svg{color:var(--accent,#E8A33D)}'
+'@media (prefers-reduced-motion:reduce){.ab-page *,.ab-page *:before,.ab-page *:after{animation:none!important;transition:none!important}}';

/* ---- page ---- */
function pwField(id,label,ph){
  return '<label class="ab-lb" for="'+id+'">'+label+'</label><div class="ab-pw"><input class="ab-in" id="'+id+'" type="password" autocomplete="off" autocapitalize="none" autocorrect="off" spellcheck="false" placeholder="'+ph+'"><button class="ab-eye" type="button" data-eye="'+id+'" aria-label="Show password">'+IC.eye+'</button></div>';
}
function build(){
  if($('abPage')) return;
  var st=document.createElement('style'); st.id='abCss'; st.textContent=CSS; document.head.appendChild(st);
  var p=document.createElement('div'); p.className='ab-page'; p.id='abPage'; p.setAttribute('role','dialog'); p.setAttribute('aria-modal','true'); p.setAttribute('aria-label','Admin Block');
  p.innerHTML=
   '<div class="ab-head"><button class="ab-ib" id="abBack" type="button" aria-label="Close Admin Block">'+IC.back+'</button><h2>ADMIN <span>BLOCK</span></h2><button class="ab-ib" id="abRef" type="button" aria-label="Refresh" hidden>'+IC.ref+'</button></div>'
  +'<div class="ab-body"><div class="ab-w">'
  +'<div class="ab-login" id="abLogin"><div class="ab-emb">'+IC.padlock+'</div><h1 class="ab-h1">Admin only</h1><p class="ab-sub" id="abSub">Enter the admin password to open this block.</p>'
  +'<div class="ab-card" id="abLoginCard">'+pwField('abPw','Admin password','Enter admin password')+'<div class="ab-msg" id="abLErr" role="alert"></div><button class="ab-btn" id="abGo" type="button">Unlock</button></div></div>'
  +'<div id="abMain" hidden>'
    +'<div class="ab-stats"><div class="ab-stat ab-s1"><b id="abN1">0</b><span>Registered</span></div><div class="ab-stat ab-s2"><b id="abN2">0</b><span>Pending</span></div><div class="ab-stat ab-s3"><b id="abN3">0</b><span>Devices</span></div></div>'
    +'<div class="ab-tabs" role="tablist"><button type="button" data-tab="req" class="on">Requests<i id="abB1"></i></button><button type="button" data-tab="usr">Users</button><button type="button" data-tab="pw">Password</button></div>'
    +'<div class="ab-msg" id="abStat" role="status"></div>'
    +'<div id="abPReq"><div class="ab-upd" id="abUpd"></div><div id="abReq"></div></div>'
    +'<div id="abPUsr" hidden><input class="ab-in" id="abQ" type="search" autocomplete="off" placeholder="Search name, class or number" style="margin-bottom:12px"><div id="abUsr"></div></div>'
    +'<div id="abPPw" hidden>'
      +'<div class="ab-card"><h3>App password</h3><p>New users must enter this to open the app. It is saved scrambled, so it cannot be shown again. <b id="abPwInfo"></b></p>'
      +pwField('abNp1','New app password','At least 6 characters')+pwField('abNp2','Confirm new password','Type it again')
      +'<label class="ab-chk"><input type="checkbox" id="abForce"><span>Make everyone who already has the app enter the new password again (next time they are online).</span></label>'
      +'<div class="ab-msg" id="abAMsg" role="status"></div><button class="ab-btn" id="abSaveApp" type="button">Save app password</button></div>'
      +'<div class="ab-card"><h3>Admin password</h3><p>This opens Admin Block. Changing it signs you in again with the new one.</p>'
      +pwField('abOp','Current admin password','Current password')+pwField('abAp1','New admin password','At least 6 characters')+pwField('abAp2','Confirm new admin password','Type it again')
      +'<div class="ab-msg" id="abPMsg" role="status"></div><button class="ab-btn" id="abSaveAdm" type="button">Change admin password</button></div>'
    +'</div>'
  +'</div></div></div><div class="ab-toast" id="abToast" role="status"></div>';
  document.body.appendChild(p);
  $('abBack').addEventListener('click',closePage);
  $('abRef').addEventListener('click',function(){ load(false); });
  $('abGo').addEventListener('click',doLogin);
  $('abPw').addEventListener('keydown',function(e){ if(e.key==='Enter'){ e.preventDefault(); doLogin(); } });
  $('abQ').addEventListener('input',paint);
  $('abSaveApp').addEventListener('click',saveApp);
  $('abSaveAdm').addEventListener('click',saveAdm);
  p.addEventListener('click',function(e){
    var t=e.target.closest?e.target.closest('[data-eye],[data-tab],[data-act]'):null; if(!t) return;
    if(t.hasAttribute('data-eye')){ var i=$(t.getAttribute('data-eye')), on=i.type==='password'; i.type=on?'text':'password'; t.innerHTML=on?IC.eyeoff:IC.eye; t.classList.toggle('on',on); t.setAttribute('aria-label',on?'Hide password':'Show password'); return; }
    if(t.hasAttribute('data-tab')){ setTab(t.getAttribute('data-tab')); return; }
    act(t.getAttribute('data-act'),t.getAttribute('data-id'),t);
  });
}
function setTab(t){
  tab=t;
  Array.prototype.forEach.call(document.querySelectorAll('#abPage .ab-tabs button'),function(b){ b.classList.toggle('on',b.getAttribute('data-tab')===t); });
  $('abPReq').hidden=t!=='req'; $('abPUsr').hidden=t!=='usr'; $('abPPw').hidden=t!=='pw';
  paint();
}
function setStat(msg,cls,retry){
  var e=$('abStat'); if(!e) return;
  e.className='ab-msg'+(msg?' show '+(cls||'info'):'');
  e.innerHTML=''; if(!msg) return; e.appendChild(document.createTextNode(msg));
  if(retry){ var b=document.createElement('button'); b.type='button'; b.textContent='Retry'; b.addEventListener('click',function(){ load(false); }); e.appendChild(b); }
}
function lmsg(m){ var e=$('abLErr'); if(!e) return; e.textContent=m||''; e.className='ab-msg'+(m?' show err':''); }

/* ---- login ---- */
var LIM='sl_adm_lim';
function lim(){ try{ return JSON.parse(localStorage.getItem(LIM)||'null')||{n:0,u:0}; }catch(e){ return {n:0,u:0}; } }
function setLim(o){ try{ localStorage.setItem(LIM,JSON.stringify(o)); }catch(e){} }
async function doLogin(){
  if(busyLogin||A) return;
  if(!ON){ lmsg('The database is not connected. Fill in firebase-config.js (SETUP.md step 7).'); return; }
  var l=lim(); if(l.u>Date.now()){ lmsg('Too many wrong tries. Wait '+Math.ceil((l.u-Date.now())/1000)+'s.'); return; }
  var inp=$('abPw'), pw=L.norm(inp.value);
  if(!pw){ lmsg('Enter the admin password.'); return; }
  busyLogin=true; lmsg(''); var b=$('abGo'); b.disabled=true; b.innerHTML='<span class="ab-spin"></span>Checking…';
  try{
    A=await signIn(pw); setLim({n:0,u:0}); inp.value='';
    $('abLogin').hidden=true; $('abMain').hidden=false; $('abRef').hidden=false; setTab('req');
    load(false); clearInterval(tmr); tmr=setInterval(function(){ if(!document.hidden&&A&&tab!=='pw') load(true); },30000);
  }catch(e){
    var wrong=/INVALID_LOGIN_CREDENTIALS|INVALID_PASSWORD|EMAIL_NOT_FOUND/.test(String(e&&e.message));
    if(wrong){ l=lim(); l.n=(l.n||0)+1; if(l.n>=5){ l.n=0; l.u=Date.now()+60000; } setLim(l); }
    lmsg(loginMsg(e)+(wrong?' (Owner: first time? Create the admin account — SETUP.md step 5.)':''));
    var c=$('abLoginCard'); c.classList.remove('ab-shake'); void c.offsetWidth; c.classList.add('ab-shake');
    try{ inp.select(); }catch(_){}
  }
  busyLogin=false; b.disabled=false; b.textContent='Unlock';
}
function lockAdmin(msg){
  A=null; D={u:{},pw:null,at:0}; clearInterval(tmr); loading=false;
  if(!$('abPage')) return;
  $('abMain').hidden=true; $('abLogin').hidden=false; $('abRef').hidden=true;
  ['abPw','abNp1','abNp2','abOp','abAp1','abAp2','abQ'].forEach(function(i){ var e=$(i); if(e){ e.value=''; if(e.type==='text'&&i!=='abQ') e.type='password'; } });
  Array.prototype.forEach.call(document.querySelectorAll('#abPage [data-eye]'),function(b){ b.innerHTML=IC.eye; b.classList.remove('on'); });
  ['abAMsg','abPMsg'].forEach(function(i){ var e=$(i); if(e){ e.className='ab-msg'; e.textContent=''; } });
  $('abForce').checked=false; setStat(''); lmsg(msg||'');
  if(msg){ var e=$('abLErr'); e.className='ab-msg show info'; }
  $('abReq').innerHTML=''; $('abUsr').innerHTML='';
  if(isOpen) setTimeout(function(){ var i=$('abPw'); if(i&&!A) try{ i.focus({preventScroll:true}); }catch(_){ i.focus(); } },320);
}

/* ---- data ---- */
function people(){
  var out=[], u=D.u||{}, id, p, r, s, act, dn;
  for(id in u){
    if(!Object.prototype.hasOwnProperty.call(u,id)) continue; p=u[id]; if(!p||typeof p!=='object') continue;
    r=(p.reg&&typeof p.reg==='object')?p.reg:null; s=(p.seen&&typeof p.seen==='object')?p.seen:null;
    act=Math.max(r?(+r.t||0):0,+p.ask||0); dn=+p.done||0;
    out.push({id:id,r:r,ask:+p.ask||0,done:dn,a:s?(+s.a||0):0,l:s?(+s.l||0):0,w:s?s.w:'',act:act,pend:!!(r||p.ask)&&act>dn});
  }
  return out;
}
async function load(silent){
  if(!A||loading) return; loading=true;
  var rb=$('abRef'); if(rb&&!silent) rb.classList.add('spin');
  if(!silent) setStat('Loading…','info');
  try{
    var r=await Promise.all([adb('GET','lock/u'),adb('GET','lock/pw')]);
    if(!A) return;
    D.u=(r[0]&&typeof r[0]==='object')?r[0]:{}; D.pw=(r[1]&&typeof r[1]==='object')?r[1]:null; D.at=Date.now();
    setStat(''); paint(); paintInfo();
  }catch(e){ if(A) setStat(dataMsg(e),'err',true); }
  finally{ loading=false; if(rb) rb.classList.remove('spin'); }
}
function paintInfo(){
  var e=$('abPwInfo'); if(!e) return;
  e.textContent=(D.pw&&+D.pw.v)?'Last changed: '+fmt(+D.pw.v)+'.':'Right now the built-in default password is in use.';
}
function hows(w){ return w==='f'?'via the form':(w==='d'?'skipped the form':(w==='g'?'existing install':'')); }
function card(p){
  var r=p.r, nm=r?r.n:'Unregistered device', ini=String(nm).trim().charAt(0).toUpperCase()||'?', ch='', kv='', ac='', num=r?tel(r.m):'';
  if(p.pend) ch+='<span class="ab-chip new">NEW</span>';
  if(p.ask&&p.ask>p.done) ch+='<span class="ab-chip key">🔑 Wants the password</span>';
  if(r&&!p.pend&&p.done) ch+='<span class="ab-chip ok">✓ Handled</span>';
  if(r) ch+=r.k==='y'?'<span class="ab-chip yes">Knows Amarnath</span>':'<span class="ab-chip no">Does not know Amarnath</span>';
  if(p.a) ch+='<span class="ab-chip dim">Unlocked'+(hows(p.w)?' · '+hows(p.w):'')+'</span>'; else if(r) ch+='<span class="ab-chip dim">Not unlocked yet</span>';
  if(r){
    kv+='<div class="ab-kv"><span>Class</span><b>'+esc(r.c)+'</b></div>'
      +'<div class="ab-kv"><span>Mobile</span><b>'+esc(r.m)+'</b></div>'
      +'<div class="ab-kv"><span>Knows AMARNATH</span><b>'+(r.k==='y'?'Yes':'No')+'</b></div>'
      +'<div class="ab-kv"><span>Allowed call / message</span><b>'+(r.o?'✓ Yes':'—')+'</b></div>'
      +'<div class="ab-kv"><span>Request sent</span><b>'+esc(fmt(+r.t))+' · '+esc(ago(+r.t))+'</b></div>';
    if(p.ask) kv+='<div class="ab-kv"><span>Asked for password</span><b>'+esc(fmt(p.ask))+' · '+esc(ago(p.ask))+'</b></div>';
    if(r.x) kv+='<div class="ab-bubble"><small>Message to admin</small>'+esc(r.x)+'</div>';
  }else{
    kv+='<div class="ab-kv"><span>Device</span><b>…'+esc(String(p.id).slice(-6))+'</b></div>';
  }
  if(p.a) kv+='<div class="ab-kv"><span>Unlocked</span><b>'+esc(fmt(p.a))+'</b></div>';
  if(p.l) kv+='<div class="ab-kv"><span>Last opened</span><b>'+esc(ago(p.l))+'</b></div>';
  if(num&&num.length>=7) ac+='<a class="ab-act call" href="tel:'+esc(num)+'">'+IC.call+'Call</a><a class="ab-act sms" href="sms:'+esc(num)+'">'+IC.sms+'Message</a>';
  if(r) ac+=p.pend?'<button class="ab-act done" type="button" data-act="done" data-id="'+esc(p.id)+'">'+IC.ok+'Mark done</button>':(p.done?'<button class="ab-act" type="button" data-act="undo" data-id="'+esc(p.id)+'">Undo done</button>':'');
  return '<div class="ab-p'+(p.pend?' new':'')+'"><div class="ab-top"><div class="ab-av" style="--h:'+hue(p.id)+'">'+esc(ini)+'</div><div class="ab-nm"><b>'+esc(nm)+'</b><span>'+(r?esc(r.c)+' · '+esc(r.m):'No details given')+'</span></div><button class="ab-x" type="button" data-act="del" data-id="'+esc(p.id)+'" aria-label="Delete '+esc(nm)+'">'+IC.del+'</button></div>'
    +'<div class="ab-chips">'+ch+'</div>'+kv+(ac?'<div class="ab-acts">'+ac+'</div>':'')+'</div>';
}
var showDone=false;
function paint(){
  if(!A||!$('abReq')) return;
  var all=people(), reg=0, pend=[], dev=all.length, done=[], i;
  for(i=0;i<all.length;i++){ if(all[i].r) reg++; if(all[i].pend) pend.push(all[i]); else if(all[i].r&&all[i].done) done.push(all[i]); }
  pend.sort(function(a,b){ return b.act-a.act; }); done.sort(function(a,b){ return b.done-a.done; });
  $('abN1').textContent=reg; $('abN2').textContent=pend.length; $('abN3').textContent=dev;
  var bd=$('abB1'); bd.textContent=pend.length; bd.className=pend.length?'show':'';
  $('abUpd').textContent=D.at?'Updated '+fmt(D.at):'';
  var h='';
  if(!pend.length) h+='<div class="ab-empty"><b>No pending requests</b>New requests from people who fill the form will show up here.</div>';
  else h+=pend.map(card).join('');
  if(done.length){
    h+='<button class="ab-more" type="button" data-act="toggledone">'+(showDone?'Hide':'Show')+' handled ('+done.length+')</button>';
    if(showDone) h+=done.map(card).join('');
  }
  $('abReq').innerHTML=h;
  var q=($('abQ').value||'').trim().toLowerCase(), list=all.slice();
  list.sort(function(a,b){ return Math.max(b.l,b.act,b.a)-Math.max(a.l,a.act,a.a); });
  if(q) list=list.filter(function(p){ var r=p.r; return r&&((r.n||'').toLowerCase().indexOf(q)>-1||(r.c||'').toLowerCase().indexOf(q)>-1||tel(r.m).indexOf(tel(q)||'~')>-1); });
  $('abUsr').innerHTML=list.length?list.map(card).join(''):'<div class="ab-empty"><b>'+(q?'No match':'No users yet')+'</b>'+(q?'Try a different name, class or number.':'People who unlock the app will be listed here.')+'</div>';
}
async function act(a,id,btn){
  if(a==='toggledone'){ showDone=!showDone; paint(); return; }
  if(!A||!id||!D.u[id]) return;
  var name=(D.u[id].reg&&D.u[id].reg.n)||'this device';
  if(a==='del'){
    if(!window.confirm('Delete '+name+' from the list?\nTheir request and device record will be removed.')) return;
    btn.disabled=true;
    try{ await adb('DELETE','lock/u/'+id); delete D.u[id]; paint(); toast('Deleted'); }
    catch(e){ btn.disabled=false; toast(dataMsg(e),true); }
    return;
  }
  if(a==='done'||a==='undo'){
    btn.disabled=true;
    try{
      if(a==='done'){ await adb('PATCH','lock/u/'+id,{done:SV}); var dv=await adb('GET','lock/u/'+id+'/done'); D.u[id].done=+dv||Date.now(); }
      else{ await adb('PATCH','lock/u/'+id,{done:null}); delete D.u[id].done; }
      paint(); toast(a==='done'?'Marked as done':'Moved back to requests');
    }catch(e){ btn.disabled=false; toast(dataMsg(e),true); }
  }
}

/* ---- password changes ---- */
function pmsg(id,m,cls){ var e=$(id); if(!e) return; e.textContent=m||''; e.className='ab-msg'+(m?' show '+(cls||'err'):''); }
function btnBusy(b,on,txt){ b.disabled=on; if(on) b.innerHTML='<span class="ab-spin"></span>Saving…'; else b.textContent=txt; }
function checkNew(a,b){
  if(a.length<6) return 'The new password must be at least 6 characters.';
  if(a.length>64) return 'The new password is too long (64 characters max).';
  if(a!==b) return 'The two new passwords do not match.';
  return '';
}
async function saveApp(){
  if(!A) return; var b=$('abSaveApp');
  var p1=L.norm($('abNp1').value), p2=L.norm($('abNp2').value), force=$('abForce').checked, bad=checkNew(p1,p2);
  if(bad){ pmsg('abAMsg',bad); return; }
  pmsg('abAMsg',''); btnBusy(b,true);
  try{
    var s=L.rhex(16), h=await L.pbkdf2(p1,s,L.ITER_PW), now=Date.now(), prev=(D.pw&&+D.pw.fv)||0;
    var rec={s:s,h:h,i:L.ITER_PW,v:now,fv:force?now:prev};
    await adb('PUT','lock/pw',rec);
    D.pw=rec; L.setPv(now); paintInfo();
    $('abNp1').value=''; $('abNp2').value=''; $('abForce').checked=false;
    pmsg('abAMsg',force?'Saved. Everyone will be asked for the new password when they next open the app online.':'Saved. New users now need the new password. People already inside stay unlocked.','ok');
  }catch(e){ pmsg('abAMsg',dataMsg(e)); }
  btnBusy(b,false,'Save app password');
}
async function saveAdm(){
  if(!A) return; var b=$('abSaveAdm');
  var cur=L.norm($('abOp').value), p1=L.norm($('abAp1').value), p2=L.norm($('abAp2').value), bad=checkNew(p1,p2);
  if(!cur){ pmsg('abPMsg','Enter your current admin password.'); return; }
  if(bad){ pmsg('abPMsg',bad); return; }
  if(p1===cur){ pmsg('abPMsg','The new password is the same as the current one.'); return; }
  pmsg('abPMsg',''); btnBusy(b,true);
  try{
    var fresh=await signIn(cur);                             /* proves the current password, and gives a fresh sign-in */
    var r=await aPost('https://identitytoolkit.googleapis.com/v1/accounts:update?key='+KEY,'application/json',JSON.stringify({idToken:fresh.t,password:p1,returnSecureToken:true}));
    if(!r.idToken) throw new Error((r.error&&r.error.message)||'update');
    A=aSession(r);
    $('abOp').value=''; $('abAp1').value=''; $('abAp2').value='';
    pmsg('abPMsg','Admin password changed. Use the new one next time.','ok');
  }catch(e){
    var m=String(e&&e.message||'');
    if(/INVALID_LOGIN_CREDENTIALS|INVALID_PASSWORD/.test(m)) pmsg('abPMsg','Your current admin password is wrong.');
    else if(/WEAK_PASSWORD/.test(m)) pmsg('abPMsg','Firebase says that password is too weak. Use at least 6 characters.');
    else if(/TOO_MANY/.test(m)) pmsg('abPMsg','Too many tries. Wait a few minutes.');
    else if(/CREDENTIAL_TOO_OLD|TOKEN_EXPIRED/.test(m)) pmsg('abPMsg','Please try again.');
    else pmsg('abPMsg',L.explain(e));
  }
  btnBusy(b,false,'Change admin password');
}

/* ---- open / close ---- */
function openPage(){
  build(); if(typeof closeDrawer==='function') closeDrawer();
  var p=$('abPage'); isOpen=true; p.classList.add('open');
  if(!A){ lockAdmin(); if(!ON){ $('abSub').textContent='The database is not connected yet. Fill in firebase-config.js first (SETUP.md).'; $('abLoginCard').style.display='none'; } else { $('abSub').textContent='Enter the admin password to open this block.'; $('abLoginCard').style.display=''; } }
}
function closePage(){
  var p=$('abPage'); if(p) p.classList.remove('open'); isOpen=false; lockAdmin();
}
document.addEventListener('visibilitychange',function(){
  if(document.hidden){ hiddenAt=Date.now(); return; }
  if(isOpen&&A&&hiddenAt&&Date.now()-hiddenAt>AWAY) lockAdmin('Locked after you were away. Enter the password again.');
});
function inject(){
  var dr=document.querySelector('#drawerBackdrop .drawer'); if(!dr||$('abDrawerBtn')) return;
  var b=document.createElement('button'); b.className='drawer-item'; b.id='abDrawerBtn'; b.type='button';
  b.innerHTML=IC.shield+'Admin Block';
  dr.appendChild(b);
  b.addEventListener('click',openPage);
}
inject();
})();
