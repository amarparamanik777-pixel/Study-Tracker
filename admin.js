/* Study Log - Admin Block
   Opens from the slide drawer. Needs the admin password every time.
   The admin password is a real Firebase Authentication account (admin@study-log.app), so it is
   checked by Firebase itself and is never stored in these files. See SETUP.md.
   Tools: one-time passwords, block / unblock, popups, password popups, inspect, ask details. */
(function(){
'use strict';
var L=window.SLLock; if(!L) return;
var C=window.FB_CONFIG||{}, DB=(C.databaseURL||'').replace(/\/+$/,''), KEY=C.apiKey||'', ON=!!(DB&&KEY);
var EMAIL='admin@study-log.app', AWAY=5*60*1000;
var esc=L.esc, SV=L.SV;
var A=null, D=blank(), tab='req', loading=false, isOpen=false, hiddenAt=0, tmr=0, tT=0, busyLogin=false, showDone=false, issuing={}, SH=null, INS=null, pendingAuto=false;
function blank(){ return {u:{},c:{},ap:{},ma:{},ak:{},at:0}; }
function $(i){ return document.getElementById(i); }
function obj(v){ return (v&&typeof v==='object'&&!Array.isArray(v))?v:{}; }

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
async function adb(m,p,b,ms){
  var t=await atok(), ctl=window.AbortController?new AbortController():null, to=ctl?setTimeout(function(){ ctl.abort(); },ms||15000):0;
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
  if(/INVALID_LOGIN_CREDENTIALS|INVALID_PASSWORD|EMAIL_NOT_FOUND|INVALID_EMAIL|MISSING_PASSWORD/.test(m)) return 'Wrong password. Try again.';
  if(/USER_DISABLED/.test(m)) return 'This admin account is disabled in Firebase.';
  if(/API key|INVALID_API_KEY/.test(m)) return 'The apiKey in firebase-config.js is not valid.';
  return L.explain(e);
}
function dataMsg(e){
  if(e&&(e.status===401||e.status===403)) return 'The database refused this. Publish the latest database_rules.json and create the admin account (SETUP.md steps 3 and 5).';
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
function copyText(txt){
  return new Promise(function(res,rej){
    function fallback(){
      try{
        var ta=document.createElement('textarea'); ta.value=txt; ta.setAttribute('readonly',''); ta.style.cssText='position:fixed;left:-9999px;top:0;opacity:0';
        document.body.appendChild(ta); ta.select(); ta.setSelectionRange(0,txt.length);
        var ok=document.execCommand('copy'); document.body.removeChild(ta); ok?res():rej(new Error('copy'));
      }catch(e){ rej(e); }
    }
    if(navigator.clipboard&&navigator.clipboard.writeText){ navigator.clipboard.writeText(txt).then(res,fallback); } else fallback();
  });
}
function copyToast(txt,label){ copyText(txt).then(function(){ toast((label||'Copied')+' ✓'); },function(){ toast('Could not copy. Select the text and copy it by hand.',true); }); }
function newMid(){ var t=Date.now().toString(36); while(t.length<9) t='0'+t; return 'm'+t+L.rhex(2); }
async function hashRec(code){ var s=L.rhex(16), h=await L.pbkdf2(L.nCode(code),s,L.ITER); return {s:s,h:h,i:L.ITER}; }
async function inChunks(list,n,fn){ var i, part; for(i=0;i<list.length;i+=n){ part=list.slice(i,i+n); await Promise.all(part.map(fn)); } }
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

IC.ban='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M5.6 5.6l12.8 12.8"/></svg>';
IC.bell='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 9a6 6 0 0 0-12 0c0 6-2.5 7.5-2.5 7.5h17S18 15 18 9z"/><path d="M10.3 20a1.9 1.9 0 0 0 3.4 0"/></svg>';
IC.look='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="6.5"/><path d="M20 20l-4.2-4.2"/></svg>';
IC.copy='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="11" height="11" rx="2.5"/><path d="M5 15V6a2 2 0 0 1 2-2h8"/></svg>';
IC.plus='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><path d="M12 5v14M5 12h14"/></svg>';
IC.close='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M6 6l12 12M18 6L6 18"/></svg>';
IC.key='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M16 7l3 3"/></svg>';
IC.wand='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 20L16 8"/><path d="M14 4l1 2 2 1-2 1-1 2-1-2-2-1 2-1zM19 12l.7 1.3L21 14l-1.3.7L19 16l-.7-1.3L17 14l1.3-.7z"/></svg>';
IC.unlock='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="11" width="16" height="10" rx="2.5"/><path d="M8 11V8a4 4 0 0 1 7.5-2"/></svg>';
IC.ask='<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M9.6 9.3a2.5 2.5 0 1 1 3.6 2.2c-.8.4-1.2 1-1.2 1.8M12 17h.01"/></svg>';
var CSS2=[
'.ab-tabs button{font-size:12.5px;padding:10px 2px;gap:4px}',
'.ab-in{-webkit-appearance:none;appearance:none}select.ab-in{-webkit-appearance:menulist;appearance:auto}textarea.ab-in{resize:none;min-height:84px;line-height:1.45;font-size:15px}',
'.ab-cnt{display:block;text-align:right;margin-top:4px;font:500 11px "IBM Plex Mono",monospace;color:#63656F}',
/* one-time password box */
'.ab-code{display:flex;align-items:center;gap:8px;margin:12px 0 2px;padding:10px 10px 10px 14px;border-radius:14px;background:rgba(232,163,61,.08);border:1.5px dashed rgba(232,163,61,.5)}',
'.ab-code .c{flex:1;min-width:0}.ab-code .l{display:block;margin-bottom:2px;font:600 10px Inter,sans-serif;letter-spacing:.1em;text-transform:uppercase;color:#9294A3}',
'.ab-code .v{display:block;font:700 19px "IBM Plex Mono",monospace;letter-spacing:.06em;color:#F7BE5E;white-space:nowrap;word-break:normal}.ab-code .v.dim{font:600 13px Inter,sans-serif;letter-spacing:0;color:#9294A3;white-space:normal}',
'.ab-code.used{border-color:rgba(127,168,117,.5);background:rgba(127,168,117,.08)}.ab-code.used .v{color:#B4DBA9}',
'.ab-mini{flex:0 0 auto;display:inline-flex;align-items:center;justify-content:center;gap:5px;padding:9px 11px;border-radius:10px;border:1.5px solid #3A3D4B;background:rgba(255,255,255,.05);color:var(--text,#EDEBE3);font:600 12.5px Inter,sans-serif;cursor:pointer;transition:transform .15s}.ab-mini:active{transform:scale(.95)}.ab-mini:disabled{opacity:.5}.ab-mini svg{width:15px;height:15px}',
'.ab-mini.pri{background:linear-gradient(135deg,#F7BE5E,#E8A33D);color:#1A1409;border-color:transparent}',
'.ab-hint{margin:8px 2px 0;font-size:11.5px;line-height:1.5;color:#7A7C88}',
/* chips + cards */
'.ab-chip.bad{background:rgba(255,77,77,.16);color:#FF9C8E;border-color:rgba(255,77,77,.45)}.ab-chip.warn{background:rgba(245,197,66,.14);color:#F5C542;border-color:rgba(245,197,66,.4)}.ab-chip.pur{background:rgba(181,140,255,.15);color:#D0B6FF;border-color:rgba(181,140,255,.4)}',
'.ab-p.blocked{border-color:rgba(255,77,77,.5);box-shadow:0 0 0 1px rgba(255,77,77,.1)}',
'.ab-act.insp{background:rgba(126,201,232,.12);border-color:rgba(126,201,232,.45);color:#9ED7EE}.ab-act.pop{background:rgba(181,140,255,.13);border-color:rgba(181,140,255,.45);color:#D0B6FF}.ab-act.blk{background:rgba(255,77,77,.12);border-color:rgba(255,77,77,.45);color:#FF9C8E}.ab-act.unb{background:rgba(127,168,117,.14);border-color:rgba(127,168,117,.5);color:#B4DBA9}.ab-act.askd{background:rgba(245,197,66,.12);border-color:rgba(245,197,66,.45);color:#F5C542}',
'.ab-act.sm{flex:0 0 auto}',
'.ab-bar{display:flex;gap:8px;margin:0 0 12px}.ab-bar .ab-btn{margin:0;flex:1}.ab-bar .ab-btn.alt{flex:0 0 auto;width:auto;padding:14px 16px}',
'.ab-btn.dng{background:linear-gradient(135deg,#FF9C8E,#FF4D4D);color:#2a0303;box-shadow:0 8px 24px rgba(255,77,77,.3)}',
/* sheets */
'.ab-sheet{position:absolute;inset:0;z-index:20;display:flex;align-items:flex-end;justify-content:center;background:rgba(6,7,10,.72);-webkit-backdrop-filter:blur(4px);backdrop-filter:blur(4px);opacity:0;visibility:hidden;transition:opacity .2s,visibility 0s .2s}',
'.ab-sheet.open{opacity:1;visibility:visible;transition:opacity .2s}',
'.ab-sh{width:100%;max-width:560px;max-height:92%;display:flex;flex-direction:column;border-radius:24px 24px 0 0;background:linear-gradient(180deg,#262833,#1b1d25);border:1px solid rgba(232,163,61,.26);border-bottom:0;box-shadow:0 -20px 60px rgba(0,0,0,.5);transform:translateY(40px);transition:transform .28s cubic-bezier(.2,.8,.2,1)}',
'.ab-sheet.open .ab-sh{transform:none}',
'.ab-sh-h{display:flex;align-items:center;gap:10px;padding:16px 16px 6px}.ab-sh-h h3{flex:1;margin:0;font:700 17px Bitter,Georgia,serif;word-break:break-word}.ab-sh-h .ab-ib{width:36px;height:36px}',
'.ab-sh-b{overflow-y:auto;-webkit-overflow-scrolling:touch;padding:4px 16px calc(env(safe-area-inset-bottom,0px) + 24px)}',
'.ab-opts{display:flex;flex-wrap:wrap;gap:8px;margin:6px 0 2px}',
'.ab-o{flex:1 1 auto;display:inline-flex;align-items:center;justify-content:center;gap:7px;padding:10px 12px;border-radius:12px;border:1.5px solid #3A3D4B;background:#24262F;color:#9294A3;font:600 13px Inter,sans-serif;cursor:pointer;transition:all .15s}',
'.ab-o:active{transform:scale(.97)}.ab-o i{width:10px;height:10px;border-radius:50%;background:var(--oc,#E8A33D);flex:0 0 auto}',
'.ab-o.on{border-color:var(--oc,#E8A33D);color:var(--oc,#F7BE5E);background:rgba(255,255,255,.07);box-shadow:0 0 0 3px rgba(255,255,255,.04)}',
'.ab-pwrow{display:flex;gap:8px;align-items:center}.ab-pwrow .ab-in{flex:1;min-width:0;font:600 17px "IBM Plex Mono",monospace;letter-spacing:.08em}',
'.ab-pv{margin-top:6px;padding:14px 14px 12px;border-radius:16px;text-align:center;background:linear-gradient(180deg,rgba(38,40,50,.9),rgba(28,30,38,.92));border:1px solid var(--tl,#3A3D4B);box-shadow:0 0 34px -14px var(--tg,transparent)}',
'.ab-pv .ic{width:42px;height:42px;margin:0 auto 6px;display:grid;place-items:center;border-radius:50%;background:var(--tbg,#24262F);color:var(--tc2,#EDEBE3);box-shadow:0 0 22px var(--tg,transparent)}.ab-pv .ic svg{width:22px;height:22px}',
'.ab-pv .t{font:700 15px Bitter,Georgia,serif;color:#F4F2EA;word-break:break-word}.ab-pv .m{margin-top:4px;font-size:12.5px;line-height:1.5;color:#C9C8C2;white-space:pre-wrap;word-break:break-word}',
'.ab-pvl{margin:14px 2px 0;font:600 10.5px Inter,sans-serif;letter-spacing:.09em;text-transform:uppercase;color:#7A7C88}',
/* inspect */
'.ab-live{display:flex;align-items:center;gap:10px;padding:12px 14px;border-radius:14px;margin:10px 0 4px;background:rgba(127,168,117,.12);border:1px solid rgba(127,168,117,.45);color:#C9E8BF;font-size:13.5px;line-height:1.4}',
'.ab-live b{color:#EDEBE3}.ab-live.off{background:rgba(255,255,255,.04);border-color:#3A3D4B;color:#9294A3}.ab-live.wait{background:rgba(126,201,232,.1);border-color:rgba(126,201,232,.4);color:#9ED7EE}',
'.ab-live .dot{flex:0 0 auto;width:10px;height:10px;border-radius:50%;background:#7FA875;animation:abLive 1.4s ease-out infinite}.ab-live.off .dot{background:#63656F;animation:none}.ab-live.wait .dot{background:#7EC9E8}',
'@keyframes abLive{0%{box-shadow:0 0 0 0 rgba(127,168,117,.65)}100%{box-shadow:0 0 0 12px rgba(127,168,117,0)}}',
'.ab-tiles{display:grid;grid-template-columns:repeat(2,1fr);gap:8px;margin:10px 0}',
'.ab-tile{padding:11px 12px;border-radius:14px;background:var(--surface,#1D1F27);border:1px solid var(--border,#2E313D)}.ab-tile b{display:block;font:700 20px "IBM Plex Mono",monospace;color:var(--c,#F7BE5E)}.ab-tile span{font:600 10px Inter,sans-serif;letter-spacing:.08em;text-transform:uppercase;color:#9294A3}',
'.ab-h4{margin:16px 2px 6px;font:700 11.5px Inter,sans-serif;letter-spacing:.09em;text-transform:uppercase;color:#9294A3}',
'.ab-row{display:flex;align-items:flex-start;gap:10px;padding:8px 2px;border-bottom:1px dashed rgba(255,255,255,.07);font-size:13px}.ab-row:last-child{border-bottom:0}',
'.ab-row .d{flex:0 0 auto;width:9px;height:9px;margin-top:5px;border-radius:50%;background:#63656F}.ab-row .n{flex:1;min-width:0;word-break:break-word}.ab-row .n small{display:block;color:#7A7C88;font-size:11.5px;margin-top:1px}.ab-row .r{flex:0 0 auto;color:#9294A3;font:500 12px "IBM Plex Mono",monospace;text-align:right}.ab-row.done .n{text-decoration:line-through;color:#7A7C88}',
'.ab-meter{height:8px;margin:6px 0 2px;border-radius:8px;background:rgba(255,255,255,.08);overflow:hidden}.ab-meter i{display:block;height:100%;border-radius:8px;background:linear-gradient(90deg,#F7BE5E,#7FA875)}',
'.ab-pre{margin:6px 0 0;padding:10px;max-height:260px;overflow:auto;border-radius:10px;background:#14151A;border:1px solid #2E313D;font:11.5px/1.45 "IBM Plex Mono",monospace;color:#C9C8C2;white-space:pre-wrap;word-break:break-all}',
'details.ab-d{margin:6px 0;border:1px solid #2E313D;border-radius:12px;background:rgba(255,255,255,.02)}details.ab-d>summary{padding:11px 12px;cursor:pointer;font:600 13px Inter,sans-serif;list-style:none}details.ab-d>summary::-webkit-details-marker{display:none}details.ab-d[open]>summary{border-bottom:1px solid #2E313D}details.ab-d .ab-pre{margin:0;border:0;border-radius:0 0 12px 12px}',
'.ab-ul{margin:8px 0 0;padding-left:18px;font-size:12.5px;line-height:1.65;color:#9294A3}.ab-ul b{color:#C9C8C2;font-weight:600}',
'@media (prefers-reduced-motion:reduce){.ab-sheet,.ab-sh{transition:none!important}.ab-live .dot{animation:none!important}}'
].join('');

/* ---- page ---- */
function pwField(id,label,ph){
  return '<label class="ab-lb" for="'+id+'">'+label+'</label><div class="ab-pw"><input class="ab-in" id="'+id+'" type="password" autocomplete="off" autocapitalize="none" autocorrect="off" spellcheck="false" placeholder="'+ph+'"><button class="ab-eye" type="button" data-eye="'+id+'" aria-label="Show password">'+IC.eye+'</button></div>';
}
function build(){
  if($('abPage')) return;
  addCss();
  var p=document.createElement('div'); p.className='ab-page'; p.id='abPage'; p.setAttribute('role','dialog'); p.setAttribute('aria-modal','true'); p.setAttribute('aria-label','Admin Block');
  p.innerHTML=
   '<div class="ab-head"><button class="ab-ib" id="abBack" type="button" aria-label="Close Admin Block">'+IC.back+'</button><h2>ADMIN <span>BLOCK</span></h2><button class="ab-ib" id="abRef" type="button" aria-label="Refresh" hidden>'+IC.ref+'</button></div>'
  +'<div class="ab-body" id="abBody"><div class="ab-w">'
  +'<div class="ab-login" id="abLogin"><div class="ab-emb">'+IC.padlock+'</div><h1 class="ab-h1">Admin only</h1><p class="ab-sub" id="abSub">Enter the admin password to open this block.</p>'
  +'<div class="ab-card" id="abLoginCard">'+pwField('abPw','Admin password','Enter admin password')+'<div class="ab-msg" id="abLErr" role="alert"></div><button class="ab-btn" id="abGo" type="button">Unlock</button></div></div>'
  +'<div id="abMain" hidden>'
    +'<div class="ab-stats"><div class="ab-stat ab-s1"><b id="abN1">0</b><span>Registered</span></div><div class="ab-stat ab-s2"><b id="abN2">0</b><span>Pending</span></div><div class="ab-stat ab-s3"><b id="abN3">0</b><span>Devices</span></div></div>'
    +'<div class="ab-tabs" role="tablist"><button type="button" data-tab="req" class="on">Requests<i id="abB1"></i></button><button type="button" data-tab="usr">Users</button><button type="button" data-tab="msg">Popups</button><button type="button" data-tab="pw">Password</button></div>'
    +'<div class="ab-msg" id="abStat" role="status"></div>'
    +'<div id="abPReq"><div class="ab-upd" id="abUpd"></div><div id="abReq"></div></div>'
    +'<div id="abPUsr" hidden><div class="ab-bar" id="abUsrBar"></div><input class="ab-in" id="abQ" type="search" autocomplete="off" placeholder="Search name, class or number" style="margin-bottom:12px"><div id="abUsr"></div></div>'
    +'<div id="abPMsg" hidden><div class="ab-bar"><button class="ab-btn" type="button" data-act="newpop">'+IC.plus.replace('<svg','<svg style="width:16px;height:16px;vertical-align:-3px;margin-right:6px"')+'New popup</button></div><div id="abMsgs"></div></div>'
    +'<div id="abPPw" hidden>'
      +'<div class="ab-card"><h3>Admin password</h3><p>This opens Admin Block. Changing it signs you in again with the new one.</p>'
      +pwField('abOp','Current admin password','Current password')+pwField('abAp1','New admin password','At least 6 characters')+pwField('abAp2','Confirm new admin password','Type it again')
      +'<div class="ab-msg" id="abPMsgBox" role="status"></div><button class="ab-btn" id="abSaveAdm" type="button">Change admin password</button></div>'
      +'<div class="ab-card"><h3>How logins work</h3><ul class="ab-ul">'
        +'<li><b>One-time password.</b> Every phone gets its own. It works once, on that phone only.</li>'
        +'<li><b>Requests tab.</b> When someone sends the form, a one-time password is made for them. Copy it and send it by message or call.</li>'
        +'<li><b>Your phone.</b> The admin password also opens the app on any fresh install.</li>'
        +'<li><b>Users tab.</b> Block, popup, inspect and ask for details for each person.</li>'
        +'<li><b>Updates.</b> When you upload new files to GitHub, everyone gets an Update popup and must tap it.</li>'
      +'</ul></div>'
    +'</div>'
  +'</div></div></div>'
  +'<div class="ab-sheet" id="abSheet"><div class="ab-sh" id="abSh" role="dialog" aria-modal="true"></div></div>'
  +'<div class="ab-toast" id="abToast" role="status"></div>';
  document.body.appendChild(p);
  $('abBack').addEventListener('click',closePage);
  $('abRef').addEventListener('click',function(){ load(false); });
  $('abGo').addEventListener('click',doLogin);
  $('abPw').addEventListener('keydown',function(e){ if(e.key==='Enter'){ e.preventDefault(); doLogin(); } });
  $('abQ').addEventListener('input',paint);
  $('abSaveAdm').addEventListener('click',saveAdm);
  $('abSheet').addEventListener('click',function(e){ if(e.target===$('abSheet')) closeSheet(); });
  p.addEventListener('click',function(e){
    var t=e.target.closest?e.target.closest('[data-eye],[data-tab],[data-act]'):null; if(!t) return;
    if(t.hasAttribute('data-eye')){ var i=$(t.getAttribute('data-eye')), on=i.type==='password'; i.type=on?'text':'password'; t.innerHTML=on?IC.eyeoff:IC.eye; t.classList.toggle('on',on); t.setAttribute('aria-label',on?'Hide password':'Show password'); return; }
    if(t.hasAttribute('data-tab')){ setTab(t.getAttribute('data-tab')); return; }
    act(t.getAttribute('data-act'),t.getAttribute('data-id'),t);
  });
  document.addEventListener('keydown',function(e){ if(e.key==='Escape'&&isOpen&&SH) closeSheet(); });
}
function setTab(t){
  tab=t;
  Array.prototype.forEach.call(document.querySelectorAll('#abPage .ab-tabs button'),function(b){ b.classList.toggle('on',b.getAttribute('data-tab')===t); });
  $('abPReq').hidden=t!=='req'; $('abPUsr').hidden=t!=='usr'; $('abPMsg').hidden=t!=='msg'; $('abPPw').hidden=t!=='pw';
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
    lmsg(loginMsg(e));
    var c=$('abLoginCard'); c.classList.remove('ab-shake'); void c.offsetWidth; c.classList.add('ab-shake');
    try{ inp.select(); }catch(_){}
  }
  busyLogin=false; b.disabled=false; b.textContent='Unlock';
}
function lockAdmin(msg){
  A=null; D=blank(); clearInterval(tmr); loading=false; issuing={};
  stopIns(); if(SH) closeSheet(true);
  if(!$('abPage')) return;
  $('abMain').hidden=true; $('abLogin').hidden=false; $('abRef').hidden=true;
  ['abPw','abOp','abAp1','abAp2','abQ'].forEach(function(i){ var e=$(i); if(e){ e.value=''; if(e.type==='text'&&i!=='abQ') e.type='password'; } });
  Array.prototype.forEach.call(document.querySelectorAll('#abPage [data-eye]'),function(b){ b.innerHTML=IC.eye; b.classList.remove('on'); });
  var pm=$('abPMsgBox'); if(pm){ pm.className='ab-msg'; pm.textContent=''; }
  setStat(''); lmsg(msg||'');
  if(msg){ var e=$('abLErr'); e.className='ab-msg show info'; }
  $('abReq').innerHTML=''; $('abUsr').innerHTML=''; $('abMsgs').innerHTML='';
  if(isOpen) setTimeout(function(){ var i=$('abPw'); if(i&&!A) try{ i.focus({preventScroll:true}); }catch(_){ i.focus(); } },320);
}

/* ---- data ---- */
function people(){
  var out=[], u=D.u, id, p, r, s, c, ask, dn, a, l, act;
  for(id in u){
    if(!Object.prototype.hasOwnProperty.call(u,id)) continue; p=u[id]; if(!p||typeof p!=='object') continue;
    r=(p.reg&&typeof p.reg==='object')?p.reg:null; s=(p.seen&&typeof p.seen==='object')?p.seen:{}; c=obj(D.c[id]);
    ask=+p.ask||0; dn=+p.done||0; a=+s.a||0; l=+s.l||0; act=Math.max(r?(+r.t||0):0,ask);
    out.push({id:id,r:r,ask:ask,done:dn,a:a,l:l,k:+s.k||0,n:+s.n||0,w:s.w||'',act:act,
      pend:!!(r||ask)&&act>dn&&!a,
      pw:(c.pw&&typeof c.pw==='object')?c.pw:null,pwu:+c.pwu||0,b:(c.b&&typeof c.b==='object')?c.b:null,fm:+c.fm||0,ir:+c.ir||0,
      plain:typeof D.ap[id]==='string'?D.ap[id]:'',bplain:typeof D.ap['b_'+id]==='string'?D.ap['b_'+id]:''});
  }
  return out;
}
function byId(id){ var a=people(), i; for(i=0;i<a.length;i++) if(a[i].id===id) return a[i]; return null; }
function nameOf(p){ return p&&p.r?p.r.n:'Unregistered device'; }
function labelOf(p){ return p.r?(p.r.n+' · '+p.r.c):('Unregistered device …'+String(p.id).slice(-6)); }
async function load(silent){
  if(!A||loading) return; loading=true;
  var rb=$('abRef'); if(rb&&!silent) rb.classList.add('spin');
  if(!silent) setStat('Loading…','info');
  try{
    var r=await Promise.all([adb('GET','lock/u'),adb('GET','lock/c'),adb('GET','lock/ap'),adb('GET','lock/ma'),adb('GET','lock/ak')]);
    if(!A) return;
    D.u=obj(r[0]); D.c=obj(r[1]); D.ap=obj(r[2]); D.ma=obj(r[3]); D.ak=obj(r[4]); D.at=Date.now();
    setStat(''); paint(); fillPw();
  }catch(e){ if(A) setStat(dataMsg(e),'err',true); }
  finally{ loading=false; if(rb) rb.classList.remove('spin'); }
}

/* one-time passwords: made for each pending request, shown only here, saved scrambled for the phone to check */
var issueFail={};
async function issuePw(id){
  if(issuing[id]) return; issuing[id]=1; paint();
  try{
    var code=L.code(8), rec=await hashRec(code);
    await adb('PUT','lock/ap/'+id,code);
    await adb('DELETE','lock/c/'+id+'/pwu');
    await adb('PUT','lock/c/'+id+'/pw',{s:rec.s,h:rec.h,i:rec.i,t:SV});
    D.ap[id]=code; D.c[id]=obj(D.c[id]); D.c[id].pw={s:rec.s,h:rec.h,i:rec.i}; delete D.c[id].pwu; delete issueFail[id];
  }finally{ delete issuing[id]; }
}
async function fillPw(){
  if(!A||pendingAuto) return;
  var ps=people().filter(function(p){ return p.pend&&(p.r||p.ask)&&!p.pw&&!issuing[p.id]&&!(issueFail[p.id]&&Date.now()-issueFail[p.id]<5*60*1000); });
  if(!ps.length) return;
  pendingAuto=true;
  for(var i=0;i<ps.length;i++){
    if(!A) break;
    try{ await issuePw(ps[i].id); }catch(e){ issueFail[ps[i].id]=Date.now(); if(A) toast(dataMsg(e),true); }
  }
  pendingAuto=false; if(A) paint();
}

/* ---- cards ---- */
function hows(w){ return w==='f'?'one-time password':(w==='d'?'one-time password, no form':(w==='g'?'had the app before the lock':(w==='o'?'admin password':''))); }
function blockInfo(p){
  var b=p.b; if(!b) return null;
  var t=+b.t||0, d=+b.d||0;
  if(p.k&&p.k>=t) return {c:'warn',x:'Unblocked with the password'};
  if(!d) return {c:'bad',x:'🚫 Blocked · until you unblock'};
  if(Date.now()<t+d) return {c:'bad',x:'🚫 Blocked · until '+fmt(t+d)};
  return {c:'dim',x:'Block time is over'};
}
function pwBoxHtml(p){
  if(p.a||(!p.r&&!p.ask)) return '';
  var id=esc(p.id);
  if(issuing[p.id]) return '<div class="ab-code"><div class="c"><span class="l">One-time password</span><span class="v dim">Preparing…</span></div></div>';
  if(p.pw&&p.plain){
    var used=!!p.pwu;
    return '<div class="ab-code'+(used?' used':'')+'"><div class="c"><span class="l">One-time password'+(used?' · used '+esc(ago(p.pwu)):' · not used yet')+'</span><span class="v">'+esc(L.fmtCode(p.plain))+'</span></div>'
      +'<button class="ab-mini pri" type="button" data-act="copypw" data-id="'+id+'">'+IC.copy+'Copy</button><button class="ab-mini" type="button" data-act="newpw" data-id="'+id+'" aria-label="Make a new password">'+IC.ref+'New</button></div>';
  }
  if(p.pw&&!p.plain) return '<div class="ab-code"><div class="c"><span class="l">One-time password</span><span class="v dim">Not shown (made on another phone)</span></div><button class="ab-mini pri" type="button" data-act="newpw" data-id="'+id+'">'+IC.ref+'New</button></div>';
  return '<div class="ab-code"><div class="c"><span class="l">One-time password</span><span class="v dim">'+(issueFail[p.id]?'Could not be made. Tap Create.':'Not made yet')+'</span></div><button class="ab-mini pri" type="button" data-act="newpw" data-id="'+id+'">'+IC.key+'Create</button></div>';
}
function actsHtml(p,mode){
  var num=p.r?tel(p.r.m):'', id=esc(p.id), h='', h2='';
  var call=num.length>=7?'<a class="ab-act call" href="tel:'+esc(num)+'">'+IC.call+'Call</a>':'';
  var body=(p.plain&&!p.a&&p.pw)?('?body='+encodeURIComponent('Your Study Log one-time password is '+L.fmtCode(p.plain)+'. It works once, on your phone only.')):'';
  var sms=num.length>=7?'<a class="ab-act sms" href="sms:'+esc(num)+body+'">'+IC.sms+'Message</a>':'';
  if(mode==='req'){
    h=call+sms+(p.pend?'<button class="ab-act done" type="button" data-act="done" data-id="'+id+'">'+IC.ok+'Mark done</button>':(p.done?'<button class="ab-act" type="button" data-act="undo" data-id="'+id+'">Undo done</button>':''));
    return h?'<div class="ab-acts">'+h+'</div>':'';
  }
  h='<button class="ab-act insp" type="button" data-act="inspect" data-id="'+id+'">'+IC.look+'Inspect</button><button class="ab-act pop" type="button" data-act="popup" data-id="'+id+'">'+IC.bell+'Popup</button>'
    +(p.b?'<button class="ab-act unb" type="button" data-act="unblock" data-id="'+id+'">'+IC.unlock+'Unblock</button>':'<button class="ab-act blk" type="button" data-act="block" data-id="'+id+'">'+IC.ban+'Block</button>');
  if(!p.r) h2+='<button class="ab-act askd" type="button" data-act="ask" data-id="'+id+'">'+IC.ask+(p.fm?'Ask again':'Ask details')+'</button>';
  h2+=call+sms;
  return '<div class="ab-acts">'+h+'</div>'+(h2?'<div class="ab-acts">'+h2+'</div>':'');
}
function card(p,mode){
  var r=p.r, nm=nameOf(p), ini=String(nm).trim().charAt(0).toUpperCase()||'?', ch='', kv='', bi=blockInfo(p);
  if(p.pend) ch+='<span class="ab-chip new">NEW</span>';
  if(p.ask&&p.ask>p.done&&!p.a) ch+='<span class="ab-chip key">🔑 Wants the password</span>';
  if(bi) ch+='<span class="ab-chip '+bi.c+'">'+esc(bi.x)+'</span>';
  if(r&&!p.pend&&p.done&&!p.a) ch+='<span class="ab-chip ok">✓ Handled</span>';
  if(r) ch+=r.k==='y'?'<span class="ab-chip yes">Knows Amarnath</span>':'<span class="ab-chip no">Does not know Amarnath</span>';
  else if(p.fm) ch+='<span class="ab-chip warn">Details requested</span>';
  else ch+='<span class="ab-chip pur">No details yet</span>';
  if(p.a) ch+='<span class="ab-chip dim">Unlocked'+(hows(p.w)?' · '+esc(hows(p.w)):'')+'</span>'; else if(r) ch+='<span class="ab-chip dim">Not unlocked yet</span>';
  if(p.n) ch+='<span class="ab-chip dim">Privacy notice seen</span>';
  if(r){
    kv+='<div class="ab-kv"><span>Class</span><b>'+esc(r.c)+'</b></div>'
      +'<div class="ab-kv"><span>Mobile</span><b>'+esc(r.m)+'</b></div>'
      +'<div class="ab-kv"><span>Knows AMARNATH</span><b>'+(r.k==='y'?'Yes':'No')+'</b></div>'
      +'<div class="ab-kv"><span>Allowed call / message</span><b>'+(r.o?'✓ Yes':'—')+'</b></div>'
      +'<div class="ab-kv"><span>Details sent</span><b>'+esc(fmt(+r.t))+' · '+esc(ago(+r.t))+'</b></div>';
    if(p.ask) kv+='<div class="ab-kv"><span>Asked for password</span><b>'+esc(fmt(p.ask))+' · '+esc(ago(p.ask))+'</b></div>';
    if(r.x) kv+='<div class="ab-bubble"><small>Message to admin</small>'+esc(r.x)+'</div>';
  }else{
    kv+='<div class="ab-kv"><span>Device</span><b>…'+esc(String(p.id).slice(-6))+'</b></div>';
  }
  if(p.a) kv+='<div class="ab-kv"><span>Unlocked</span><b>'+esc(fmt(p.a))+'</b></div>';
  if(p.l) kv+='<div class="ab-kv"><span>Last opened</span><b>'+esc(ago(p.l))+'</b></div>';
  return '<div class="ab-p'+(p.pend?' new':'')+(bi&&bi.c==='bad'?' blocked':'')+'"><div class="ab-top"><div class="ab-av" style="--h:'+hue(p.id)+'">'+esc(ini)+'</div><div class="ab-nm"><b>'+esc(nm)+'</b><span>'+(r?esc(r.c)+' · '+esc(r.m):'No details given')+'</span></div><button class="ab-x" type="button" data-act="del" data-id="'+esc(p.id)+'" aria-label="Delete '+esc(nm)+'">'+IC.del+'</button></div>'
    +'<div class="ab-chips">'+ch+'</div>'+kv+pwBoxHtml(p)+actsHtml(p,mode)+'</div>';
}

/* popups sent so far (to everyone, or to one phone) */
function messages(){
  var out=[], id, m, uid, md;
  for(id in D.ma){ m=D.ma[id]; if(m&&typeof m==='object') out.push({id:id,m:m,to:''}); }
  for(uid in D.c){ md=obj(obj(D.c[uid]).md); for(id in md){ m=md[id]; if(m&&typeof m==='object') out.push({id:id,m:m,to:uid}); } }
  out.sort(function(a,b){ return (+b.m.t||0)-(+a.m.t||0)||(a.id<b.id?1:-1); });
  return out;
}
var STY={i:['Info','#6CB6F2','info'],w:['Warning','#F5C542','warn'],g:['Good','#5FD08A','good'],a:['Alert','#FF6B5E','alert']};
var showOldMsgs=false;
function msgCard(x){
  var m=x.m, st=STY[m.st]||STY.i, pw=m.k==='p', p=x.to?byId(x.to):null, id=esc(x.id);
  var acks=Object.keys(obj(D.ak[x.id])).length, plain=typeof D.ap['m_'+x.id]==='string'?D.ap['m_'+x.id]:'';
  var seen=x.to?(acks?'Seen ✓':'Not seen yet'):('Seen by '+acks);
  var h='<div class="ab-p"><div class="ab-top"><div class="ab-av" style="--h:'+hue(x.id)+';font-size:15px">'+(pw?'🔑':'💬')+'</div><div class="ab-nm"><b>'+esc(m.ti||'')+'</b><span>'+(x.to?'To '+esc(p?nameOf(p):'a removed user'):'To everyone')+' · '+esc(ago(+m.t))+'</span></div>'
    +'<button class="ab-x" type="button" data-act="delmsg" data-id="'+id+'" data-to="'+esc(x.to)+'" aria-label="Delete this popup">'+IC.del+'</button></div>'
    +'<div class="ab-chips"><span class="ab-chip ok">'+(pw?'Password popup':'Message')+'</span>'+(pw?'':'<span class="ab-chip dim" style="color:'+st[1]+'">'+esc(st[0])+'</span>')+'<span class="ab-chip dim">'+esc(seen)+'</span></div>'
    +'<div class="ab-bubble"><small>Message</small>'+esc(m.m||'')+'</div>';
  if(pw) h+='<div class="ab-code"><div class="c"><span class="l">Popup password</span><span class="v">'+(plain?esc(plain):'—')+'</span></div>'+(plain?'<button class="ab-mini pri" type="button" data-act="copymsgpw" data-id="'+id+'">'+IC.copy+'Copy</button>':'')+'</div>';
  return h+'</div>';
}

function paint(){
  if(!A||!$('abReq')) return;
  var all=people(), reg=0, pend=[], done=[], i, unreg=[], toAsk=[];
  for(i=0;i<all.length;i++){
    if(all[i].r) reg++; else{ unreg.push(all[i]); if(!all[i].fm) toAsk.push(all[i]); }
    if(all[i].pend) pend.push(all[i]); else if(all[i].r&&all[i].done&&!all[i].a) done.push(all[i]);
  }
  pend.sort(function(a,b){ return b.act-a.act; }); done.sort(function(a,b){ return b.done-a.done; });
  $('abN1').textContent=reg; $('abN2').textContent=pend.length; $('abN3').textContent=all.length;
  var bd=$('abB1'); bd.textContent=pend.length; bd.className=pend.length?'show':'';
  $('abUpd').textContent=D.at?'Updated '+fmt(D.at):'';
  var h='';
  if(!pend.length) h+='<div class="ab-empty"><b>No pending requests</b>New requests from people who fill the form will show up here, each with its own one-time password.</div>';
  else h+=pend.map(function(p){ return card(p,'req'); }).join('');
  if(done.length){
    h+='<button class="ab-more" type="button" data-act="toggledone">'+(showDone?'Hide':'Show')+' handled ('+done.length+')</button>';
    if(showDone) h+=done.map(function(p){ return card(p,'req'); }).join('');
  }
  $('abReq').innerHTML=h;
  /* users */
  var bar=$('abUsrBar');
  if(unreg.length) bar.innerHTML=toAsk.length?'<button class="ab-btn" type="button" data-act="askall">'+IC.ask.replace('<svg','<svg style="width:16px;height:16px;vertical-align:-3px;margin-right:6px"')+'Ask all '+toAsk.length+' unregistered for details</button>':'<button class="ab-btn alt" type="button" disabled style="flex:1">All '+unreg.length+' unregistered users were asked ✓</button>';
  else bar.innerHTML='';
  var q=($('abQ').value||'').trim().toLowerCase(), list=all.slice();
  list.sort(function(a,b){ return Math.max(b.l,b.act,b.a)-Math.max(a.l,a.act,a.a); });
  if(q) list=list.filter(function(p){ var r=p.r; return r&&((r.n||'').toLowerCase().indexOf(q)>-1||(r.c||'').toLowerCase().indexOf(q)>-1||tel(r.m).indexOf(tel(q)||'~')>-1); });
  $('abUsr').innerHTML=list.length?list.map(function(p){ return card(p,'usr'); }).join(''):'<div class="ab-empty"><b>'+(q?'No match':'No users yet')+'</b>'+(q?'Try a different name, class or number.':'People who unlock the app will be listed here.')+'</div>';
  /* popups */
  var ms=messages(), mh='';
  if(!ms.length) mh='<div class="ab-empty"><b>No popups sent yet</b>Tap New popup to send a message, or a password popup, to everyone or to one person.</div>';
  else{
    var shown=showOldMsgs?ms:ms.slice(0,25);
    mh=shown.map(msgCard).join('');
    if(ms.length>25) mh+='<button class="ab-more" type="button" data-act="oldmsgs">'+(showOldMsgs?'Show fewer':'Show older ('+(ms.length-25)+')')+'</button>';
  }
  $('abMsgs').innerHTML=mh;
}

/* ---- sheets ---- */
function openSheet(title,bodyHtml,onClose){
  var sh=$('abSh');
  sh.innerHTML='<div class="ab-sh-h"><h3 id="abShT"></h3><button class="ab-ib" type="button" data-act="shclose" aria-label="Close">'+IC.close+'</button></div><div class="ab-sh-b" id="abShB">'+bodyHtml+'</div>';
  $('abShT').textContent=title;
  $('abSheet').classList.add('open'); SH={onClose:onClose||null};
  var b=$('abShB'); if(b) b.scrollTop=0;
}
function closeSheet(quiet){
  if(!SH) return; var cb=SH.onClose; SH=null;
  var s=$('abSheet'); if(s) s.classList.remove('open');
  BL=null; CP=null;
  if(cb) cb();
}
function shMsg(id,m,cls){ var e=$(id); if(!e) return; e.textContent=m||''; e.className='ab-msg'+(m?' show '+(cls||'err'):''); }
function setOn(group,btn){
  Array.prototype.forEach.call(group.querySelectorAll('.ab-o'),function(x){ x.classList.toggle('on',x===btn); });
}
function sheetBusy(b,on,txt){ if(!b) return; b.disabled=on; if(on) b.innerHTML='<span class="ab-spin"></span>Working…'; else b.textContent=txt; }
document.addEventListener('input',function(e){ if(SH&&e.target&&e.target.closest&&e.target.closest('#abSh')) sheetInput(e); });
document.addEventListener('change',function(e){ if(SH&&e.target&&e.target.closest&&e.target.closest('#abSh')) sheetInput(e); });
function sheetInput(e){
  var id=e.target.id;
  if(BL){
    if(id==='blMsg') $('blCnt').textContent=e.target.value.length+'/300';
    if(id==='blPwOn') $('blPwBox').hidden=!e.target.checked;
  }
  if(CP){
    if(id==='cpTi') $('cpTiC').textContent=e.target.value.length+'/80';
    if(id==='cpMsg') $('cpMC').textContent=e.target.value.length+'/600';
    if(id==='cpSel') CP.to=e.target.value;
    paintPv();
  }
}

/* ---- one request / user actions ---- */
async function doNewPw(id,btn){
  var p=byId(id); if(!p) return;
  if(p.pw&&p.plain&&!p.pwu&&!window.confirm('Make a new password for '+nameOf(p)+'?\nThe old one will stop working.')) return;
  if(btn) btn.disabled=true;
  try{ await issuePw(id); paint(); toast('New password ready'); }
  catch(e){ issueFail[id]=Date.now(); if(btn) btn.disabled=false; paint(); toast(dataMsg(e),true); }
}
async function doDone(a,id,btn){
  if(!D.u[id]) return; btn.disabled=true;
  try{
    if(a==='done'){ await adb('PATCH','lock/u/'+id,{done:SV}); var dv=await adb('GET','lock/u/'+id+'/done'); D.u[id].done=+dv||Date.now(); }
    else{ await adb('PATCH','lock/u/'+id,{done:null}); delete D.u[id].done; }
    paint(); toast(a==='done'?'Marked as done':'Moved back to requests');
  }catch(e){ btn.disabled=false; toast(dataMsg(e),true); }
}
async function doDel(id,btn){
  var p=byId(id); if(!p) return;
  if(!window.confirm('Delete '+nameOf(p)+' from the list?\nTheir request, password and saved copy of their data are removed.\n\nTheir phone can still open the app (use Block to stop that), and they show up again if they open it.')) return;
  btn.disabled=true;
  try{
    await Promise.all(['lock/u/'+id,'lock/c/'+id,'lock/ap/'+id,'lock/ap/b_'+id,'lock/ins/'+id].map(function(path){ return adb('DELETE',path); }));
    delete D.u[id]; delete D.c[id]; delete D.ap[id]; delete D.ap['b_'+id];
    paint(); toast('Deleted');
  }catch(e){ btn.disabled=false; toast(dataMsg(e),true); }
}
async function doAsk(ids,btn){
  if(btn) btn.disabled=true;
  try{
    await inChunks(ids,6,function(id){ return adb('PUT','lock/c/'+id+'/fm',SV); });
    var now=Date.now(); ids.forEach(function(id){ D.c[id]=obj(D.c[id]); D.c[id].fm=now; });
    paint(); toast(ids.length>1?'Asked '+ids.length+' users':'Asked. They see the form next time the app is open.');
  }catch(e){ if(btn) btn.disabled=false; toast(dataMsg(e),true); }
}
async function doAskAll(btn){
  var ids=people().filter(function(p){ return !p.r&&!p.fm; }).map(function(p){ return p.id; });
  if(!ids.length) return;
  if(!window.confirm('Ask '+ids.length+' unregistered user'+(ids.length>1?'s':'')+' to fill in their details?\nThey see the form the next time the app is open and cannot use the app until they send it.')) return;
  await doAsk(ids,btn);
}
async function doUnblock(id,btn){
  var p=byId(id); if(!p||!p.b) return;
  if(btn) btn.disabled=true;
  try{
    await adb('DELETE','lock/c/'+id+'/b'); await adb('DELETE','lock/ap/b_'+id);
    if(D.c[id]) delete D.c[id].b; delete D.ap['b_'+id];
    paint(); toast(nameOf(p)+' is unblocked. Their app opens again within a minute.');
  }catch(e){ if(btn) btn.disabled=false; toast(dataMsg(e),true); }
}
async function doDelMsg(id,to,btn){
  if(!window.confirm('Delete this popup?\nPeople who have not seen it yet will not get it.')) return;
  btn.disabled=true;
  try{
    await adb('DELETE',to?'lock/c/'+to+'/md/'+id:'lock/ma/'+id);
    await adb('DELETE','lock/ap/m_'+id); await adb('DELETE','lock/ak/'+id);
    if(to){ if(D.c[to]&&D.c[to].md) delete D.c[to].md[id]; } else delete D.ma[id];
    delete D.ap['m_'+id]; delete D.ak[id];
    paint(); toast('Deleted');
  }catch(e){ btn.disabled=false; toast(dataMsg(e),true); }
}

/* ---- block sheet ---- */
var BL=null, CP=null;
var DUR=[['1 hour',3600000],['6 hours',21600000],['1 day',86400000],['7 days',604800000],['Until I unblock',0]];
function openBlock(id){
  var p=byId(id); if(!p) return;
  BL={id:id,d:DUR[0][1]};
  var body='<p class="ab-sub" style="margin:0 0 2px">'+esc(nameOf(p))+' will not be able to use Study Log. It takes effect within about a minute, when their app next checks.</p>'
    +'<label class="ab-lb">How long</label><div class="ab-opts" id="blDur">'+DUR.map(function(d,i){ return '<button class="ab-o'+(i===0?' on':'')+'" type="button" data-act="bldur" data-v="'+d[1]+'">'+esc(d[0])+'</button>'; }).join('')+'</div>'
    +'<label class="ab-lb" for="blMsg">Message they will see <small>(optional)</small></label><textarea class="ab-in" id="blMsg" maxlength="300" rows="3" placeholder="e.g. Please talk to Amarnath."></textarea><span class="ab-cnt" id="blCnt">0/300</span>'
    +'<label class="ab-chk"><input type="checkbox" id="blPwOn"><span>Let them unblock themselves with a one-time password</span></label>'
    +'<div id="blPwBox" hidden><label class="ab-lb" for="blPw">One-time unblock password</label><div class="ab-pwrow"><input class="ab-in" id="blPw" type="text" autocomplete="off" autocapitalize="characters" autocorrect="off" spellcheck="false" maxlength="40" value="'+esc(L.fmtCode(L.code(8)))+'"><button class="ab-mini" type="button" data-act="blgen">'+IC.wand+'New</button><button class="ab-mini pri" type="button" data-act="blcopy">'+IC.copy+'Copy</button></div><p class="ab-hint">Send it to them yourself. When they type it, the block lifts on their phone. It is saved scrambled for the phone to check.</p></div>'
    +'<div class="ab-msg" id="blErr" role="alert"></div><button class="ab-btn dng" id="blGo" type="button" data-act="blgo">Block '+esc(nameOf(p))+'</button>';
  openSheet('Block user',body);
}
async function blGo(btn){
  if(!BL) return;
  var id=BL.id, p=byId(id), msg=$('blMsg').value.trim(), on=$('blPwOn').checked, raw=$('blPw').value.trim(), code=L.nCode(raw);
  if(on&&code.length<4){ shMsg('blErr','Use at least 4 characters for the unblock password.'); return; }
  shMsg('blErr',''); var label=btn.textContent; sheetBusy(btn,true);
  try{
    var rec={t:SV,d:BL.d}; if(msg) rec.m=msg;
    if(on){ var hr=await hashRec(code); rec.s=hr.s; rec.h=hr.h; rec.i=hr.i; await adb('PUT','lock/ap/b_'+id,raw); }
    else await adb('DELETE','lock/ap/b_'+id);
    await adb('PUT','lock/c/'+id+'/b',rec);
    closeSheet(); toast((p?nameOf(p):'User')+' is blocked'); load(true);
  }catch(e){ sheetBusy(btn,false,label); shMsg('blErr',dataMsg(e)); }
}

/* ---- popup sheet ---- */
var PVI={
  info:IC.bell,
  warn:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.9L2.4 17.5A2 2 0 0 0 4.1 20.5h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4.5M12 17h.01"/></svg>',
  good:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M7.8 12.4l2.8 2.8 5.6-6.2"/></svg>',
  alert:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M8.3 2.5h7.4l5.3 5.3v7.4l-5.3 5.3H8.3L3 15.2V7.8z"/><path d="M12 7.5v5.2M12 16.3h.01"/></svg>',
  pass:IC.key
};
function openCompose(toId){
  var ps=people().sort(function(a,b){ return nameOf(a).toLowerCase()<nameOf(b).toLowerCase()?-1:1; });
  CP={to:toId||'',kind:'i',st:'i'};
  var opts=ps.map(function(p){ return '<option value="'+esc(p.id)+'"'+(p.id===toId?' selected':'')+'>'+esc(labelOf(p))+'</option>'; }).join('');
  if(!CP.to&&ps.length) CP.sel=ps[0].id;
  var body='<label class="ab-lb">Send to</label><div class="ab-opts" id="cpTo"><button class="ab-o'+(toId?'':' on')+'" type="button" data-act="cpto" data-v="all">Everyone</button><button class="ab-o'+(toId?' on':'')+'" type="button" data-act="cpto" data-v="one">One person</button></div>'
    +'<div id="cpWho"'+(toId?'':' hidden')+' style="margin-top:8px"><select class="ab-in" id="cpSel">'+(opts||'<option value="">No users yet</option>')+'</select></div>'
    +'<label class="ab-lb">Type</label><div class="ab-opts" id="cpKind"><button class="ab-o on" type="button" data-act="cpkind" data-v="i">Message</button><button class="ab-o" type="button" data-act="cpkind" data-v="p">🔑 Password popup</button></div>'
    +'<div id="cpStyle"><label class="ab-lb">Style</label><div class="ab-opts" id="cpSt">'+['i','w','g','a'].map(function(k,i){ return '<button class="ab-o'+(i===0?' on':'')+'" type="button" data-act="cpst" data-v="'+k+'" style="--oc:'+STY[k][1]+'"><i></i>'+STY[k][0]+'</button>'; }).join('')+'</div></div>'
    +'<label class="ab-lb" for="cpTi">Title</label><input class="ab-in" id="cpTi" maxlength="80" autocomplete="off" placeholder="e.g. Exam week"><span class="ab-cnt" id="cpTiC">0/80</span>'
    +'<label class="ab-lb" for="cpMsg">Message</label><textarea class="ab-in" id="cpMsg" maxlength="600" rows="4" placeholder="Write your message…"></textarea><span class="ab-cnt" id="cpMC">0/600</span>'
    +'<div id="cpPwBox" hidden><label class="ab-lb" for="cpPw">Popup password</label><div class="ab-pwrow"><input class="ab-in" id="cpPw" type="text" autocomplete="off" autocapitalize="characters" autocorrect="off" spellcheck="false" maxlength="40" value="'+esc(L.fmtCode(L.code(8)))+'"><button class="ab-mini" type="button" data-act="cpgen">'+IC.wand+'New</button><button class="ab-mini pri" type="button" data-act="cpcopy">'+IC.copy+'Copy</button></div><p class="ab-hint">They cannot close this popup until they type this password. Send it to them yourself. It is saved scrambled for their phone to check.</p></div>'
    +'<div class="ab-pvl">Preview</div><div class="ab-pv sl-th-info" id="cpPv"></div>'
    +'<div class="ab-msg" id="cpErr" role="alert"></div><button class="ab-btn" id="cpGo" type="button" data-act="cpgo">Send popup</button>';
  openSheet(toId?'Popup to '+nameOf(byId(toId)):'New popup',body);
  paintPv();
}
function paintPv(){
  var pv=$('cpPv'); if(!pv||!CP) return;
  var th=CP.kind==='p'?'pass':STY[CP.st][2], ti=$('cpTi').value.trim(), m=$('cpMsg').value.trim();
  pv.className='ab-pv sl-th-'+th;
  pv.innerHTML='<div class="ic">'+PVI[th]+'</div><div class="t">'+esc(ti||'Title')+'</div><div class="m">'+esc(m||'Your message appears here.')+'</div>'+(CP.kind==='p'?'<div class="m" style="margin-top:8px;color:#F2B84B">🔑 They must type the password to continue.</div>':'');
}
async function pruneMd(uid){
  try{
    var md=obj(await adb('GET','lock/c/'+uid+'/md')), ids=Object.keys(md).sort();
    if(ids.length<=10) return;
    var old=ids.slice(0,ids.length-10);
    await Promise.all(old.map(function(id){ return Promise.all([adb('DELETE','lock/c/'+uid+'/md/'+id),adb('DELETE','lock/ap/m_'+id),adb('DELETE','lock/ak/'+id)]); }));
  }catch(e){}
}
async function cpGo(btn){
  if(!CP) return;
  var ti=$('cpTi').value.trim(), m=$('cpMsg').value.trim(), who=$('cpWho').hidden?'':($('cpSel').value||''), pk=CP.kind==='p', raw=$('cpPw').value.trim(), code=L.nCode(raw);
  if(!$('cpWho').hidden&&!who){ shMsg('cpErr','Choose who to send it to.'); return; }
  if(!ti){ shMsg('cpErr','Write a title.'); return; }
  if(!m){ shMsg('cpErr','Write a message.'); return; }
  if(pk&&code.length<4){ shMsg('cpErr','Use at least 4 characters for the popup password.'); return; }
  shMsg('cpErr',''); var label=btn.textContent; sheetBusy(btn,true);
  try{
    var mid=newMid(), rec={t:SV,k:pk?'p':'i',st:pk?'i':CP.st,ti:ti,m:m};
    if(pk){ var hr=await hashRec(code); rec.s=hr.s; rec.h=hr.h; rec.i=hr.i; await adb('PUT','lock/ap/m_'+mid,raw); }
    if(who){ await adb('PUT','lock/c/'+who+'/md/'+mid,rec); pruneMd(who); }
    else await adb('PUT','lock/ma/'+mid,rec);
    closeSheet(); toast(who?'Popup sent':'Popup sent to everyone'); load(true);
  }catch(e){ sheetBusy(btn,false,label); shMsg('cpErr',dataMsg(e)); }
}

/* ---- action router ---- */
function act(a,id,btn){
  var v=btn.getAttribute('data-v');
  switch(a){
    case 'toggledone': showDone=!showDone; paint(); return;
    case 'oldmsgs': showOldMsgs=!showOldMsgs; paint(); return;
    case 'shclose': closeSheet(); return;
    case 'copypw': { var p=byId(id); if(p&&p.plain) copyToast(L.fmtCode(p.plain),'Password copied'); return; }
    case 'copymsgpw': { var t=D.ap['m_'+id]; if(t) copyToast(t,'Password copied'); return; }
    case 'newpw': doNewPw(id,btn); return;
    case 'done': case 'undo': doDone(a,id,btn); return;
    case 'del': doDel(id,btn); return;
    case 'ask': doAsk([id],btn); return;
    case 'askall': doAskAll(btn); return;
    case 'block': openBlock(id); return;
    case 'unblock': doUnblock(id,btn); return;
    case 'popup': openCompose(id); return;
    case 'newpop': openCompose(''); return;
    case 'inspect': openInspect(id); return;
    case 'delmsg': doDelMsg(id,btn.getAttribute('data-to'),btn); return;
    case 'bldur': if(BL){ BL.d=+v; setOn($('blDur'),btn); } return;
    case 'blgen': $('blPw').value=L.fmtCode(L.code(8)); return;
    case 'blcopy': copyToast($('blPw').value,'Password copied'); return;
    case 'blgo': blGo(btn); return;
    case 'cpto': if(CP){ setOn($('cpTo'),btn); $('cpWho').hidden=v!=='one'; if(v==='one'&&!CP.to&&$('cpSel')) CP.to=$('cpSel').value; paintPv(); } return;
    case 'cpkind': if(CP){ CP.kind=v; setOn($('cpKind'),btn); $('cpPwBox').hidden=v!=='p'; $('cpStyle').hidden=v==='p'; paintPv(); } return;
    case 'cpst': if(CP){ CP.st=v; setOn($('cpSt'),btn); paintPv(); } return;
    case 'cpgen': $('cpPw').value=L.fmtCode(L.code(8)); return;
    case 'cpcopy': copyToast($('cpPw').value,'Password copied'); return;
    case 'cpgo': cpGo(btn); return;
    case 'insreq': insRequest(); return;
    case 'inswatch': insWatch(btn); return;
    case 'inscopy': insCopy(); return;
  }
}

/* ---- inspect: a copy of this person's study data, uploaded by their phone when asked ---- */
var INSWAIT=150000, INSLIVE=10*60*1000;
function stopIns(){ if(INS){ INS.dead=true; clearInterval(INS.tm); } INS=null; }
function p2(n){ return n<10?'0'+n:''+n; }
function dayFn(tz){
  var f=null;
  try{ f=new Intl.DateTimeFormat('en-US',{timeZone:tz||undefined,year:'numeric',month:'2-digit',day:'2-digit'}); }catch(e){ f=null; }
  return function(ts){
    var dt=new Date(ts);
    if(f&&f.formatToParts){
      try{
        var y='',mo='',da='',ps=f.formatToParts(dt),i;
        for(i=0;i<ps.length;i++){ if(ps[i].type==='year') y=ps[i].value; else if(ps[i].type==='month') mo=ps[i].value; else if(ps[i].type==='day') da=ps[i].value; }
        if(y&&mo&&da) return y+'-'+mo+'-'+da;
      }catch(e){}
    }
    return dt.getFullYear()+'-'+p2(dt.getMonth()+1)+'-'+p2(dt.getDate());
  };
}
function backKey(k,n){
  var a=String(k).split('-'), x=new Date(Date.UTC(+a[0],+a[1]-1,+a[2]-n));
  return x.getUTCFullYear()+'-'+p2(x.getUTCMonth()+1)+'-'+p2(x.getUTCDate());
}
function dow(k){ var a=String(k).split('-'); return ['Sun','Mon','Tue','Wed','Thu','Fri','Sat'][new Date(Date.UTC(+a[0],+a[1]-1,+a[2])).getUTCDay()]; }
function hm(n){ n=Math.max(0,Math.round(+n||0)); return n<60?n+'m':Math.floor(n/60)+'h '+p2(n%60)+'m'; }
function clock(sec){ sec=Math.max(0,Math.floor(+sec||0)); var h=Math.floor(sec/3600), m=Math.floor(sec%3600/60), s=sec%60; return (h?h+':'+p2(m):m)+':'+p2(s); }
function safeCol(c){ return /^#[0-9a-fA-F]{3,8}$/.test(String(c||''))?c:'#6E7A8A'; }
function clip(s,n){ s=String(s==null?'':s); return s.length>n?s.slice(0,n)+'…':s; }
function whenAt(ts,tz){
  try{ return new Date(ts).toLocaleString('en-US',{timeZone:tz||undefined,weekday:'short',day:'numeric',month:'short',hour:'numeric',minute:'2-digit'}); }
  catch(e){ return fmt(ts); }
}
function insStats(d,m){
  var df=dayFn(m.tz), now=+m.now||Date.now(), today=df(now), byDay={}, total=0, s=Array.isArray(d.sessions)?d.sessions:[], i, x, k, dm, week=0, streak=0, cur;
  for(i=0;i<s.length;i++){
    x=s[i]; if(!x||typeof x!=='object') continue;
    dm=+x.durationMin||0; if(dm<0) dm=0; total+=dm; k=df(+x.start||0); byDay[k]=(byDay[k]||0)+dm;
  }
  for(i=0;i<7;i++) week+=byDay[backKey(today,i)]||0;
  cur=today; if(!byDay[cur]) cur=backKey(today,1);
  while(byDay[cur]&&streak<4000){ streak++; cur=backKey(cur,1); }
  return {today:today,tm:byDay[today]||0,week:week,total:total,streak:streak,days:Object.keys(byDay).length,byDay:byDay,n:s.length};
}
function insTake(rec){
  var I=INS; if(!I||!rec||typeof rec!=='object'||typeof rec.j!=='string') return;
  var o=null; try{ o=JSON.parse(rec.j); }catch(e){ o=null; }
  if(!o||typeof o!=='object'||Array.isArray(o)) return;
  I.rec=rec; I.at=+rec.t||0; I.data=o;
}
function openInspect(id){
  var p=byId(id); if(!p) return;
  stopIns();
  INS={id:id,name:nameOf(p),rec:null,data:null,at:0,req:0,sent:0,st:'load',watch:false,wstart:0,open:{},tm:0,dead:false,busy:false,ticking:false,err:''};
  openSheet('Inspect · '+nameOf(p),'<div id="insBody"></div>',stopIns);
  insPaint();
  insStart(INS);
}
async function insStart(I){
  try{
    var rec=await adb('GET','lock/ins/'+I.id,undefined,30000);
    if(INS!==I) return;
    if(rec) insTake(rec);
  }catch(e){ if(INS===I) I.err=dataMsg(e); }
  if(INS!==I) return;
  insPaint();
  I.tm=setInterval(insTick,4000);
  await insRequest();
}
async function insRequest(){
  var I=INS; if(!I||I.busy) return;
  I.busy=true; I.err=''; insPaint();
  try{
    await adb('PUT','lock/c/'+I.id+'/ir',SV);
    var v=await adb('GET','lock/c/'+I.id+'/ir');
    if(INS!==I) return;
    I.req=+v||Date.now(); I.sent=Date.now(); I.st=(I.at&&I.at>=I.req)?'got':'wait';
    if(D.c[I.id]) D.c[I.id].ir=I.req;
  }catch(e){ if(INS===I) I.err=dataMsg(e); }
  finally{ I.busy=false; }
  if(INS===I) insPaint();
}
async function insTick(){
  var I=INS; if(!I||I.dead||I.ticking||!A||I.busy) return;
  I.ticking=true;
  try{
    var t=+(await adb('GET','lock/ins/'+I.id+'/t'))||0;
    if(INS!==I) return;
    if(t>I.at){
      var rec=await adb('GET','lock/ins/'+I.id,undefined,30000);
      if(INS!==I) return;
      insTake(rec);
    }
    if(I.st==='wait'){
      if(I.at&&I.at>=I.req) I.st='got';
      else if(Date.now()-I.sent>INSWAIT) I.st='late';
    }
    if(I.watch){
      if(Date.now()-I.wstart>INSLIVE) I.watch=false;
      else if((I.st==='got'||I.st==='late')&&Date.now()-I.sent>=12000){ I.ticking=false; insPaint(); insRequest(); return; }
    }
    if(I.err) I.err='';
    insPaint();
  }catch(e){
    if(INS===I){ I.err=dataMsg(e); insPaint(); }
  }finally{ I.ticking=false; }
}
function insWatch(){
  var I=INS; if(!I) return;
  I.watch=!I.watch; I.wstart=Date.now();
  if(I.watch&&!I.busy&&I.st!=='wait') insRequest(); else insPaint();
}
function insCopy(){
  var I=INS; if(!I||!I.data){ toast('Nothing to copy yet',true); return; }
  var txt=JSON.stringify({user:I.name,device:I.id,takenAt:new Date(I.at).toISOString(),phone:I.data.m,data:I.data.d},null,1);
  copyToast(txt,'Copied everything');
}
function insPaint(){
  var I=INS, body=$('insBody'); if(!I||!body) return;
  Array.prototype.forEach.call(body.querySelectorAll('details[data-k]'),function(d){ I.open[d.getAttribute('data-k')]=d.open; });
  body.innerHTML=insHtml(I);
}
function rawSec(I,k,title,v,n){
  if(v===undefined||v===null) return '';
  var s; try{ s=JSON.stringify(v,null,1); }catch(e){ s=String(v); }
  var cut=s.length>20000;
  return '<details class="ab-d" data-k="'+esc(k)+'"'+(I.open[k]?' open':'')+'><summary>'+esc(title)+(n!=null?' · '+n:'')+'</summary><pre class="ab-pre">'+esc(cut?s.slice(0,20000):s)+(cut?'\n… (shortened here. Use "Copy all" for the full data)':'')+'</pre></details>';
}
function insHtml(I){
  var o=I.data, m=o?obj(o.m):{}, d=o?obj(o.d):{}, p=byId(I.id), h='', st=null, subj={}, i, x, now=I.at?(+m.now||I.at):Date.now();
  var ctl='<div class="ab-opts" style="margin:8px 0 2px"><button class="ab-mini" style="flex:1" type="button" data-act="insreq"'+(I.busy?' disabled':'')+'>'+IC.ref+'Refresh</button><button class="ab-mini'+(I.watch?' pri':'')+'" style="flex:1" type="button" data-act="inswatch">'+(I.watch?'● Live on':'Watch live')+'</button><button class="ab-mini" style="flex:1" type="button" data-act="inscopy">'+IC.copy+'Copy all</button></div>';
  /* banner */
  var fresh=(I.st==='got');
  if(I.err) h+='<div class="ab-msg show err">'+esc(I.err)+'</div>';
  if(I.st==='load'||I.st==='wait'){
    h+='<div class="ab-live wait"><span class="dot"></span><div>Asking this phone for fresh data…<br><small>It arrives within about a minute while the app is open. If the app is closed, it arrives the next time they open it.'+((p&&!p.n)?' They have not seen the privacy notice yet, so nothing is sent until they open the app and tap OK.':'')+'</small></div></div>';
  }else if(I.st==='late'){
    h+='<div class="ab-live off"><span class="dot"></span><div>No fresh answer yet.'+(I.at?' Showing the copy from '+esc(ago(I.at))+'.':'')+'<br><small>The phone answers when its app is open'+((p&&!p.n)?' and the privacy notice has been accepted':'')+'. Tap Refresh to ask again.</small></div></div>';
  }
  if(!o){
    h+='<div class="ab-empty" style="margin-top:12px"><b>No data yet</b>'+(I.st==='late'?'This phone has not answered.':'Waiting for the first copy from this phone.')+'</div>';
    return h+ctl;
  }
  for(i=0;i<(Array.isArray(d.subjects)?d.subjects.length:0);i++){ x=d.subjects[i]; if(x&&typeof x==='object') subj[x.id]=x; }
  var S2=insStats(d,m), at=d.activeTimer&&typeof d.activeTimer==='object'?d.activeTimer:null, goal=+obj(d.settings).dailyGoalMin||120;
  /* studying now */
  if(at&&at.phase&&at.subjectId!=null){
    var el=(+at.elapsedSec||0)+(at.phase==='running'?Math.max(0,(now-(+at.savedAt||now))/1000):0), nm=subj[at.subjectId]?subj[at.subjectId].name:'a subject', tg=+at.targetSec||0;
    h+='<div class="ab-live'+(fresh?'':' wait')+'"><span class="dot"></span><div><b>'+(at.isBreak?'On a break':'Studying '+esc(nm))+'</b> · '+esc(clock(el))+(tg>0?' of '+esc(clock(tg)):'')+' · '+(at.phase==='running'?'running':'paused')+'<br><small>'+esc(at.mode==='stopwatch'||!at.mode?'Stopwatch':String(at.mode))+' · as of '+esc(ago(I.at))+'</small></div></div>';
  }else{
    h+='<div class="ab-live off"><span class="dot"></span><div>Not studying right now<br><small>As of '+esc(ago(I.at))+' ('+esc(fmt(I.at))+')</small></div></div>';
  }
  h+=ctl;
  /* tiles */
  h+='<div class="ab-tiles"><div class="ab-tile"><b>'+esc(hm(S2.tm))+'</b><span>Today</span></div><div class="ab-tile"><b>'+esc(hm(S2.week))+'</b><span>Last 7 days</span></div><div class="ab-tile"><b>'+esc(hm(S2.total))+'</b><span>All time</span></div><div class="ab-tile"><b>'+S2.streak+(S2.streak===1?' day':' days')+'</b><span>Streak</span></div></div>';
  /* daily goal */
  var pc=Math.max(0,Math.min(100,Math.round(S2.tm/goal*100)));
  h+='<div class="ab-row" style="border:0;display:block"><div style="display:flex;justify-content:space-between;font-size:13px"><span>Daily goal · '+esc(hm(goal))+'</span><b>'+Math.round(S2.tm/goal*100)+'%</b></div><div class="ab-meter"><i style="width:'+pc+'%"></i></div></div>';
  /* last 7 days */
  var mx=1, k, days=[];
  for(i=6;i>=0;i--){ k=backKey(S2.today,i); days.push([k,S2.byDay[k]||0]); if((S2.byDay[k]||0)>mx) mx=S2.byDay[k]; }
  h+='<div class="ab-h4">Last 7 days</div><div style="display:flex;gap:6px;align-items:flex-end;margin:4px 0 2px">'
    +days.map(function(a){ var px=a[1]?Math.max(4,Math.round(a[1]/mx*56)):2; return '<div style="flex:1;text-align:center;min-width:0"><div style="font:600 9.5px Inter,sans-serif;color:#9294A3;margin-bottom:3px">'+(a[1]?esc(hm(a[1])):'')+'</div><div style="height:'+px+'px;border-radius:5px 5px 2px 2px;background:'+(a[1]?'linear-gradient(180deg,#F7BE5E,#E8A33D)':'#2E313D')+'"></div><div style="font:600 9.5px Inter,sans-serif;color:#7A7C88;margin-top:4px">'+esc(dow(a[0]))+'</div></div>'; }).join('')+'</div>';
  /* subjects */
  var rows=[], sess=Array.isArray(d.sessions)?d.sessions:[], tot={}, tod={}, df=dayFn(m.tz);
  for(i=0;i<sess.length;i++){ x=sess[i]; if(!x||typeof x!=='object') continue; var sid=String(x.subjectId), dm=Math.max(0,+x.durationMin||0); tot[sid]=(tot[sid]||0)+dm; if(df(+x.start||0)===S2.today) tod[sid]=(tod[sid]||0)+dm; }
  Object.keys(tot).forEach(function(sid){ rows.push({sid:sid,t:tot[sid],d:tod[sid]||0}); });
  Object.keys(subj).forEach(function(sid){ if(tot[sid]==null) rows.push({sid:sid,t:0,d:0}); });
  rows.sort(function(a,b){ return b.t-a.t; });
  h+='<div class="ab-h4">Subjects</div>'+(rows.length?rows.map(function(r){
    var s=subj[r.sid];
    return '<div class="ab-row"><span class="d" style="background:'+esc(safeCol(s&&s.color))+'"></span><div class="n">'+esc(s?clip(s.name,60):'Removed subject')+'<small>Today '+esc(hm(r.d))+(s&&+s.dailyGoalMin?' · goal '+esc(hm(+s.dailyGoalMin)):'')+'</small></div><div class="r">'+esc(hm(r.t))+'</div></div>';
  }).join(''):'<div class="ab-hint">No subjects.</div>');
  /* recent sessions */
  var rec=sess.filter(function(a){ return a&&typeof a==='object'; }).sort(function(a,b){ return (+b.start||0)-(+a.start||0); }).slice(0,8);
  h+='<div class="ab-h4">Recent sessions · '+S2.n+' in total</div>'+(rec.length?rec.map(function(a){
    var s=subj[a.subjectId];
    return '<div class="ab-row"><span class="d" style="background:'+esc(safeCol(s&&s.color))+'"></span><div class="n">'+esc(s?clip(s.name,60):'Removed subject')+'<small>'+esc(whenAt(+a.start||0,m.tz))+'</small></div><div class="r">'+esc(hm(+a.durationMin||0))+'</div></div>';
  }).join(''):'<div class="ab-hint">No study sessions yet.</div>');
  /* to-do */
  var td=(Array.isArray(d.todos)?d.todos:[]).filter(function(a){ return a&&typeof a==='object'; }), open=td.filter(function(a){ return !a.done; }), dn=td.filter(function(a){ return a.done; });
  td=open.concat(dn).slice(0,14);
  h+='<div class="ab-h4">To-do · '+open.length+' open, '+dn.length+' done</div>'+(td.length?td.map(function(a){
    var s=subj[a.subjectId], due=a.endDate?('due '+a.endDate+(a.endTime?' '+a.endTime:'')):(a.todayOnly?'today only':'');
    return '<div class="ab-row'+(a.done?' done':'')+'"><span class="d" style="background:'+esc(safeCol(s&&s.color))+'"></span><div class="n">'+esc(clip(a.text,160))+((s||due)?'<small>'+esc((s?clip(s.name,40):'')+(s&&due?' · ':'')+due)+'</small>':'')+'</div></div>';
  }).join(''):'<div class="ab-hint">Nothing in the to-do list.</div>');
  /* achievements */
  var ac=obj(d.achievements), at1=Object.keys(obj(ac.total)).map(Number).sort(function(a,b){ return a-b; }), at2=Object.keys(obj(ac.daily)).map(Number).sort(function(a,b){ return a-b; });
  h+='<div class="ab-h4">Achievements</div><div class="ab-kv"><span>Total-hours badges</span><b>'+(at1.length?esc(at1.join('h, ')+'h'):'none yet')+'</b></div><div class="ab-kv"><span>Daily-hours badges</span><b>'+(at2.length?esc(at2.join('h, ')+'h'):'none yet')+'</b></div>';
  /* phone */
  h+='<div class="ab-h4">Phone</div>'
    +'<div class="ab-kv"><span>Copy taken</span><b>'+esc(fmt(I.at))+'</b></div>'
    +'<div class="ab-kv"><span>Time zone</span><b>'+esc(m.tz||'—')+'</b></div>'
    +'<div class="ab-kv"><span>Installed app</span><b>'+(m.sa?'Yes':'No (in browser)')+'</b></div>'
    +'<div class="ab-kv"><span>App version</span><b>'+esc(m.rel||I.rec&&I.rec.r||'—')+'</b></div>'
    +'<div class="ab-kv"><span>Screen</span><b>'+esc((m.sw||'?')+' × '+(m.sh||'?'))+'</b></div>'
    +(m.ua?'<div class="ab-bubble"><small>Browser</small>'+esc(clip(m.ua,220))+'</div>':'');
  if(m.cut&&m.cut.length) h+='<div class="ab-hint">This copy was shortened to fit: '+esc(m.cut.join(', '))+'.</div>';
  /* raw data */
  h+='<div class="ab-h4">Everything (raw)</div>'
    +rawSec(I,'r-sub','Subjects',d.subjects,Array.isArray(d.subjects)?d.subjects.length:null)
    +rawSec(I,'r-ses','Study sessions',sess.length>400?sess.slice(-400):sess,sess.length>400?'last 400 of '+sess.length:sess.length)
    +rawSec(I,'r-set','Settings',d.settings)
    +rawSec(I,'r-ev','Exams and events',d.events,Array.isArray(d.events)?d.events.length:null)
    +rawSec(I,'r-busy','Busy blocks',d.busyBlocks,Array.isArray(d.busyBlocks)?d.busyBlocks.length:null)
    +rawSec(I,'r-td','To-do list',d.todos,Array.isArray(d.todos)?d.todos.length:null)
    +rawSec(I,'r-ach','Achievements',d.achievements)
    +rawSec(I,'r-wt','Winter plan targets',d.winterTargets,Array.isArray(d.winterTargets)?d.winterTargets.length:null)
    +rawSec(I,'r-wl','Winter plan logs',d.winterLogs)
    +rawSec(I,'r-wn','Winter plan notes',d.winterNotes)
    +rawSec(I,'r-at','Timer',d.activeTimer)
    +rawSec(I,'r-m','Phone details',m);
  h+='<p class="ab-hint">This is a copy the phone uploads when you ask. You only read it here. Nothing on their phone is changed.</p>';
  return h;
}

/* ---- admin password change ---- */
var busyAdm=false;
function pmsg(m,cls){ var e=$('abPMsgBox'); if(!e) return; e.textContent=m||''; e.className='ab-msg'+(m?' show '+(cls||'err'):''); }
function admMsg(e){
  var m=String(e&&e.message||'');
  if(/WEAK_PASSWORD/.test(m)) return 'Use at least 6 characters.';
  if(/CREDENTIAL_TOO_OLD|TOKEN_EXPIRED|INVALID_ID_TOKEN/.test(m)) return 'Please lock and open Admin Block again, then retry.';
  return loginMsg(e);
}
async function saveAdm(){
  if(busyAdm||!A) return;
  var cur=L.norm($('abOp').value), n1=$('abAp1').value.trim(), n2=$('abAp2').value.trim();
  if(!cur){ pmsg('Enter the current admin password.'); return; }
  if(n1.length<6){ pmsg('The new password needs at least 6 characters.'); return; }
  if(n1!==n2){ pmsg('The two new passwords do not match.'); return; }
  if(n1===cur){ pmsg('The new password is the same as the current one.'); return; }
  busyAdm=true; pmsg(''); var b=$('abSaveAdm'); b.disabled=true; b.innerHTML='<span class="ab-spin"></span>Changing…';
  try{
    var s=await signIn(cur);
    var r=await aPost('https://identitytoolkit.googleapis.com/v1/accounts:update?key='+KEY,'application/json',JSON.stringify({idToken:s.t,password:n1,returnSecureToken:true}));
    if(!r.idToken) throw new Error((r.error&&r.error.message)||'auth');
    if(A) A=aSession(r);
    ['abOp','abAp1','abAp2'].forEach(function(i){ var e=$(i); if(e){ e.value=''; e.type='password'; } });
    Array.prototype.forEach.call(document.querySelectorAll('#abPPw [data-eye]'),function(x){ x.innerHTML=IC.eye; x.classList.remove('on'); });
    pmsg('Admin password changed ✓. Use the new one next time.','ok');
  }catch(e){ pmsg(admMsg(e)); }
  busyAdm=false; b.disabled=false; b.textContent='Change admin password';
}

/* ---- open / close ---- */
function addCss(){
  if($('abCss')) return;
  var st=document.createElement('style'); st.id='abCss'; st.textContent=CSS+CSS2; document.head.appendChild(st);
}
function openPage(){
  build(); if(typeof closeDrawer==='function') closeDrawer();
  var p=$('abPage'); isOpen=true; p.classList.add('open');
  if(!A){
    lockAdmin();
    if(!ON){ $('abSub').textContent='The database is not connected yet. Fill in firebase-config.js first (SETUP.md).'; $('abLoginCard').style.display='none'; }
    else{ $('abSub').textContent='Enter the admin password to open this block.'; $('abLoginCard').style.display=''; }
  }
}
function closePage(){
  var p=$('abPage'); if(p) p.classList.remove('open'); isOpen=false; lockAdmin();
}
document.addEventListener('visibilitychange',function(){
  if(document.hidden){ hiddenAt=Date.now(); return; }
  if(isOpen&&A&&hiddenAt&&Date.now()-hiddenAt>AWAY) lockAdmin('Locked after you were away. Enter the password again.');
});
function inject(){
  var dr=document.querySelector('#drawerBackdrop .drawer'); if(!dr) return false;
  if($('abDrawerBtn')) return true;
  var b=document.createElement('button'); b.className='drawer-item'; b.id='abDrawerBtn'; b.type='button';
  b.innerHTML=IC.shield+'Admin Block';
  dr.appendChild(b);
  b.addEventListener('click',openPage);
  return true;
}
addCss();
if(!inject()){ var injTries=0, injTimer=setInterval(function(){ if(inject()||++injTries>80) clearInterval(injTimer); },250); }
window.SLAdmin={open:openPage};
})();
