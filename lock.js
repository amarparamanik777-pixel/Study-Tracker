/* Study Log lock system
   - one-time password for every new install (first open, and again after delete + reinstall)
   - request form for new users, "Already a user" shortcut, password request
   - Admin Block support: block / unblock, popups, password popups, inspect, forced update, ask-details
   Uses the same Firebase Realtime Database as Study Squad (see SETUP.md). */
(function(){
'use strict';
var LS='sl_lock_v1', REL=17, ITER=50000, COOL=30*60*1000, POLL=45000, FAST=10000;
var ADMIN_EMAIL='admin@study-log.app';
var FILES=['index.html','lock.js','admin.js','friends.js','firebase-config.js','sw.js','manifest.json'];
var C=window.FB_CONFIG||{}, DB=(C.databaseURL||'').replace(/\/+$/,''), KEY=C.apiKey||'', ON=!!(DB&&KEY);
var SV={'.sv':'timestamp'};
var S={}; try{ S=JSON.parse(localStorage.getItem(LS)||'null')||{}; }catch(e){ S={}; }
if(typeof S!=='object'||S===null||Array.isArray(S)) S={};
function save(){ try{ localStorage.setItem(LS,JSON.stringify(S)); }catch(e){} }
function $(i){ return document.getElementById(i); }
function esc(s){ return String(s==null?'':s).replace(/[&<>"']/g,function(c){ return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); }
function norm(p){ p=String(p==null?'':p); try{ p=p.normalize('NFC'); }catch(e){} return p.trim(); }
/* one-time passwords, unblock passwords and popup passwords ignore case, spaces and hyphens */
function nCode(p){ p=String(p==null?'':p); try{ p=p.normalize('NFC'); }catch(e){} return p.toUpperCase().replace(/[\s\-]+/g,''); }
function rhex(n){ var a=new Uint8Array(n), s='', i; try{ crypto.getRandomValues(a); }catch(e){ for(i=0;i<n;i++) a[i]=Math.floor(Math.random()*256); } for(i=0;i<n;i++) s+=('0'+a[i].toString(16)).slice(-2); return s; }
var AL='ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function genCode(n){ n=n||8; var a=new Uint8Array(n), s='', i; try{ crypto.getRandomValues(a); }catch(e){ for(i=0;i<n;i++) a[i]=Math.floor(Math.random()*256); } for(i=0;i<n;i++) s+=AL.charAt(a[i]&31); return s; }
function fmtCode(c){ c=String(c||''); return c.length===8?c.slice(0,4)+'-'+c.slice(4):c; }
/* ---- crypto: PBKDF2-HMAC-SHA256 (WebCrypto when available, pure-JS fallback with identical output) ---- */
var K256=new Uint32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
var IV256=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19], Wk=new Uint32Array(64);
function comp(st,m,out){
  var a=st[0],b=st[1],c=st[2],d=st[3],e=st[4],f=st[5],g=st[6],h=st[7],i,t1,t2,x,y;
  for(i=0;i<16;i++) Wk[i]=m[i];
  for(;i<64;i++){ x=Wk[i-15]; y=Wk[i-2];
    Wk[i]=(Wk[i-16]+(((x>>>7)|(x<<25))^((x>>>18)|(x<<14))^(x>>>3))+Wk[i-7]+(((y>>>17)|(y<<15))^((y>>>19)|(y<<13))^(y>>>10)))|0; }
  for(i=0;i<64;i++){
    t1=(h+(((e>>>6)|(e<<26))^((e>>>11)|(e<<21))^((e>>>25)|(e<<7)))+((e&f)^(~e&g))+K256[i]+Wk[i])|0;
    t2=((((a>>>2)|(a<<30))^((a>>>13)|(a<<19))^((a>>>22)|(a<<10)))+((a&b)^(a&c)^(b&c)))|0;
    h=g; g=f; f=e; e=(d+t1)|0; d=c; c=b; b=a; a=(t1+t2)|0;
  }
  out[0]=(st[0]+a)|0; out[1]=(st[1]+b)|0; out[2]=(st[2]+c)|0; out[3]=(st[3]+d)|0;
  out[4]=(st[4]+e)|0; out[5]=(st[5]+f)|0; out[6]=(st[6]+g)|0; out[7]=(st[7]+h)|0;
}
function pad(bytes,extra){ // SHA-256 padding; extra = bytes already hashed before this message (HMAC key block)
  var n=bytes.length, tot=((n+9+63)>>6)<<6, buf=new Uint8Array(tot), bits=(n+extra)*8;
  buf.set(bytes); buf[n]=0x80;
  buf[tot-4]=(bits>>>24)&255; buf[tot-3]=(bits>>>16)&255; buf[tot-2]=(bits>>>8)&255; buf[tot-1]=bits&255;
  return buf;
}
function run(st,buf){ var m=new Uint32Array(16), i, o;
  for(o=0;o<buf.length;o+=64){ for(i=0;i<16;i++) m[i]=(buf[o+4*i]<<24)|(buf[o+4*i+1]<<16)|(buf[o+4*i+2]<<8)|buf[o+4*i+3]; comp(st,m,st); }
  return st; }
function sha256w(bytes){ return run(new Uint32Array(IV256),pad(bytes,0)); }
function hexw(w){ var s='',i; for(i=0;i<w.length;i++) s+=('00000000'+(w[i]>>>0).toString(16)).slice(-8); return s; }
function pbkdf2Js(pw,salt,iters){
  var key=pw, i, kb=new Uint8Array(64);
  if(key.length>64){ var kw=sha256w(key); key=new Uint8Array(32); for(i=0;i<8;i++){ key[4*i]=kw[i]>>>24; key[4*i+1]=(kw[i]>>>16)&255; key[4*i+2]=(kw[i]>>>8)&255; key[4*i+3]=kw[i]&255; } }
  kb.set(key);
  var ip=new Uint32Array(16), op=new Uint32Array(16), si=new Uint32Array(8), so=new Uint32Array(8), w;
  for(i=0;i<16;i++){ w=(kb[4*i]<<24)|(kb[4*i+1]<<16)|(kb[4*i+2]<<8)|kb[4*i+3]; ip[i]=w^0x36363636; op[i]=w^0x5c5c5c5c; }
  comp(new Uint32Array(IV256),ip,si); comp(new Uint32Array(IV256),op,so);
  var msg=new Uint8Array(salt.length+4); msg.set(salt); msg[salt.length+3]=1;
  var h=run(new Uint32Array(si),pad(msg,64)), u=new Uint32Array(8), t=new Uint32Array(8), ib=new Uint32Array(16), ob=new Uint32Array(16), j;
  ob.set(h); ob[8]=0x80000000; ob[15]=768; comp(so,ob,u); t.set(u);
  ib[8]=0x80000000; ib[15]=768; ob[8]=0x80000000; ob[15]=768;
  for(j=1;j<iters;j++){
    ib.set(u); comp(si,ib,h);
    ob.set(h); comp(so,ob,u);
    for(i=0;i<8;i++) t[i]^=u[i];
  }
  return hexw(t);
}
function utf8(s){
  if(typeof TextEncoder!=='undefined') return new TextEncoder().encode(s);
  s=unescape(encodeURIComponent(s)); var a=new Uint8Array(s.length), i; for(i=0;i<s.length;i++) a[i]=s.charCodeAt(i); return a;
}
function hexb(buf){ var a=new Uint8Array(buf), s='', i; for(i=0;i<a.length;i++) s+=('0'+a[i].toString(16)).slice(-2); return s; }
async function pbkdf2(pw,salt,iters){
  var p=utf8(pw), s=utf8(salt), sub=window.crypto&&window.crypto.subtle;
  if(sub&&sub.importKey&&sub.deriveBits){
    try{
      var k=await sub.importKey('raw',p,{name:'PBKDF2'},false,['deriveBits']);
      return hexb(await sub.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:s,iterations:iters},k,256));
    }catch(e){}
  }
  await new Promise(function(r){ setTimeout(r,30); });
  return pbkdf2Js(p,s,iters);
}

/* ---- anonymous auth + database over REST (own identity, separate from Study Squad) ---- */
var idTok='', tokExp=0, tokP=null;
function post(u,t,b){ return fetch(u,{method:'POST',headers:{'Content-Type':t},body:b}).then(function(r){ return r.json(); }); }
async function tok0(){
  var r;
  if(S.rt){
    r=await post('https://securetoken.googleapis.com/v1/token?key='+KEY,'application/x-www-form-urlencoded','grant_type=refresh_token&refresh_token='+encodeURIComponent(S.rt));
    if(r.id_token){
      idTok=r.id_token; tokExp=Date.now()+(+r.expires_in)*1000;
      if(r.refresh_token&&r.refresh_token!==S.rt){ S.rt=r.refresh_token; save(); }
      if(r.user_id&&r.user_id!==S.uid){ S.uid=r.user_id; save(); }
      return idTok;
    }
  }
  r=await post('https://identitytoolkit.googleapis.com/v1/accounts:signUp?key='+KEY,'application/json','{"returnSecureToken":true}');
  if(!r.idToken) throw new Error((r.error&&r.error.message)||'auth');
  idTok=r.idToken; tokExp=Date.now()+(+r.expiresIn)*1000; S.uid=r.localId; S.rt=r.refreshToken; save();
  return idTok;
}
function tok(){
  if(!ON) return Promise.reject(new Error('not configured'));
  if(idTok&&Date.now()<tokExp-60000) return Promise.resolve(idTok);
  if(!tokP) tokP=tok0().then(function(t){ tokP=null; return t; },function(e){ tokP=null; throw e; });
  return tokP;
}
async function db(m,p,b,ms,q){
  var t=await tok(), ctl=window.AbortController?new AbortController():null, to=ctl?setTimeout(function(){ ctl.abort(); },ms||10000):0;
  try{
    var r=await fetch(DB+'/'+p+'.json?auth='+t+(q?'&'+q:''),{method:m,body:b===undefined?undefined:JSON.stringify(b),signal:ctl?ctl.signal:undefined});
    if(!r.ok){ var e=new Error('http '+r.status); e.status=r.status; throw e; }
    return await r.json();
  }finally{ if(to) clearTimeout(to); }
}
function explain(e){
  var m=String(e&&e.message||e);
  if(e&&e.name==='AbortError') return 'The connection timed out. Check your internet and try again.';
  if(/Failed to fetch|NetworkError|Load failed|network/i.test(m)) return 'No internet connection. Connect and try again.';
  if(/not configured/.test(m)) return 'The lock is not set up yet. Please tell Amarnath.';
  if(/ADMIN_ONLY|OPERATION_NOT_ALLOWED/.test(m)) return 'The server is not ready yet (sign-in is off). Please tell Amarnath.';
  if(e&&(e.status===401||e.status===403)) return 'The server refused this request. Please tell Amarnath.';
  return 'Something went wrong. Please try again.';
}
function isNet(e){ var m=String(e&&e.message||e); return !!(e&&e.name==='AbortError')||/Failed to fetch|NetworkError|Load failed|network/i.test(m); }

/* ---- registration (create-only on the server, so details cannot be changed afterwards) ---- */
async function putReg(rec){
  try{ await db('PUT','lock/u/'+S.uid+'/reg',rec); }
  catch(e){
    if(e.status===401||e.status===403){ var ex=null; try{ ex=await db('GET','lock/u/'+S.uid+'/reg'); }catch(_){} if(ex) return; }
    throw e;
  }
}
async function ensureReg(){            /* same details again if this device ever got a new anonymous identity */
  if(!S.sub||!S.reg||S.regUid===S.uid) return;
  var r=S.reg, rec={n:r.n,c:r.c,m:r.m,k:r.k,o:true,t:SV}; if(r.x) rec.x=r.x;
  await putReg(rec); S.regUid=S.uid; save();
}
/* a salted hash record {s,h,i} is checked here; the text itself is never stored on a phone or in the database */
async function verify(code,rec){
  if(!rec||typeof rec.s!=='string'||typeof rec.h!=='string'||!(+rec.i>=1000&&+rec.i<=1000000)) return false;
  try{ return (await pbkdf2(nCode(code),rec.s,+rec.i))===rec.h; }catch(e){ return false; }
}
/* the owner's admin password opens any install (Firebase checks it, it is not in the files) */
async function master(pw){
  var r=await post('https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key='+KEY,'application/json',JSON.stringify({email:ADMIN_EMAIL,password:pw,returnSecureToken:true}));
  return !!(r&&r.idToken);
}
/* this phone's own one-time password: 'ok' | 'used' | 'bad'. The server keeps only a salted hash. */
async function oneTime(code){
  var c=await db('GET','lock/c/'+S.uid,undefined,9000), pw=c&&c.pw;
  if(!pw||!(await verify(code,pw))) return 'bad';
  if(c.pwu){ return S.pwTry===pw.h?'ok':'used'; }
  S.pwTry=pw.h; save();
  try{ await db('PUT','lock/c/'+S.uid+'/pwu',SV); }
  catch(e){ if(e.status===401||e.status===403) return 'used'; throw e; }
  return 'ok';
}
/* ---- styles ---- */
var CSS='html.sl-locked{background:#14151A;overflow:hidden!important}html.sl-locked body>*:not(.sl-ov){visibility:hidden!important}'
+'.sl-ov,.sl-ov *{box-sizing:border-box}'
+'.sl-ov{position:fixed;inset:0;z-index:100000;background:#14151A;color:#EDEBE3;font-family:Inter,system-ui,-apple-system,sans-serif;-webkit-font-smoothing:antialiased;overflow:hidden;opacity:1;transition:opacity .5s ease;-webkit-tap-highlight-color:transparent}'
+'.sl-ov.sl-fade{opacity:0;pointer-events:none}'
+'.sl-ov button,.sl-ov input,.sl-ov textarea{font-family:inherit}'
+'.sl-bg{position:absolute;inset:0;overflow:hidden;background:radial-gradient(120% 70% at 50% -10%,#3d2b10 0%,#1d1b1c 42%,#14151A 80%)}'
+'.sl-blob{position:absolute;border-radius:50%;filter:blur(55px);will-change:transform}'
+'.sl-b1{width:250px;height:250px;left:-90px;top:-70px;background:#E8A33D;opacity:.4;animation:slF1 15s ease-in-out infinite}'
+'.sl-b2{width:230px;height:230px;right:-100px;top:34%;background:#D9705B;opacity:.26;animation:slF2 18s ease-in-out infinite}'
+'.sl-b3{width:260px;height:260px;left:8%;bottom:-130px;background:#7EC9E8;opacity:.22;animation:slF3 20s ease-in-out infinite}'
+'@keyframes slF1{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(70px,60px) scale(1.15)}}'
+'@keyframes slF2{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(-60px,-70px) scale(1.2)}}'
+'@keyframes slF3{0%,100%{transform:translate(0,0) scale(1)}50%{transform:translate(50px,-50px) scale(1.12)}}'
+'.sl-pt{position:absolute;bottom:-12px;left:var(--x);width:var(--s);height:var(--s);border-radius:50%;background:var(--c);opacity:0;animation:slRise var(--t) linear var(--d) infinite}'
+'@keyframes slRise{0%{transform:translateY(0);opacity:0}12%{opacity:.8}100%{transform:translateY(-110vh);opacity:0}}'
+'.sl-scroll{position:absolute;inset:0;overflow-y:auto;-webkit-overflow-scrolling:touch;display:flex;padding:calc(env(safe-area-inset-top,0px) + 22px) 16px calc(env(safe-area-inset-bottom,0px) + 28px)}'
+'.sl-wrap{margin:auto;width:100%;max-width:440px}'
+'.sl-brand{text-align:center;margin-bottom:16px;animation:slUp .6s ease both}'
+'.sl-bt{font:700 18px Bitter,Georgia,serif;letter-spacing:3px}.sl-bt span{color:#E8A33D}'
+'.sl-sig{font:700 15px "Dancing Script",cursive;margin-top:1px;background:linear-gradient(90deg,#63656F 0%,#E8A33D 50%,#63656F 100%);background-size:200% auto;-webkit-background-clip:text;background-clip:text;color:transparent;animation:slSh 3.5s ease-in-out infinite}'
+'@keyframes slSh{0%{background-position:200% center}100%{background-position:-200% center}}'
+'.sl-steps{display:flex;align-items:center;justify-content:center;gap:10px;margin:0 0 16px;font:600 11px Inter,sans-serif;letter-spacing:.08em;text-transform:uppercase;color:#63656F;animation:slUp .6s .08s ease both}'
+'.sl-steps b{display:inline-flex;align-items:center;gap:7px;font-weight:600;transition:color .3s}.sl-steps b i{width:22px;height:22px;border-radius:50%;border:1.5px solid #3A3D4B;display:grid;place-items:center;font:700 11px Inter,sans-serif;font-style:normal;transition:all .3s}'
+'.sl-steps b.on{color:#EDEBE3}.sl-steps b.on i{border-color:#E8A33D;color:#1A1409;background:#E8A33D;box-shadow:0 0 14px rgba(232,163,61,.55)}.sl-steps b.ok{color:#A9D49E}.sl-steps b.ok i{border-color:#7FA875;background:#7FA875;color:#14210f}'
+'.sl-steps u{width:34px;height:2px;border-radius:2px;background:#2E313D;text-decoration:none;position:relative;overflow:hidden}.sl-steps u.ok:after{content:"";position:absolute;inset:0;background:linear-gradient(90deg,#7FA875,#E8A33D);animation:slGrow .6s ease both}'
+'@keyframes slGrow{from{transform:translateX(-100%)}to{transform:none}}'
+'.sl-card{position:relative;border-radius:24px;padding:22px 18px 20px;background:linear-gradient(180deg,rgba(38,40,50,.86),rgba(26,28,36,.88));-webkit-backdrop-filter:blur(14px);backdrop-filter:blur(14px);border:1px solid rgba(232,163,61,.26);box-shadow:0 24px 70px rgba(0,0,0,.5),inset 0 1px 0 rgba(255,255,255,.06);animation:slCard .6s cubic-bezier(.2,.8,.2,1) both}'
+'.sl-card:before{content:"";position:absolute;left:22px;right:22px;top:-1px;height:2px;border-radius:2px;background:linear-gradient(90deg,transparent,#E8A33D,#D9705B,#7EC9E8,transparent);opacity:.9}'
+'.sl-card[hidden]{display:none}'
+'.sl-card.sl-enter{animation:slSlideIn .45s cubic-bezier(.2,.8,.2,1) both}'
+'@keyframes slCard{from{opacity:0;transform:translateY(22px) scale(.97)}to{opacity:1;transform:none}}'
+'@keyframes slSlideIn{from{opacity:0;transform:translateX(26px)}to{opacity:1;transform:none}}'
+'@keyframes slUp{from{opacity:0;transform:translateY(12px)}to{opacity:1;transform:none}}'
+'.sl-h{margin:0 0 6px;font:700 22px/1.2 Bitter,Georgia,serif;text-align:center}.sl-p{margin:0 0 18px;font-size:13px;line-height:1.55;color:#9294A3;text-align:center}'
+'.sl-f{margin-bottom:14px;animation:slUp .5s calc(var(--i,0)*55ms + 120ms) ease both}'
+'.sl-lb{display:flex;align-items:center;gap:8px;margin:0 0 7px 1px;font:600 11.5px Inter,sans-serif;letter-spacing:.07em;text-transform:uppercase;color:#9294A3}.sl-lb small{font-weight:500;text-transform:none;letter-spacing:0;color:#63656F;font-size:11.5px}'
+'.sl-ch{width:22px;height:22px;border-radius:7px;display:grid;place-items:center;flex:0 0 auto;color:var(--c);background:var(--cb)}.sl-ch svg{width:13px;height:13px}'
+'.sl-in{display:block;width:100%;background:#24262F;border:1.5px solid #3A3D4B;border-radius:13px;padding:13px 14px;color:#EDEBE3;font:500 16px Inter,sans-serif;outline:none;transition:border-color .2s,box-shadow .2s,background .2s;-webkit-appearance:none;appearance:none}'
+'.sl-in::placeholder{color:#63656F}.sl-in:focus{border-color:#E8A33D;box-shadow:0 0 0 4px rgba(232,163,61,.16);background:#272A34}.sl-in.bad{border-color:#D9705B;box-shadow:0 0 0 4px rgba(217,112,91,.13)}'
+'textarea.sl-in{resize:none;line-height:1.45;min-height:84px}.sl-cnt{display:block;text-align:right;font:500 11px "IBM Plex Mono",monospace;color:#63656F;margin-top:4px}'
+'.sl-pw{position:relative}.sl-pw .sl-in{padding-right:48px;letter-spacing:.02em}.sl-eye{position:absolute;right:6px;top:50%;transform:translateY(-50%);width:38px;height:38px;border:0;background:none;color:#9294A3;cursor:pointer;border-radius:10px;display:grid;place-items:center}.sl-eye:hover,.sl-eye.on{color:#E8A33D}.sl-eye svg{width:20px;height:20px}'
+'.sl-seg{display:grid;grid-template-columns:1fr 1fr;gap:8px}.sl-seg button{display:flex;align-items:center;justify-content:center;gap:8px;padding:13px;border-radius:13px;border:1.5px solid #3A3D4B;background:#24262F;color:#9294A3;font:700 14px Inter,sans-serif;cursor:pointer;transition:all .2s}'
+'.sl-seg button:active{transform:scale(.97)}.sl-seg button[data-k=y].on{background:rgba(127,168,117,.16);border-color:#7FA875;color:#B4DBA9;box-shadow:0 0 0 3px rgba(127,168,117,.14)}.sl-seg button[data-k=n].on{background:rgba(217,112,91,.14);border-color:#D9705B;color:#F29A85;box-shadow:0 0 0 3px rgba(217,112,91,.14)}'
+'.sl-chk{position:relative;display:flex;gap:12px;align-items:flex-start;padding:13px;margin:4px 0 14px;border:1.5px solid #3A3D4B;border-radius:14px;background:rgba(36,38,47,.6);cursor:pointer;font-size:13px;line-height:1.5;color:#C9C8C2;transition:border-color .2s,background .2s}'
+'.sl-chk input{position:absolute;opacity:0;width:1px;height:1px}.sl-box{flex:0 0 auto;width:22px;height:22px;margin-top:1px;border-radius:7px;border:2px solid #63656F;display:grid;place-items:center;transition:all .2s}'
+'.sl-box svg{width:14px;height:14px;stroke:#1A1409;stroke-width:3.2;fill:none;stroke-linecap:round;stroke-linejoin:round;stroke-dasharray:24;stroke-dashoffset:24;transition:stroke-dashoffset .3s ease .05s}'
+'.sl-chk input:checked+.sl-box{background:#E8A33D;border-color:#E8A33D;box-shadow:0 0 14px rgba(232,163,61,.4)}.sl-chk input:checked+.sl-box svg{stroke-dashoffset:0}.sl-chk input:focus-visible+.sl-box{box-shadow:0 0 0 4px rgba(232,163,61,.3)}.sl-chk.on{border-color:rgba(232,163,61,.6);background:rgba(232,163,61,.08)}'
+'.sl-btn{position:relative;overflow:hidden;display:block;width:100%;border:0;border-radius:14px;padding:15px 18px;font:700 15px Inter,sans-serif;letter-spacing:.01em;color:#1A1409;background:linear-gradient(135deg,#F7BE5E 0%,#E8A33D 50%,#D98A25 100%);box-shadow:0 8px 26px rgba(232,163,61,.3),inset 0 1px 0 rgba(255,255,255,.35);cursor:pointer;transition:transform .15s ease,box-shadow .2s ease,opacity .2s ease,filter .2s}'
+'.sl-btn:active:not(:disabled){transform:scale(.98)}.sl-btn:disabled{opacity:.42;cursor:not-allowed;box-shadow:none;filter:saturate(.55)}'
+'.sl-btn:not(:disabled):not(.sl-ghost):after{content:"";position:absolute;top:0;left:-60%;width:40%;height:100%;background:linear-gradient(100deg,transparent,rgba(255,255,255,.5),transparent);transform:skewX(-20deg);animation:slShine 3.2s ease-in-out infinite;pointer-events:none}'
+'@keyframes slShine{0%,55%{left:-60%}100%{left:130%}}'
+'.sl-ghost{background:rgba(255,255,255,.04);color:#EDEBE3;border:1.5px solid #3A3D4B;box-shadow:none}.sl-ghost:hover:not(:disabled){border-color:#E8A33D;color:#fff}.sl-warm{background:rgba(232,163,61,.08);color:#F0B456;border:1.5px solid rgba(232,163,61,.5);box-shadow:none}.sl-warm:hover:not(:disabled){background:rgba(232,163,61,.15)}'
+'.sl-spin{display:inline-block;width:15px;height:15px;margin-right:9px;vertical-align:-2px;border:2.5px solid rgba(26,20,9,.25);border-top-color:#1A1409;border-radius:50%;animation:slSpin .7s linear infinite}.sl-ghost .sl-spin,.sl-warm .sl-spin{border-color:rgba(255,255,255,.2);border-top-color:#E8A33D}@keyframes slSpin{to{transform:rotate(360deg)}}'
+'.sl-hint{margin:10px 2px 0;font-size:12px;line-height:1.5;color:#7A7C88;text-align:center;min-height:18px}.sl-hint.ok{color:#A9D49E}.sl-note{margin:12px 2px 0;font-size:11.5px;line-height:1.5;color:#63656F;text-align:center}'
+'.sl-err{display:none;margin:10px 0 0;padding:10px 12px;border-radius:12px;background:rgba(217,112,91,.13);border:1px solid rgba(217,112,91,.5);color:#F29A85;font-size:13px;line-height:1.45}.sl-err.show{display:block;margin-bottom:12px;animation:slUp .3s ease both}'
+'.sl-ok{display:none;margin:10px 0 0;padding:10px 12px;border-radius:12px;background:rgba(127,168,117,.13);border:1px solid rgba(127,168,117,.5);color:#B4DBA9;font-size:13px;line-height:1.45}.sl-ok.show{display:block;margin-bottom:12px;animation:slUp .3s ease both}'
+'.sl-or{display:flex;align-items:center;gap:12px;margin:16px 0 14px;color:#63656F;font:600 11px Inter,sans-serif;letter-spacing:.1em;text-transform:uppercase}.sl-or:before,.sl-or:after{content:"";flex:1;height:1px;background:linear-gradient(90deg,transparent,#3A3D4B,transparent)}'
+'.sl-link{display:block;margin:14px auto 0;padding:8px 10px;border:0;background:none;color:#9294A3;font:600 13px Inter,sans-serif;cursor:pointer;text-decoration:underline;text-underline-offset:3px}.sl-link:hover{color:#E8A33D}.sl-link[hidden]{display:none}'
+'.sl-emb{position:relative;width:88px;height:88px;margin:0 auto 14px;display:grid;place-items:center;border-radius:50%;background:radial-gradient(circle at 32% 26%,#343744,#1a1b22);box-shadow:0 0 42px rgba(232,163,61,.28),inset 0 2px 6px rgba(255,255,255,.06)}'
+'.sl-ring{position:absolute;inset:-3px;border-radius:50%;background:conic-gradient(from 0deg,#E8A33D,#D9705B,#7EC9E8,#E8A33D);-webkit-mask:radial-gradient(farthest-side,transparent calc(100% - 3px),#000 calc(100% - 2px));mask:radial-gradient(farthest-side,transparent calc(100% - 3px),#000 calc(100% - 2px));animation:slSpin 6s linear infinite}'
+'.sl-emb:after{content:"";position:absolute;inset:-10px;border-radius:50%;border:2px solid rgba(232,163,61,.35);animation:slPulse 2.4s ease-out infinite}'
+'@keyframes slPulse{0%{transform:scale(.88);opacity:.9}100%{transform:scale(1.28);opacity:0}}'
+'.sl-lk{width:44px;height:44px;position:relative;z-index:1;filter:drop-shadow(0 3px 8px rgba(0,0,0,.45))}.sl-sh{transition:transform .5s cubic-bezier(.3,1.4,.5,1);transform-origin:21px 30px}'
+'.sl-open .sl-sh{transform:translateY(-6px) rotate(-24deg)}.sl-open .sl-emb{animation:slPop .6s ease both}.sl-open .sl-ring{animation-duration:1.2s}'
+'@keyframes slPop{40%{transform:scale(1.14)}100%{transform:scale(1)}}'
+'.sl-sent{display:flex;align-items:center;gap:10px;margin:0 0 14px;padding:11px 12px;border-radius:14px;background:rgba(127,168,117,.1);border:1px solid rgba(127,168,117,.4);font-size:12.5px;line-height:1.4;color:#B4DBA9}.sl-sent[hidden]{display:none}.sl-sent svg{width:18px;height:18px;flex:0 0 auto}.sl-sent b{display:block;color:#EDEBE3;font-weight:600;margin-top:1px;word-break:break-word}'
+'.sl-shake{animation:slShake .45s ease}@keyframes slShake{20%,60%{transform:translateX(-8px)}40%,80%{transform:translateX(8px)}}'
+'.sl-cf{position:absolute;left:50%;top:38%;width:9px;height:14px;border-radius:2px;background:var(--c);opacity:0;animation:slBurst .95s cubic-bezier(.15,.7,.3,1) forwards;pointer-events:none;z-index:5}'
+'@keyframes slBurst{0%{opacity:1;transform:translate(-50%,-50%) rotate(0)}100%{opacity:0;transform:translate(calc(-50% + var(--dx)),calc(-50% + var(--dy))) rotate(var(--r))}}'
+'@media (max-width:360px){.sl-card{padding:20px 14px 18px}.sl-h{font-size:20px}}'
+'@media (prefers-reduced-motion:reduce){.sl-ov *,.sl-ov *:before,.sl-ov *:after{animation:none!important;transition:none!important}.sl-cf{display:none}}';

/* ---- popup themes: one look per kind of popup (new popups + the app's own popups) ---- */
var CSS2=[
/* shared popup pieces */
'.sl-th-info{--tc:#6CB6F2;--tc2:#A9DBFF;--tl:rgba(108,182,242,.34);--tg:rgba(108,182,242,.42);--tbg:#10283f;--tx:#06182a}',
'.sl-th-warn{--tc:#F5C542;--tc2:#FFE28F;--tl:rgba(245,197,66,.36);--tg:rgba(245,197,66,.4);--tbg:#3a2f0c;--tx:#231a02}',
'.sl-th-good{--tc:#5FD08A;--tc2:#AEF2C8;--tl:rgba(95,208,138,.34);--tg:rgba(95,208,138,.4);--tbg:#0f3322;--tx:#04200f}',
'.sl-th-alert{--tc:#FF6B5E;--tc2:#FFAAA1;--tl:rgba(255,107,94,.4);--tg:rgba(255,107,94,.46);--tbg:#3d1210;--tx:#2a0502}',
'.sl-th-notice{--tc:#B58CFF;--tc2:#DCC8FF;--tl:rgba(181,140,255,.36);--tg:rgba(181,140,255,.42);--tbg:#2a1a4a;--tx:#190a33}',
'.sl-th-block{--tc:#FF4D4D;--tc2:#FF9C8E;--tl:rgba(255,77,77,.42);--tg:rgba(255,77,77,.5);--tbg:#3b0d0d;--tx:#2a0303}',
'.sl-th-upd{--tc:#45D6A0;--tc2:#A2F2D2;--tl:rgba(69,214,160,.36);--tg:rgba(69,214,160,.42);--tbg:#0c3a2c;--tx:#032018}',
'.sl-th-pass{--tc:#F2B84B;--tc2:#FFDC95;--tl:rgba(242,184,75,.38);--tg:rgba(242,184,75,.44);--tbg:#3a280c;--tx:#231601}',
'.sl-pbg{position:absolute;inset:0;overflow:hidden;background:radial-gradient(120% 75% at 50% -10%,var(--tbg) 0%,#17181e 48%,#14151A 86%)}',
'.sl-pbg .sl-b1{background:var(--tc);opacity:.34}.sl-pbg .sl-b2{background:var(--tc2);opacity:.2}.sl-pbg .sl-b3{background:var(--tc);opacity:.18}',
'.sl-pcard{border-color:var(--tl);box-shadow:0 24px 70px rgba(0,0,0,.5),0 0 60px -12px var(--tg),inset 0 1px 0 rgba(255,255,255,.06)}',
'.sl-pcard:before{background:linear-gradient(90deg,transparent,var(--tc),var(--tc2),transparent)}',
'.sl-pcard.sl-enter,.sl-msgov .sl-pcard{animation:slPop2 .55s cubic-bezier(.2,1.1,.3,1) both}',
'@keyframes slPop2{0%{opacity:0;transform:translateY(26px) scale(.86) rotate(-1.5deg)}60%{opacity:1;transform:translateY(-4px) scale(1.03) rotate(.4deg)}100%{opacity:1;transform:none}}',
'@keyframes slBd{from{opacity:0}to{opacity:1}}',
'.sl-ti{position:relative;width:84px;height:84px;margin:0 auto 14px;display:grid;place-items:center;border-radius:50%;background:radial-gradient(circle at 32% 26%,rgba(255,255,255,.14),rgba(255,255,255,.02) 60%),var(--tbg);box-shadow:0 0 40px var(--tg),inset 0 2px 6px rgba(255,255,255,.07);color:var(--tc2)}',
'.sl-ti svg{width:42px;height:42px;position:relative;z-index:1;overflow:visible}',
'.sl-ti:before{content:"";position:absolute;inset:-3px;border-radius:50%;background:conic-gradient(from 0deg,var(--tc),var(--tc2),transparent 55%,var(--tc));-webkit-mask:radial-gradient(farthest-side,transparent calc(100% - 3px),#000 calc(100% - 2px));mask:radial-gradient(farthest-side,transparent calc(100% - 3px),#000 calc(100% - 2px));animation:slSpin 7s linear infinite}',
'.sl-ti:after{content:"";position:absolute;inset:-10px;border-radius:50%;border:2px solid var(--tl);animation:slPulse 2.4s ease-out infinite}',
'.sl-pov .sl-h{color:#F4F2EA}.sl-pov .sl-hh{display:inline-block;margin:0 auto 10px;padding:3px 11px;border-radius:99px;font:700 10.5px Inter,sans-serif;letter-spacing:.12em;text-transform:uppercase;color:var(--tc2);background:var(--tbg);border:1px solid var(--tl)}',
'.sl-pov .sl-hw{text-align:center}',
'.sl-pov .sl-in:focus{border-color:var(--tc);box-shadow:0 0 0 4px var(--tg)}.sl-pov .sl-lb{color:var(--tc2)}',
'.sl-btn.sl-tbtn{color:var(--tx);background:linear-gradient(135deg,var(--tc2) 0%,var(--tc) 100%);box-shadow:0 8px 26px var(--tg),inset 0 1px 0 rgba(255,255,255,.35)}',
'.sl-btn.sl-tbtn:disabled{box-shadow:none}',
'.sl-pm{margin:0 0 18px;font-size:14.5px;line-height:1.6;color:#D6D4CC;text-align:center;white-space:pre-wrap;word-break:break-word;max-height:38vh;overflow-y:auto}',
'.sl-tmr{margin:2px 0 16px;text-align:center;font:600 30px "IBM Plex Mono",monospace;letter-spacing:.04em;color:var(--tc2);text-shadow:0 0 18px var(--tg)}',
'.sl-tmr small{display:block;margin-bottom:3px;font:600 10.5px Inter,sans-serif;letter-spacing:.12em;text-transform:uppercase;color:#9294A3;text-shadow:none}',
'.sl-tmr.sl-tx{font:600 15px Inter,sans-serif;letter-spacing:0;text-shadow:none;color:#F0B4AC}',
'.sl-bar{height:6px;border-radius:6px;background:rgba(255,255,255,.08);overflow:hidden;margin:2px 0 16px}.sl-bar[hidden]{display:none}',
'.sl-bar i{display:block;height:100%;width:42%;border-radius:6px;background:linear-gradient(90deg,var(--tc),var(--tc2));animation:slBar 1.15s ease-in-out infinite}',
'@keyframes slBar{0%{transform:translateX(-110%)}100%{transform:translateX(260%)}}',
'.sl-fine{margin:12px 2px 0;font-size:11.5px;line-height:1.5;color:#7A7C88;text-align:center}',
'.sl-sp{height:12px}',
/* info popup sits over the app (not full screen) */
'.sl-msgov{z-index:99990;background:rgba(9,10,14,.74);-webkit-backdrop-filter:blur(7px);backdrop-filter:blur(7px);animation:slBd .25s ease both}',
'.sl-msgov:before{content:"";position:absolute;inset:0;background:radial-gradient(60% 45% at 50% 48%,var(--tg),transparent 72%);pointer-events:none}',
'.sl-msgov .sl-scroll{z-index:1}',
/* per-theme icon motion */
'.sl-th-info .sl-ti svg{animation:slBell 2.6s ease-in-out infinite;transform-origin:50% 12%}',
'@keyframes slBell{0%,50%,100%{transform:rotate(0)}6%{transform:rotate(16deg)}14%{transform:rotate(-14deg)}22%{transform:rotate(10deg)}30%{transform:rotate(-6deg)}38%{transform:rotate(2deg)}}',
'.sl-th-warn .sl-ti svg{animation:slWarn 1.5s ease-in-out infinite}',
'@keyframes slWarn{0%,100%{transform:scale(1);filter:drop-shadow(0 0 0 transparent)}50%{transform:scale(1.12);filter:drop-shadow(0 0 10px var(--tc))}}',
'.sl-th-warn .sl-pcard{background-image:repeating-linear-gradient(135deg,rgba(245,197,66,.07) 0 14px,transparent 14px 28px),linear-gradient(180deg,rgba(38,40,50,.88),rgba(26,28,36,.9))}',
'.sl-th-good .sl-ti svg path{stroke-dasharray:34;stroke-dashoffset:34;animation:slDraw .8s ease .25s forwards}',
'@keyframes slDraw{to{stroke-dashoffset:0}}',
'.sl-th-alert .sl-ti svg{animation:slShakeI .8s ease-in-out infinite}',
'@keyframes slShakeI{0%,100%{transform:translateX(0) rotate(0)}15%{transform:translateX(-4px) rotate(-6deg)}30%{transform:translateX(4px) rotate(6deg)}45%{transform:translateX(-3px) rotate(-4deg)}60%{transform:translateX(3px) rotate(4deg)}75%{transform:translateX(0) rotate(0)}}',
'.sl-th-alert .sl-pcard{animation:slPop2 .55s cubic-bezier(.2,1.1,.3,1) both,slAlertGlow 1.6s ease-in-out .6s infinite}',
'@keyframes slAlertGlow{0%,100%{box-shadow:0 24px 70px rgba(0,0,0,.5),0 0 30px -10px var(--tg)}50%{box-shadow:0 24px 70px rgba(0,0,0,.5),0 0 70px 0 var(--tg)}}',
'.sl-th-notice .sl-ti{animation:slBreath 3.2s ease-in-out infinite}',
'@keyframes slBreath{0%,100%{transform:scale(1)}50%{transform:scale(1.07)}}',
'.sl-th-block .sl-ti{animation:slSiren 1s ease-in-out infinite}',
'@keyframes slSiren{0%,100%{box-shadow:0 0 22px var(--tg),inset 0 2px 6px rgba(255,255,255,.07)}50%{box-shadow:0 0 62px 6px var(--tg),inset 0 2px 6px rgba(255,255,255,.07)}}',
'.sl-th-block .sl-pbg:after{content:"";position:absolute;inset:0;box-shadow:inset 0 0 130px rgba(255,60,60,.36);animation:slFlash 1.8s ease-in-out infinite;pointer-events:none}',
'@keyframes slFlash{0%,100%{opacity:.35}50%{opacity:1}}',
'.sl-th-upd .sl-ti svg{animation:slSpin 1.8s linear infinite}',
'.sl-th-pass .sl-ti svg{animation:slWig 1.9s ease-in-out infinite;transform-origin:30% 70%}',
'@keyframes slWig{0%,60%,100%{transform:rotate(0)}68%{transform:rotate(-16deg)}76%{transform:rotate(14deg)}84%{transform:rotate(-8deg)}92%{transform:rotate(4deg)}}',
/* the app\'s own popups, restyled by CSS only */
'@keyframes slGlowG{0%,100%{box-shadow:0 0 0 1px rgba(247,190,94,.18),0 22px 70px rgba(232,163,61,.3),0 0 40px -10px rgba(247,190,94,.4)}50%{box-shadow:0 0 0 1px rgba(247,190,94,.4),0 22px 80px rgba(232,163,61,.5),0 0 70px -6px rgba(247,190,94,.7)}}',
'@keyframes slGlowB{0%,100%{box-shadow:0 0 0 1px rgba(89,178,255,.2),0 22px 70px rgba(59,130,246,.32),0 0 40px -10px rgba(89,178,255,.45)}50%{box-shadow:0 0 0 1px rgba(89,178,255,.45),0 22px 80px rgba(59,130,246,.55),0 0 70px -6px rgba(89,178,255,.75)}}',
'@keyframes slGlowO{0%,100%{box-shadow:0 0 0 1px rgba(255,138,61,.2),0 22px 70px rgba(255,98,30,.3),0 0 40px -10px rgba(255,138,61,.45)}50%{box-shadow:0 0 0 1px rgba(255,138,61,.45),0 22px 80px rgba(255,98,30,.5),0 0 70px -6px rgba(255,138,61,.75)}}',
'@keyframes slFlame{0%{transform:scale(1) rotate(-3deg)}100%{transform:scale(1.14) rotate(3deg)}}',
'.ach-popup-backdrop{background:radial-gradient(60% 50% at 50% 46%,rgba(247,190,94,.26),rgba(6,6,9,.84) 72%);-webkit-backdrop-filter:blur(3px);backdrop-filter:blur(3px);animation:slBd .3s ease both}',
'.ach-popup-card{position:relative;background:linear-gradient(165deg,#3A2A0B,#1C1E26 62%);border:1.5px solid #F7BE5E;border-radius:20px;animation:slPop2 .6s cubic-bezier(.2,1.1,.3,1) both,slGlowG 3s ease-in-out .7s infinite}',
'.ach-popup-card:has(img):after{content:"";position:absolute;top:0;left:-60%;width:40%;height:100%;background:linear-gradient(100deg,transparent,rgba(255,255,255,.32),transparent);transform:skewX(-20deg);animation:slShine 3.4s ease-in-out .8s infinite;pointer-events:none}',
'.ach-popup-backdrop:has(.ach-popup-card:not(:has(img))){background:radial-gradient(60% 50% at 50% 46%,rgba(89,178,255,.28),rgba(6,6,9,.84) 72%)}',
'.ach-popup-card:not(:has(img)){background:linear-gradient(165deg,#0E2A52,#14161f 66%);border-color:#59B2FF;animation:slPop2 .6s cubic-bezier(.2,1.1,.3,1) both,slGlowB 3s ease-in-out .7s infinite}',
'.ach-popup-card:not(:has(img)) .ach-popup-unlocked,.ach-popup-card:not(:has(img)) .ach-popup-sub{color:#8CCBFF}',
'.ach-popup-card:not(:has(img)) .ach-popup-num{background:linear-gradient(180deg,#fff,#7CC4FF);-webkit-background-clip:text;background-clip:text;color:transparent;filter:drop-shadow(0 0 14px rgba(89,178,255,.55))}',
'.ach-popup-card:not(:has(img)) .btn-primary{background:linear-gradient(135deg,#8CCBFF,#3B82F6);color:#041428}',
'.ach-popup-card:has(img) .btn-primary{background:linear-gradient(135deg,#FFD98A,#E8A33D);color:#1A1409}',
'.modal-backdrop{background:radial-gradient(60% 50% at 50% 46%,rgba(255,122,47,.3),rgba(8,6,6,.86) 72%);animation:slBd .3s ease both}',
'.modal-card{position:relative;background:linear-gradient(170deg,#43200c,#1C1E26 62%);border:1.5px solid #FF8A3D;animation:slPop2 .6s cubic-bezier(.2,1.1,.3,1) both,slGlowO 2.6s ease-in-out .7s infinite}',
'.modal-flame{display:inline-block;animation:slFlame 1.1s ease-in-out infinite alternate;filter:drop-shadow(0 0 14px rgba(255,138,61,.7))}',
'.modal-streak{color:#FFB347;text-shadow:0 0 22px rgba(255,138,61,.55)}',
'.modal-card .btn-primary{background:linear-gradient(135deg,#FFC163,#FF7A2F);color:#2a1000}',
'.w-modal-backdrop{--wm:#7EC9E8;--wm2:#BFE8FA;--wmbg:#0f2530;--wmg:rgba(126,201,232,.5);--wmt:#0B222B}',
'#todoModalBackdrop{--wm:#5FD6A0;--wm2:#B6F2D6;--wmbg:#10291f;--wmg:rgba(95,214,160,.45);--wmt:#062014}',
'#todoDeleteModalBackdrop{--wm:#FF6B5E;--wm2:#FFAAA1;--wmbg:#341210;--wmg:rgba(255,107,94,.45);--wmt:#2a0502}',
'#achDetailModalBackdrop{--wm:#B58CFF;--wm2:#DCC8FF;--wmbg:#241743;--wmg:rgba(181,140,255,.45);--wmt:#190a33}',
'.w-modal-backdrop{background:radial-gradient(60% 50% at 50% 46%,var(--wmg),rgba(6,8,10,.84) 74%);animation:slBd .3s ease both}',
'.w-modal-card{position:relative;background:linear-gradient(170deg,var(--wmbg),#1C1E26 62%);border:1px solid var(--wm);box-shadow:0 20px 60px rgba(0,0,0,.5),0 0 50px -12px var(--wmg);animation:slPop2 .5s cubic-bezier(.2,1.1,.3,1) both}',
'.w-modal-card:before{content:"";position:absolute;left:18px;right:18px;top:-1px;height:2px;border-radius:2px;background:linear-gradient(90deg,transparent,var(--wm),var(--wm2),transparent)}',
'.w-modal-card h3{color:var(--wm2)}',
'.w-modal-card .btn-primary{background:linear-gradient(135deg,var(--wm2),var(--wm));color:var(--wmt)}',
'.w-modal-card .w-input:focus{outline:none;border-color:var(--wm);box-shadow:0 0 0 3px var(--wmg)}',
'@media (prefers-reduced-motion:reduce){.ach-popup-card,.ach-popup-backdrop,.modal-card,.modal-backdrop,.modal-flame,.w-modal-card,.w-modal-backdrop,.sl-msgov,.sl-th-block .sl-pbg:after{animation:none!important}.ach-popup-card:has(img):after{display:none}}'
].join('');
function injectCss(){
  var st=$('slLockCss'); if(!st){ st=document.createElement('style'); st.id='slLockCss'; (document.head||document.documentElement).appendChild(st); }
  if(st.textContent!==CSS+CSS2) st.textContent=CSS+CSS2;
}
/* ---- gate UI ---- */
var IC={
  user:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 3.6-7 8-7s8 3 8 7"/></svg>',
  cap:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 9l10-5 10 5-10 5z"/><path d="M6 11.5V16c0 1.5 3 3 6 3s6-1.5 6-3v-4.5"/></svg>',
  phone:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 4h4l2 5-2.5 1.5a11 11 0 0 0 5 5L15 13l5 2v4a2 2 0 0 1-2 2A16 16 0 0 1 3 6a2 2 0 0 1 2-2z"/></svg>',
  know:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c0-3.6 2.9-6 6.5-6s6.5 2.4 6.5 6"/><circle cx="17.5" cy="9" r="2.5"/><path d="M17 14c2.6 0 4.5 1.8 4.5 4.5"/></svg>',
  msg:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12a8 8 0 0 1-11.5 7.2L3 21l1.8-5.5A8 8 0 1 1 21 12z"/></svg>',
  key:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M16 7l3 3"/></svg>',
  eye:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.6-7 10-7 10 7 10 7-3.6 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>',
  eyeoff:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3l18 18"/><path d="M10.6 6.1A10 10 0 0 1 12 5c6.4 0 10 7 10 7a17 17 0 0 1-3.2 4.2M6.5 7A17 17 0 0 0 2 12s3.6 7 10 7a9.8 9.8 0 0 0 4.1-.9"/><path d="M9.9 9.9a3 3 0 0 0 4.2 4.2"/></svg>',
  lockc:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="11" width="16" height="10" rx="2.5"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>',
  padlock:'<svg class="sl-lk" viewBox="0 0 64 64" aria-hidden="true"><defs><linearGradient id="slG1" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#FFD98A"/><stop offset=".55" stop-color="#E8A33D"/><stop offset="1" stop-color="#C77B1E"/></linearGradient></defs><g class="sl-sh"><path d="M21 30v-8a11 11 0 0 1 22 0v8" fill="none" stroke="url(#slG1)" stroke-width="5.5" stroke-linecap="round"/></g><rect x="12" y="29" width="40" height="28" rx="8" fill="url(#slG1)"/><circle cx="32" cy="41.5" r="4" fill="#1A1409"/><rect x="30.3" y="43" width="3.4" height="8" rx="1.7" fill="#1A1409"/></svg>'
};
var CHK='<svg viewBox="0 0 24 24"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>';
function lab(ic,c,bg,txt,id,extra){ return '<label class="sl-lb"'+(id?' for="'+id+'"':'')+'><span class="sl-ch" style="--c:'+c+';--cb:'+bg+'">'+IC[ic]+'</span>'+txt+(extra?' '+extra:'')+'</label>'; }
function bgHtml(){
  var cols=['#E8A33D','#F7BE5E','#7EC9E8','#D9705B','#BFE8FA'], p='', i;
  for(i=0;i<16;i++) p+='<i class="sl-pt" style="--x:'+(4+i*6.1)+'%;--s:'+(3+(i*7)%4)+'px;--c:'+cols[i%5]+';--t:'+(9+(i*5)%8)+'s;--d:-'+((i*2.3)%11).toFixed(1)+'s"></i>';
  return '<div class="sl-bg"><i class="sl-blob sl-b1"></i><i class="sl-blob sl-b2"></i><i class="sl-blob sl-b3"></i>'+p+'</div>';
}
var TI={
  info:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M18 9a6 6 0 0 0-12 0c0 6-2.5 7.5-2.5 7.5h17S18 15 18 9z"/><path d="M10.3 20a1.9 1.9 0 0 0 3.4 0"/></svg>',
  warn:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M10.3 3.9L2.4 17.5A2 2 0 0 0 4.1 20.5h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/><path d="M12 9v4.5M12 17h.01"/></svg>',
  good:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M7.8 12.4l2.8 2.8 5.6-6.2"/></svg>',
  alert:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M8.3 2.5h7.4l5.3 5.3v7.4l-5.3 5.3H8.3L3 15.2V7.8z"/><path d="M12 7.5v5.2M12 16.3h.01"/></svg>',
  notice:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l8 3v5.5c0 4.7-3.3 8.1-8 9.5-4.7-1.4-8-4.8-8-9.5V6z"/><path d="M9 12l2.2 2.2L15.2 10"/></svg>',
  block:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M5.6 5.6l12.8 12.8"/></svg>',
  upd:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20 11a8 8 0 0 0-14.3-4.2L4 8.5"/><path d="M4 4v4.5h4.5"/><path d="M4 13a8 8 0 0 0 14.3 4.2L20 15.5"/><path d="M20 20v-4.5h-4.5"/></svg>',
  pass:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"><circle cx="8" cy="15" r="4"/><path d="M11 12l9-9M16 7l3 3"/></svg>'
};
var THEME={i:'info',w:'warn',g:'good',a:'alert',n:'notice'}, KIND={i:'Message',w:'Warning',g:'Good news',a:'Important',n:'Privacy'};

var view='form', mode='gate', busy=false, ans='', coolT=0, reqT=0, blkT=0, opening=false;
function brandHtml(){ return '<div class="sl-brand"><div class="sl-bt">STUDY <span>LOG</span></div><div class="sl-sig">by Amarnath</div></div>'; }
function sendTxt(){ return mode==='details'?'Send details':'Send request'; }
function setErr(id,msg,cls){ var e=$(id); if(!e) return; e.textContent=msg||''; e.className=(cls||'sl-err')+(msg?' show':''); }
function perr(m){ setErr('slPErr',m); }
function shakeEl(el){ if(!el) return; el.classList.remove('sl-shake'); void el.offsetWidth; el.classList.add('sl-shake'); }
function focusLater(id,ms){ setTimeout(function(){ var i=$(id); if(i&&!busy) try{ i.focus({preventScroll:true}); }catch(e){ try{ i.focus(); }catch(_){} } },ms||280); }

/* wrong-password limiter shared by every password box: 5 wrong tries = 30 seconds wait */
function coolLeft(){ return Math.ceil(((S.until||0)-Date.now())/1000); }
function failOne(){ S.fails=(S.fails||0)+1; if(S.fails>=5){ S.fails=0; S.until=Date.now()+30000; } save(); }
function okReset(){ S.fails=0; S.until=0; }

/* ---- the gate: details form + one-time password ---- */
function formHtml(){
  var det=mode==='details';
  return '<section class="sl-card" id="slForm" aria-labelledby="slFT">'
  +'<h1 class="sl-h" id="slFT">'+(det?'Please add your details':'Welcome 👋')+'</h1><p class="sl-p">'+(det?'Amarnath asked everyone to fill this in once, so he knows who is using Study Log. Fields marked * are required.':'New here? Tell Amarnath who you are to get access to Study Log. Fields marked * are required.')+'</p>'
  +'<div class="sl-f" style="--i:1">'+lab('user','#E8A33D','rgba(232,163,61,.16)','Full name *','slN')+'<input class="sl-in" id="slN" maxlength="40" autocomplete="name" enterkeyhint="next" placeholder="Your name"></div>'
  +'<div class="sl-f" style="--i:2">'+lab('cap','#A98BC0','rgba(139,107,158,.2)','Class *','slC')+'<input class="sl-in" id="slC" maxlength="24" autocomplete="off" enterkeyhint="next" placeholder="e.g. 10th, 12th, BSc 1st year"></div>'
  +'<div class="sl-f" style="--i:3">'+lab('phone','#6FC2B4','rgba(76,154,142,.2)','Mobile number *','slM')+'<input class="sl-in" id="slM" type="tel" inputmode="tel" maxlength="20" autocomplete="tel" enterkeyhint="next" placeholder="e.g. 98765 43210"></div>'
  +'<div class="sl-f" style="--i:4">'+lab('know','#F29A85','rgba(217,112,91,.18)','Do you know AMARNATH? *')+'<div class="sl-seg" role="group" aria-label="Do you know AMARNATH?"><button type="button" data-k="y" aria-pressed="false">Yes</button><button type="button" data-k="n" aria-pressed="false">No</button></div></div>'
  +'<div class="sl-f" style="--i:5">'+lab('msg','#8FB2DB','rgba(91,127,166,.22)','Message to Admin','slX','<small>(optional)</small>')+'<textarea class="sl-in" id="slX" maxlength="300" rows="3" placeholder="Anything you want Amarnath to know…"></textarea><span class="sl-cnt" id="slCnt">0/300</span></div>'
  +'<label class="sl-chk" id="slChk" style="--i:6"><input type="checkbox" id="slO"><span class="sl-box">'+CHK+'</span><span>I allow Admin (Amarnath) to call or message me on this number. *</span></label>'
  +'<button class="sl-btn" id="slSend" type="button" disabled>'+sendTxt()+'</button>'
  +'<div class="sl-hint" id="slHint" aria-live="polite"></div>'
  +'<div class="sl-err" id="slErr" role="alert"></div>'
  +'<p class="sl-note">Once sent, these details cannot be changed.</p>'
  +(det?'':'<div class="sl-or"><span>or</span></div><button class="sl-btn sl-ghost" id="slAlready" type="button">Already a user</button>')
  +'</section>';
}
function passHtml(){
  return '<section class="sl-card" id="slPass" aria-labelledby="slPT" hidden>'
  +'<div class="sl-emb" id="slEmb"><span class="sl-ring"></span>'+IC.padlock+'</div>'
  +'<h1 class="sl-h" id="slPT">Enter one-time password</h1><p class="sl-p" id="slPS"></p>'
  +'<div class="sl-sent" id="slSent" hidden>'+IC.lockc+'<div>Details sent. They can’t be changed.<b id="slWho"></b></div></div>'
  +'<div class="sl-f">'+lab('key','#E8A33D','rgba(232,163,61,.16)','One-time password','slPw')+'<div class="sl-pw"><input class="sl-in" id="slPw" type="password" name="slpw" autocomplete="off" autocapitalize="none" autocorrect="off" spellcheck="false" enterkeyhint="go" placeholder="Enter one-time password"><button class="sl-eye" id="slEye" type="button" aria-label="Show password">'+IC.eye+'</button></div></div>'
  +'<div class="sl-err" id="slPErr" role="alert"></div>'
  +'<button class="sl-btn" id="slUnlock" type="button">Unlock</button>'
  +'<div id="slReqBox" hidden><div class="sl-or"><span>don’t have it?</span></div><button class="sl-btn sl-warm" id="slReq" type="button">Request password</button><div class="sl-hint" id="slReqHint" aria-live="polite"></div><div class="sl-err" id="slRErr" role="alert"></div></div>'
  +'<button class="sl-link" id="slToForm" type="button" hidden>New here? Fill the form</button>'
  +'</section>';
}

/* form */
function cleanPhone(v){ return String(v||'').replace(/[\s\-().]/g,''); }
function phoneOk(m){ return /^\+?\d{7,15}$/.test(m); }
function formVals(){
  return {n:$('slN').value.trim().replace(/\s+/g,' '),c:$('slC').value.trim().replace(/\s+/g,' '),m:cleanPhone($('slM').value),k:ans,x:$('slX').value.trim(),o:$('slO').checked};
}
function missing(v){
  var a=[]; if(v.n.length<2) a.push('name'); if(!v.c) a.push('class'); if(!phoneOk(v.m)) a.push('a valid mobile number');
  if(!v.k) a.push('Yes / No answer'); if(!v.o) a.push('permission tick'); return a;
}
function check(){
  var b=$('slSend'), h=$('slHint'); if(!b||!$('slN')) return;
  var v=formVals(), miss=missing(v);
  b.disabled=busy||miss.length>0;
  if(miss.length){ h.textContent='Still needed: '+miss.join(', ')+'.'; h.className='sl-hint'; }
  else{ h.textContent='All set. Tap '+sendTxt()+'.'; h.className='sl-hint ok'; }
  $('slCnt').textContent=$('slX').value.length+'/300';
  $('slChk').classList.toggle('on',v.o);
}
async function submitForm(){
  if(busy) return;
  var v=formVals(); if(missing(v).length){ check(); return; }
  busy=true; setErr('slErr','');
  var b=$('slSend'), card=$('slForm'); b.disabled=true; b.innerHTML='<span class="sl-spin"></span>Sending…'; card.style.pointerEvents='none';
  try{
    await tok();
    var rec={n:v.n,c:v.c,m:v.m,k:v.k,o:true,t:SV}; if(v.x) rec.x=v.x;
    await putReg(rec);
    S.sub=1; S.sk=0; S.fmq=0; S.regUid=S.uid; S.reg={n:v.n,c:v.c,m:v.m,k:v.k}; if(v.x) S.reg.x=v.x; save();
    b.innerHTML='Sent ✓';
    setTimeout(function(){
      busy=false; card.style.pointerEvents=''; b.innerHTML=sendTxt();
      if(mode==='details'){ render(); ping(true); } else show('pass',true,false);
    },700);
  }catch(e){
    busy=false; card.style.pointerEvents=''; b.innerHTML=sendTxt(); check();
    setErr('slErr',explain(e));
  }
}

/* password screen */
function maskPhone(m){ m=String(m||''); return m.length>3?'•'.repeat(Math.min(7,m.length-3))+m.slice(-3):m; }
function paintCool(){
  clearInterval(coolT); var u=$('slUnlock'); if(!u) return;
  function tick(){
    var w=coolLeft();
    if(w>0){ u.disabled=true; perr('Too many wrong tries. Try again in '+w+'s.'); }
    else{ clearInterval(coolT); u.disabled=busy; perr(''); }
  }
  if(coolLeft()>0){ tick(); coolT=setInterval(tick,500); } else u.disabled=busy;
}
function paintReq(){
  clearTimeout(reqT);
  var box=$('slReqBox'), btn=$('slReq'), h=$('slReqHint'), lnk=$('slToForm'); if(!box) return;
  box.hidden=!ON; lnk.hidden=!!S.sub||!ON;
  if(!ON) return;
  var left=COOL-(Date.now()-(S.ask||0)), idt=S.uid?String(S.uid).slice(-6):'';
  if(S.ask&&left>0){
    btn.disabled=true; btn.textContent='Requested ✓';
    h.textContent=(S.sub?'Request sent. Amarnath will contact you on your number.':'Request sent. Tell Amarnath your device ID ('+idt+') so he knows it is you.')+' You can ask again in '+Math.ceil(left/60000)+' min.'; h.className='sl-hint ok';
    reqT=setTimeout(paintReq,Math.min(left,60000)+200);
  }else{
    btn.disabled=false; btn.textContent=S.ask?'Request password again':'Request password';
    h.textContent=S.sub?'Tap to ask Amarnath for a one-time password. He will contact you on the number you gave.':'Tap to ask Amarnath for a one-time password. A device ID will appear. Tell it to Amarnath so he knows it is you.'; h.className='sl-hint';
  }
}
function paintPass(){
  var sub=$('slPS'), sent=$('slSent');
  sub.textContent=S.sub?'Your details are with Amarnath. Enter the one-time password he sends you.':'Enter the one-time password Amarnath gave you.';
  sent.hidden=!S.sub||!S.reg;
  if(S.sub&&S.reg) $('slWho').textContent=S.reg.n+' · '+maskPhone(S.reg.m);
  paintReq(); paintCool();
}
function steps(){
  var s=$('slSteps'); if(!s) return;
  s.style.display=(ON&&mode==='gate')?'flex':'none';
  var a=$('slS1'), b=$('slS2'), u=$('slU');
  a.className=view==='form'?'on':(S.sub?'ok':''); b.className=view==='pass'?'on':'';
  a.firstChild.textContent=(view==='pass'&&S.sub)?'✓':'1'; u.className=(view==='pass'&&S.sub)?'ok':'';
}
function show(v,anim,focus){
  view=v; var f=$('slForm'), p=$('slPass'); if(!f) return;
  f.hidden=v!=='form'; if(p) p.hidden=v!=='pass';
  var c=v==='form'?f:p; if(c&&anim){ c.classList.remove('sl-enter'); void c.offsetWidth; c.classList.add('sl-enter'); }
  steps();
  if(v==='form'){ check(); }
  else{ paintPass(); if(focus!==false) focusLater('slPw'); }
  var sc=document.querySelector('#slGate .sl-scroll'); if(sc) sc.scrollTop=0;
}

async function unlock(){
  if(busy) return;
  if(coolLeft()>0){ paintCool(); return; }
  var inp=$('slPw'), t=norm(inp.value);
  if(!t){ perr('Enter the password.'); shakeEl($('slPass')); return; }
  busy=true; perr('');
  var b=$('slUnlock'); b.disabled=true; b.innerHTML='<span class="sl-spin"></span>Checking…';
  var res='bad', err=null;
  try{
    await tok();
    res=await oneTime(t);
    if(res==='bad'){ try{ if(await master(t)) res='owner'; }catch(e){} }
  }catch(e){ res='net'; err=e; }
  busy=false; b.textContent='Unlock'; b.disabled=false;
  if(res==='ok'||res==='owner'){ success(res==='owner'?'o':(S.sub?'f':'d')); return; }
  if(res==='used'){ perr('This password was already used. Ask Amarnath for a new one.'); shakeEl($('slPass')); try{ inp.select(); }catch(e){} return; }
  if(res==='net'){ perr(explain(err)); return; }
  failOne();
  perr('Wrong password. Try again.'); shakeEl($('slPass')); try{ inp.select(); }catch(e){} paintCool();
}
function confetti(o){
  var cols=['#E8A33D','#F7BE5E','#7EC9E8','#D9705B','#7FA875','#BFE8FA'], i, e, a, d;
  for(i=0;i<26;i++){
    e=document.createElement('i'); e.className='sl-cf'; a=Math.random()*Math.PI*2; d=90+Math.random()*150;
    e.style.cssText='--c:'+cols[i%6]+';--dx:'+Math.round(Math.cos(a)*d)+'px;--dy:'+Math.round(Math.sin(a)*d-40)+'px;--r:'+Math.round(Math.random()*540-270)+'deg;animation-delay:'+(Math.random()*120|0)+'ms';
    o.appendChild(e);
  }
}
function success(how){
  if(opening) return; opening=true;
  S.ok=1; S.at=Date.now(); S.how=how; okReset(); save();
  var o=$('slGate');
  if(!o){ opening=false; render(); return; }
  perr(''); o.classList.add('sl-open'); confetti(o);
  setTimeout(function(){ opening=false; render(); startTimers(); ping(true); poll(true); checkUpdate(true); },950);
}
async function reqPw(){
  if(busy||Date.now()-(S.ask||0)<COOL) return;
  busy=true; setErr('slRErr','');
  var b=$('slReq'); b.disabled=true; b.innerHTML='<span class="sl-spin"></span>Sending…';
  try{ await tok(); await ensureReg(); await db('PUT','lock/u/'+S.uid+'/ask',SV); S.ask=Date.now(); save(); }
  catch(e){ setErr('slRErr',explain(e)); }
  busy=false; paintReq();
}

function buildGate(m){
  mode=m||'gate'; busy=false; ans=''; injectCss();
  var o=document.createElement('div'); o.id='slGate'; o.className='sl-ov sl-blocking'; o.setAttribute('role','dialog'); o.setAttribute('aria-modal','true'); o.setAttribute('aria-label','Study Log lock');
  o.innerHTML=bgHtml()+'<div class="sl-scroll"><div class="sl-wrap">'+brandHtml()
    +'<div class="sl-steps" id="slSteps"><b id="slS1"><i>1</i>Details</b><u id="slU"></u><b id="slS2"><i>2</i>Password</b></div>'
    +formHtml()+(mode==='gate'?passHtml():'')+'</div></div>';
  document.body.insertBefore(o,document.body.firstChild);
  ['slN','slC','slM','slX'].forEach(function(id){ $(id).addEventListener('input',function(){ if(id==='slM'){ var p=this.value, q=p.replace(/[^\d+\-\s().]/g,''); if(p!==q) this.value=q; } this.classList.remove('bad'); check(); }); });
  $('slN').addEventListener('blur',function(){ this.classList.toggle('bad',!!this.value.trim()&&this.value.trim().length<2); });
  $('slM').addEventListener('blur',function(){ this.classList.toggle('bad',!!this.value.trim()&&!phoneOk(cleanPhone(this.value))); });
  $('slO').addEventListener('change',check);
  Array.prototype.forEach.call(o.querySelectorAll('.sl-seg button'),function(b){ b.addEventListener('click',function(){
    ans=b.getAttribute('data-k'); Array.prototype.forEach.call(o.querySelectorAll('.sl-seg button'),function(x){ var on=x===b; x.classList.toggle('on',on); x.setAttribute('aria-pressed',on?'true':'false'); }); check();
  }); });
  $('slSend').addEventListener('click',submitForm);
  if(mode==='details'){ show('form',false); return; }
  $('slAlready').addEventListener('click',function(){ if(busy) return; S.sk=1; save(); show('pass',true,true); });
  $('slToForm').addEventListener('click',function(){ if(busy) return; S.sk=0; save(); show('form',true); });
  $('slEye').addEventListener('click',function(){ var p=$('slPw'), on=p.type==='password'; p.type=on?'text':'password'; this.innerHTML=on?IC.eyeoff:IC.eye; this.classList.toggle('on',on); this.setAttribute('aria-label',on?'Hide password':'Show password'); p.focus(); });
  $('slUnlock').addEventListener('click',unlock);
  $('slPw').addEventListener('keydown',function(e){ if(e.key==='Enter'){ e.preventDefault(); unlock(); } });
  $('slPw').addEventListener('input',function(){ if($('slPErr').classList.contains('show')&&coolLeft()<=0) perr(''); });
  $('slReq').addEventListener('click',reqPw);
  show((S.sub||S.sk||!ON)?'pass':'form',false,!S.sub);
}

/* ---- block / update / password popup / message popup ---- */
function popShell(id,theme,inner){
  var o=document.createElement('div'); o.id=id; o.className='sl-ov sl-blocking sl-pov sl-th-'+theme; o.setAttribute('role','alertdialog'); o.setAttribute('aria-modal','true');
  o.innerHTML='<div class="sl-pbg"><i class="sl-blob sl-b1"></i><i class="sl-blob sl-b2"></i><i class="sl-blob sl-b3"></i></div><div class="sl-scroll"><div class="sl-wrap">'+brandHtml()+'<section class="sl-card sl-pcard sl-enter">'+inner+'</section></div></div>';
  return o;
}
function pwBox(id,eyeId,label,ph){
  return '<div class="sl-f">'+lab('key','#FFDC95','rgba(242,184,75,.16)',label,id)+'<div class="sl-pw"><input class="sl-in" id="'+id+'" type="password" autocomplete="off" autocapitalize="none" autocorrect="off" spellcheck="false" enterkeyhint="go" placeholder="'+ph+'"><button class="sl-eye" id="'+eyeId+'" type="button" aria-label="Show password">'+IC.eye+'</button></div></div>';
}
function wireEye(eyeId,inputId){
  var b=$(eyeId); if(!b) return;
  b.addEventListener('click',function(){ var p=$(inputId), on=p.type==='password'; p.type=on?'text':'password'; b.innerHTML=on?IC.eyeoff:IC.eye; b.classList.toggle('on',on); b.setAttribute('aria-label',on?'Hide password':'Show password'); p.focus(); });
}
/* may a typed text open a password box? the right code, or the owner's admin password */
async function passes(v,rec){
  if(await verify(v,rec)) return true;
  var t=norm(v);
  if(t){ try{ return await master(t); }catch(e){} }
  return false;
}

/* block */
function fmtLeft(ms){
  var s=Math.max(0,Math.ceil(ms/1000)), d=Math.floor(s/86400), h=Math.floor(s%86400/3600), m=Math.floor(s%3600/60), x=s%60;
  function p(n){ return (n<10?'0':'')+n; }
  return (d?d+'d ':'')+p(h)+':'+p(m)+':'+p(x);
}
function paintBlock(){
  var b=S.blk, t=$('slBTm'); if(!b||!t||!$('slBM')) return;
  $('slBM').textContent=b.m||'Amarnath has blocked your access to Study Log for now.';
  if(b.d>0){ t.className='sl-tmr'; t.innerHTML='<small>Time left</small>'+fmtLeft(b.bs+b.d-Date.now()); }
  else{ t.className='sl-tmr sl-tx'; t.textContent='Blocked until Amarnath unblocks you.'; }
}
function endBlock(byPw){
  var b=S.blk; if(!b) return;
  S.ub=b.t; S.blk=null; okReset(); save();
  if(byPw) tok().then(function(){ return db('PATCH','lock/u/'+S.uid+'/seen',{k:SV}); }).catch(function(){});
  render();
}
function startBlockTick(){
  clearInterval(blkT);
  blkT=setInterval(function(){
    var b=S.blk;
    if(!b||!$('slBlock')){ clearInterval(blkT); return; }
    if(b.d>0&&Date.now()>=b.bs+b.d){ endBlock(false); return; }
    paintBlock();
  },1000);
}
async function blockCheck(){
  if(busy) return; busy=true;
  var b=$('slBChk'); b.disabled=true; b.innerHTML='<span class="sl-spin"></span>Checking…'; setErr('slBErr',''); setErr('slBOk','','sl-ok');
  var ok=await poll(true);
  busy=false;
  var el=$('slBlock'); if(!el||el.classList.contains('sl-fade')) return;
  b.disabled=false; b.textContent='Check again';
  if(!ok) setErr('slBErr','No internet connection. Connect and try again.');
  else{ setErr('slBOk','Still blocked.','sl-ok'); setTimeout(function(){ setErr('slBOk','','sl-ok'); },2500); }
}
async function blockUnlock(){
  var b0=S.blk; if(!b0||busy) return;
  if(coolLeft()>0){ setErr('slBErr','Too many wrong tries. Try again in '+coolLeft()+'s.'); return; }
  var inp=$('slBPw'), v=inp.value;
  if(!norm(v)){ setErr('slBErr','Enter the password.'); return; }
  busy=true; setErr('slBErr','');
  var b=$('slBGo'); b.disabled=true; b.innerHTML='<span class="sl-spin"></span>Checking…';
  var ok=await passes(v,b0);
  busy=false;
  if(ok){ endBlock(true); return; }
  b.disabled=false; b.textContent='Unblock';
  failOne(); setErr('slBErr','Wrong password. Try again.'); shakeEl(document.querySelector('#slBlock .sl-pcard')); try{ inp.select(); }catch(e){}
}
function buildBlock(){
  injectCss();
  var b=S.blk||{};
  var inner='<div class="sl-ti">'+TI.block+'</div><div class="sl-hw"><span class="sl-hh">Blocked</span></div>'
    +'<h1 class="sl-h" id="slBT">Access blocked</h1><p class="sl-pm" id="slBM"></p><div class="sl-tmr" id="slBTm"></div>'
    +(b.h?pwBox('slBPw','slBEye','One-time unblock password','Enter unblock password')+'<div class="sl-err" id="slBErr" role="alert"></div><button class="sl-btn sl-tbtn" id="slBGo" type="button">Unblock</button><div class="sl-sp"></div>':'<div class="sl-err" id="slBErr" role="alert"></div>')
    +'<button class="sl-btn sl-ghost" id="slBChk" type="button">Check again</button><div class="sl-ok" id="slBOk" role="status"></div>';
  var o=popShell('slBlock','block',inner); o.setAttribute('aria-labelledby','slBT');
  document.body.insertBefore(o,document.body.firstChild);
  $('slBChk').addEventListener('click',blockCheck);
  if(b.h){
    wireEye('slBEye','slBPw');
    $('slBGo').addEventListener('click',blockUnlock);
    $('slBPw').addEventListener('keydown',function(e){ if(e.key==='Enter'){ e.preventDefault(); blockUnlock(); } });
  }
  paintBlock(); startBlockTick();
}

/* forced update */
async function doUpdate(){
  if(busy) return; busy=true; setErr('slUErr','');
  var b=$('slUGo'); b.disabled=true; b.innerHTML='<span class="sl-spin"></span>Updating…'; $('slUBar').hidden=false;
  try{ await applyUpdate(); }                      /* reloads the page when it works */
  catch(e){
    busy=false; var b2=$('slUGo'); if(!b2) return;
    b2.disabled=false; b2.textContent='Update'; $('slUBar').hidden=true;
    setErr('slUErr',isNet(e)?'No internet connection. Connect and tap Update again.':'The update did not finish. Tap Update to try again.');
  }
}
function buildUpd(){
  injectCss();
  var inner='<div class="sl-ti">'+TI.upd+'</div><div class="sl-hw"><span class="sl-hh">New version</span></div>'
    +'<h1 class="sl-h" id="slUT">Update available</h1><p class="sl-pm">A new version of Study Log is ready. Tap Update to keep using the app.</p>'
    +'<div class="sl-bar" id="slUBar" hidden><i></i></div><div class="sl-err" id="slUErr" role="alert"></div>'
    +'<button class="sl-btn sl-tbtn" id="slUGo" type="button">Update</button><p class="sl-fine">Your study data stays on this phone. Nothing is lost.</p>';
  var o=popShell('slUpd','upd',inner); o.setAttribute('aria-labelledby','slUT');
  document.body.insertBefore(o,document.body.firstChild);
  $('slUGo').addEventListener('click',doUpdate);
  focusLater('slUGo',350);
}

/* password popup: cannot be closed until the password is entered */
async function popGo(){
  var m=S.pop; if(!m||busy) return;
  if(coolLeft()>0){ setErr('slOErr','Too many wrong tries. Try again in '+coolLeft()+'s.'); return; }
  var inp=$('slOPw'), v=inp.value;
  if(!norm(v)){ setErr('slOErr','Enter the password.'); return; }
  busy=true; setErr('slOErr','');
  var b=$('slOGo'); b.disabled=true; b.innerHTML='<span class="sl-spin"></span>Checking…';
  var ok=await passes(v,m);
  if(ok){
    okReset(); markSeen(m.id); S.pop=(S.pq&&S.pq.length)?S.pq.shift():null; save();
    b.innerHTML='Done ✓'; confetti(document.querySelector('#slPop .sl-pcard'));
    setTimeout(function(){ busy=false; render(); },650);
    return;
  }
  busy=false; b.disabled=false; b.textContent='Continue';
  failOne(); setErr('slOErr','Wrong password. Try again.'); shakeEl(document.querySelector('#slPop .sl-pcard')); try{ inp.select(); }catch(e){}
}
function buildPop(){
  var m=S.pop; if(!m) return;
  injectCss();
  var inner='<div class="sl-ti">'+TI.pass+'</div><div class="sl-hw"><span class="sl-hh">Password needed</span></div>'
    +'<h1 class="sl-h" id="slOT"></h1><p class="sl-pm" id="slOM"></p>'
    +pwBox('slOPw','slOEye','Password from Amarnath','Enter password')
    +'<div class="sl-err" id="slOErr" role="alert"></div><button class="sl-btn sl-tbtn" id="slOGo" type="button">Continue</button>'
    +'<p class="sl-fine">This message stays until you enter the password. Ask Amarnath if you do not have it.</p>';
  var o=popShell('slPop','pass',inner); o.setAttribute('aria-labelledby','slOT');
  document.body.insertBefore(o,document.body.firstChild);
  $('slOT').textContent=m.ti||'Message'; $('slOM').textContent=m.m||'';
  wireEye('slOEye','slOPw');
  $('slOGo').addEventListener('click',popGo);
  $('slOPw').addEventListener('keydown',function(e){ if(e.key==='Enter'){ e.preventDefault(); popGo(); } });
  focusLater('slOPw',420);
}

/* message popup (can be closed with OK) */
function showInfo(msg){
  injectCss();
  var st=THEME[msg.st]?msg.st:'i', th=THEME[st];
  var o=document.createElement('div'); o.id='slMsg'; o.className='sl-ov sl-msgov sl-pov sl-th-'+th; o.setAttribute('role','alertdialog'); o.setAttribute('aria-modal','true'); o.setAttribute('aria-labelledby','slMT');
  o.innerHTML='<div class="sl-scroll"><div class="sl-wrap"><section class="sl-card sl-pcard"><div class="sl-ti">'+TI[th]+'</div><div class="sl-hw"><span class="sl-hh">'+KIND[st]+'</span></div><h1 class="sl-h" id="slMT"></h1><p class="sl-pm" id="slMM"></p><button class="sl-btn sl-tbtn" id="slMOk" type="button">'+(st==='n'?'I understand':'OK')+'</button></section></div></div>';
  document.body.appendChild(o);
  $('slMT').textContent=msg.ti||''; $('slMM').textContent=msg.m||'';
  $('slMOk').addEventListener('click',function(){ closeInfo(msg); });
  if(th==='good') confetti(o.querySelector('.sl-pcard'));
  setTimeout(function(){ var k=$('slMOk'); if(k) try{ k.focus({preventScroll:true}); }catch(e){} },300);
}
function closeInfo(msg){
  var o=$('slMsg'); if(o&&o.parentNode) o.parentNode.removeChild(o);
  if(msg.id==='_n'){
    S.pn=Date.now(); save();
    ping(true); maybeInspect();
  }else{ markSeen(msg.id); }
  showNextInfo();
}

/* ---- device registry: first unlock + last open ---- */
var pinging=false;
async function ping(force){
  if(!ON||S.ok!==1||pinging) return;
  var now=Date.now();
  if(!force&&S.pa&&now-(S.la||0)<10*60*1000) return;
  if(!force&&S.pf&&now-S.pf<30*60*1000) return;
  pinging=true;
  try{
    await tok(); await ensureReg();
    var b={l:SV}, first=!S.pa||(S.pu&&S.pu!==S.uid), sendN=!!(S.pn&&!S.pns);
    if(first){ b.a=SV; b.w=S.how||'g'; }
    if(sendN) b.n=SV;
    await db('PATCH','lock/u/'+S.uid+'/seen',b);
    S.pa=1; S.pu=S.uid; S.la=Date.now(); if(sendN) S.pns=1; delete S.pf; save();
  }catch(e){ S.pf=Date.now(); save(); }
  pinging=false;
}

/* ---- messages from Admin Block: popups to everyone or to this phone only ---- */
var queue=[], acking=false;
var NOTICE={id:'_n',k:'i',st:'n',ti:'Your privacy',m:'Study Log is run by Amarnath. While you use this app he can see your study activity (subjects, study sessions, to-do list and goals), send you messages, and block access to the app.\n\nHe cannot see anything outside Study Log.'};
function byId(a,b){ return a.id<b.id?-1:(a.id>b.id?1:0); }
function addMsg(id,m){
  if(!m||typeof m!=='object') return;
  S.ms=S.ms||{};
  if(S.ms[id]) return;
  var rec={id:id,k:m.k==='p'?'p':'i',st:(m.st==='w'||m.st==='g'||m.st==='a')?m.st:'i',ti:String(m.ti==null?'':m.ti).slice(0,80),m:String(m.m==null?'':m.m).slice(0,600)};
  if(rec.k==='p'){
    if(typeof m.s!=='string'||typeof m.h!=='string'||!(+m.i>=1000&&+m.i<=1000000)) return;
    rec.s=m.s; rec.h=m.h; rec.i=+m.i;
    if(S.pop&&S.pop.id===id) return;
    if((S.pq||[]).some(function(x){ return x.id===id; })) return;
    if(!S.pop) S.pop=rec; else{ S.pq=S.pq||[]; S.pq.push(rec); }
  }else if(!queue.some(function(x){ return x.id===id; })){ queue.push(rec); queue.sort(byId); }
}
function markSeen(id){
  S.ms=S.ms||{}; S.ms[id]=1;
  queue=queue.filter(function(x){ return x.id!==id; });
  S.pk=S.pk||[]; if(S.pk.indexOf(id)<0) S.pk.push(id);
  var ks=Object.keys(S.ms); if(ks.length>500){ ks.sort(); ks.slice(0,ks.length-400).forEach(function(k){ delete S.ms[k]; }); }
  save(); flushAcks();
}
async function flushAcks(){
  if(acking||!ON||S.ok!==1||!S.pk||!S.pk.length) return;
  acking=true;
  try{
    await tok();
    var list=S.pk.slice(), i, id;
    for(i=0;i<list.length;i++){
      id=list[i];
      try{ await db('PUT','lock/ak/'+id+'/'+S.uid,SV); S.pk=S.pk.filter(function(x){ return x!==id; }); save(); }
      catch(e){ if(e&&(e.status===401||e.status===403)){ S.pk=S.pk.filter(function(x){ return x!==id; }); save(); } else break; }
    }
  }catch(e){}
  acking=false;
}
function nextMsg(){
  if(S.ok===1&&ON&&!S.pn) return NOTICE;
  while(queue.length){ if(S.ms&&S.ms[queue[0].id]){ queue.shift(); continue; } return queue[0]; }
  return null;
}
function showNextInfo(){
  if(!document.body||$('slMsg')||need()||opening) return;
  var m=nextMsg(); if(m) showInfo(m);
}

/* ---- inspect: Amarnath can ask this phone for a copy of the study data ---- */
var SNAPK=['subjects','sessions','settings','events','busyBlocks','todos','achievements','winterTargets','winterLogs','winterNotes','activeTimer','lastPopup'], snapBusy=false;
function readKey(k){ try{ var raw=localStorage.getItem(k); if(raw===null) return undefined; try{ return JSON.parse(raw); }catch(e){ return raw; } }catch(e){ return undefined; } }
function buildSnap(drop){
  var d={}, i, k, v;
  for(i=0;i<SNAPK.length;i++){ k=SNAPK[i]; if(drop.indexOf(k)>-1) continue; v=readKey(k); if(v!==undefined) d[k]=v; }
  if(drop.indexOf('sessions:trim')>-1&&d.sessions&&d.sessions.length>3000) d.sessions=d.sessions.slice(-3000);
  var tz=''; try{ tz=Intl.DateTimeFormat().resolvedOptions().timeZone||''; }catch(e){}
  var sa=false; try{ sa=!!(window.matchMedia&&window.matchMedia('(display-mode: standalone)').matches)||!!navigator.standalone; }catch(e){}
  var meta={now:Date.now(),rel:REL,tz:tz,lang:navigator.language||'',ua:navigator.userAgent||'',sw:(window.screen&&screen.width)||0,sh:(window.screen&&screen.height)||0,dpr:window.devicePixelRatio||1,sa:sa,vis:document.visibilityState};
  if(drop.length) meta.cut=drop;
  return JSON.stringify({m:meta,d:d});
}
async function uploadSnap(){
  var tries=[[],['winterNotes'],['winterNotes','winterLogs'],['winterNotes','winterLogs','sessions:trim'],['winterNotes','winterLogs','sessions:trim','events','busyBlocks','achievements','todos']], j='', i;
  for(i=0;i<tries.length;i++){ j=buildSnap(tries[i]); if(j.length<=900000) break; }
  if(j.length>900000) j=JSON.stringify({m:{now:Date.now(),rel:REL,cut:['all']},d:{}});
  await tok();
  await db('PUT','lock/ins/'+S.uid,{t:SV,r:REL,j:j},25000);
}
async function maybeInspect(){
  if(snapBusy||!ON||S.ok!==1) return;
  var want=+S.irq||0; if(!want||want<=(+S.ir||0)) return;
  if(!S.pn) return;                                   /* the privacy notice is shown first */
  snapBusy=true;
  try{ await uploadSnap(); S.ir=want; save(); }catch(e){}
  snapBusy=false;
}

/* ---- control channel: block, details request, inspect request, messages ---- */
var polling=false, pollP=null, lastPoll=0, fastUntil=0;
function settle(p){ return p.then(function(v){ return {ok:true,v:v}; },function(e){ return {ok:false,e:e}; }); }
function onControl(c){
  var b=c.b;
  if(b&&typeof b==='object'&&b.t!=null){
    var d=+b.d||0;
    if(S.ub!==b.t){
      if(!S.blk||S.blk.t!==b.t) S.blk={t:b.t,d:d,m:String(b.m==null?'':b.m).slice(0,300),s:typeof b.s==='string'?b.s:'',h:typeof b.h==='string'?b.h:'',i:+b.i||0,bs:Date.now()};
    }
  }else if(S.blk){ S.blk=null; }
  if(c.fm&&!S.sub) S.fmq=1;
  var ir=+c.ir||0; if(ir>(+S.ir||0)){ S.irq=ir; fastUntil=Date.now()+10*60*1000; }
  var md=c.md; if(md&&typeof md==='object') Object.keys(md).sort().forEach(function(id){ addMsg(id,md[id]); });
  save();
}
function onBroadcast(m){
  var ids=Object.keys(m).sort();
  if(!S.m0){ S.ms=S.ms||{}; ids.forEach(function(id){ S.ms[id]=1; }); S.m0=1; save(); return; }
  ids.forEach(function(id){ addMsg(id,m[id]); });
  save();
}
function poll(force){
  if(!ON||S.ok!==1) return Promise.resolve(false);
  if(polling) return pollP;
  var now=Date.now();
  if(!force&&now-lastPoll<15000) return Promise.resolve(true);
  polling=true; lastPoll=now;
  pollP=(async function(){
    var ok=false;
    try{
      await tok();
      var rc=await settle(db('GET','lock/c/'+S.uid,undefined,10000));
      var rm=await settle(db('GET','lock/ma',undefined,10000,'orderBy=%22%24key%22&limitToLast=20'));
      if(rc.ok) onControl((rc.v&&typeof rc.v==='object')?rc.v:{});
      if(rm.ok) onBroadcast((rm.v&&typeof rm.v==='object')?rm.v:{});
      ok=rc.ok||rm.ok;
    }catch(e){ ok=false; }
    polling=false; pollP=null;
    if(ok){ flushAcks(); maybeInspect(); }
    render();
    return ok;
  })();
  return pollP;
}

/* ---- forced update: when the app files change online, everyone must tap Update ---- */
var fpBusy=false, lastFp=0;
function normTag(h){ return String(h||'').replace(/^W\//,'').replace(/"/g,''); }
async function fingerprint(){
  var base=new URL('./',location.href).href, out=[], ok=0, bad=false;
  var rs=await Promise.all(FILES.map(function(f){
    return fetch(base+f,{method:'HEAD',cache:'no-store'}).then(function(r){ return r; },function(){ return null; });
  }));
  rs.forEach(function(r,i){
    if(!r){ bad=true; return; }
    if(r.ok){ ok++; out.push(FILES[i]+'='+normTag(r.headers.get('etag'))+'|'+(r.headers.get('last-modified')||'')); }
    else out.push(FILES[i]+'=x'+r.status);
  });
  if(bad||!ok) return null;
  return out.join(';');
}
async function checkUpdate(force){
  if(S.ok!==1||fpBusy||S.upd) return;
  var now=Date.now();
  if(!force&&now-lastFp<5*60*1000) return;
  fpBusy=true; lastFp=now;
  try{
    var fp=await fingerprint(); if(!fp) return;
    if(!S.fp){ S.fp=fp; save(); return; }
    if(fp===S.fp) return;
    await new Promise(function(r){ setTimeout(r,(window.SLLock&&window.SLLock.confirmMs!=null)?window.SLLock.confirmMs:6000); });   /* confirm once more, so one odd answer never triggers it */
    var fp2=await fingerprint(); if(!fp2||fp2!==fp) return;
    var ul=(S.ul||[]).filter(function(t){ return now-t<30*60*1000; });
    if(ul.length>=3){ S.fp=fp2; save(); return; }        /* never nag more than 3 times in 30 minutes */
    S.upd=1; S.nfp=fp2; save(); render();
  }catch(e){}
  finally{ fpBusy=false; }
}
async function applyUpdate(){
  var base=new URL('./',location.href).href, i, res;
  res=await Promise.all(FILES.map(function(f){ return fetch(base+f,{cache:'reload'}).then(function(r){ return r.ok; },function(e){ return e||new Error('network'); }); }));
  for(i=0;i<res.length;i++){ if(res[i]!==true&&res[i]!==false) throw res[i]; }
  if(res[0]!==true||res[1]!==true) throw new Error('http');
  try{
    if(navigator.serviceWorker&&navigator.serviceWorker.getRegistration){
      var reg=await navigator.serviceWorker.getRegistration();
      if(reg) await Promise.race([reg.update(),new Promise(function(r){ setTimeout(r,8000); })]);
    }
  }catch(e){}
  var fp=null; try{ fp=await fingerprint(); }catch(e){}
  S.fp=fp||S.nfp||S.fp; delete S.nfp; S.upd=0; S.ul=(S.ul||[]).concat(Date.now()).slice(-5); save();
  location.reload();
}

/* ---- timers ---- */
var timersOn=false;
function startTimers(){
  if(timersOn) return; timersOn=true;
  setInterval(function(){
    if(document.hidden||S.ok!==1) return;
    if(Date.now()-lastPoll>=(fastUntil>Date.now()?FAST:POLL)) poll();
    if(S.pa&&Date.now()-(S.la||0)>=10*60*1000) ping();
    checkUpdate();
  },5000);
}

/* ---- which screen must be showing right now ---- */
var curKey='';
function need(){
  if(S.ok!==1) return 'gate';
  if(S.blk&&!(S.blk.d>0&&Date.now()>=S.blk.bs+S.blk.d)) return 'block';
  if(S.fmq&&!S.sub) return 'details';
  if(S.upd) return 'upd';
  if(S.pop) return 'pop';
  return '';
}
function keyOf(n){ return n==='block'?'block:'+(S.blk&&S.blk.t):(n==='pop'?'pop:'+(S.pop&&S.pop.id):n); }
function whenBody(fn){
  if(document.body) return fn();
  var mo=new MutationObserver(function(){ if(document.body){ mo.disconnect(); fn(); } });
  mo.observe(document.documentElement,{childList:true});
}
function clearBlocking(fade){
  clearInterval(blkT); clearInterval(coolT);
  var els=document.querySelectorAll('.sl-ov.sl-blocking'), i;
  for(i=0;i<els.length;i++){
    (function(o){
      if(fade){ if(o.classList.contains('sl-fade')) return; o.classList.add('sl-fade'); setTimeout(function(){ if(o.parentNode) o.parentNode.removeChild(o); },560); }
      else if(o.parentNode) o.parentNode.removeChild(o);
    })(els[i]);
  }
  curKey='';
}
function showBlocking(n,key){
  var ex=document.querySelector('.sl-ov.sl-blocking:not(.sl-fade)');
  if(ex&&curKey===key) return;
  clearBlocking(false);
  var info=$('slMsg'); if(info&&info.parentNode) info.parentNode.removeChild(info);
  curKey=key; busy=false;
  if(n==='gate') buildGate('gate');
  else if(n==='details') buildGate('details');
  else if(n==='block') buildBlock();
  else if(n==='upd') buildUpd();
  else if(n==='pop') buildPop();
}
function render(){
  if(opening) return;
  if(S.blk&&S.blk.d>0&&Date.now()>=S.blk.bs+S.blk.d){ S.ub=S.blk.t; S.blk=null; save(); }
  var n=need(), root=document.documentElement;
  var hold=(n&&n!=='gate')?1:0; if((S.hold?1:0)!==hold){ S.hold=hold; save(); }
  if(n){
    root.classList.add('sl-locked');
    var key=keyOf(n);
    whenBody(function(){ if(need()===n) showBlocking(n,key); });
  }else{
    root.classList.remove('sl-locked');
    whenBody(function(){ clearBlocking(true); showNextInfo(); });
  }
}

/* ---- start ---- */
function boot(){
  injectCss();
  if(S.ok===1){ startTimers(); setTimeout(function(){ ping(); poll(true); checkUpdate(); },1500); }
  render();
}
document.addEventListener('visibilitychange',function(){ if(!document.hidden&&S.ok===1){ ping(); poll(); checkUpdate(); } });
window.addEventListener('online',function(){ if(S.ok===1){ ping(); poll(true); checkUpdate(true); flushAcks(); } });
window.SLLock={
  ON:ON, tok:tok, db:db, explain:explain, pbkdf2:pbkdf2, norm:norm, nCode:nCode, rhex:rhex, esc:esc, code:genCode, fmtCode:fmtCode,
  ITER:ITER, SV:SV, REL:REL,
  uid:function(){ return S.uid||''; },
  poll:poll, check:checkUpdate, confirmMs:6000
};
boot();
})();
