/* Study Log lock system
   - password gate for every new install (first open, and again after delete + reinstall)
   - request form for new users, "Already a user" shortcut, password request
   - device registry used by Admin Block (admin.js)
   Uses the same Firebase Realtime Database as Study Squad (see SETUP.md). */
(function(){
'use strict';
var LS='sl_lock_v1', ITER_PW=50000, COOL=30*60*1000;
/* Default app password, stored only as a salted PBKDF2 hash (never the text itself). */
var DEF={s:'f6d0ab307a3cb9753c72d1ab28c089fc',i:ITER_PW,h:'1f6200a55f3600bd3dfabd0fceb2d8b53eca24b307bfd1d1a6d74fc3aa05ca76',v:0};
var C=window.FB_CONFIG||{}, DB=(C.databaseURL||'').replace(/\/+$/,''), KEY=C.apiKey||'', ON=!!(DB&&KEY);
var SV={'.sv':'timestamp'};
var S={}; try{ S=JSON.parse(localStorage.getItem(LS)||'null')||{}; }catch(e){ S={}; }
function save(){ try{ localStorage.setItem(LS,JSON.stringify(S)); }catch(e){} }
function $(i){ return document.getElementById(i); }
function esc(s){ return String(s==null?'':s).replace(/[&<>"']/g,function(c){ return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]; }); }
function norm(p){ p=String(p==null?'':p); try{ p=p.normalize('NFC'); }catch(e){} return p.trim(); }
function rhex(n){ var a=new Uint8Array(n), s='', i; try{ crypto.getRandomValues(a); }catch(e){ for(i=0;i<n;i++) a[i]=Math.floor(Math.random()*256); } for(i=0;i<n;i++) s+=('0'+a[i].toString(16)).slice(-2); return s; }
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
async function db(m,p,b,ms){
  var t=await tok(), ctl=window.AbortController?new AbortController():null, to=ctl?setTimeout(function(){ ctl.abort(); },ms||10000):0;
  try{
    var r=await fetch(DB+'/'+p+'.json?auth='+t,{method:m,body:b===undefined?undefined:JSON.stringify(b),signal:ctl?ctl.signal:undefined});
    if(!r.ok){ var e=new Error('http '+r.status); e.status=r.status; throw e; }
    return await r.json();
  }finally{ if(to) clearTimeout(to); }
}
function explain(e){
  var m=String(e&&e.message||e);
  if(e&&e.name==='AbortError') return 'The connection timed out. Check your internet and try again.';
  if(/Failed to fetch|NetworkError|Load failed|network/i.test(m)) return 'No internet connection. Connect and try again.';
  if(/ADMIN_ONLY|OPERATION_NOT_ALLOWED/.test(m)) return 'The server is not ready yet (sign-in is off). Please tell Amarnath.';
  if(e&&(e.status===401||e.status===403)) return 'The server refused this request. Please tell Amarnath.';
  return 'Something went wrong. Please try again.';
}

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

/* ---- current app password record: database copy wins, built-in default otherwise ---- */
var warm=null;
async function fetchRec(){
  if(!ON) return {rec:DEF,live:false};
  try{
    var v=await db('GET','lock/pw',undefined,7000);
    if(v&&typeof v.s==='string'&&typeof v.h==='string'&&+v.i>=1000&&+v.i<=1000000){ S.cr=v; save(); return {rec:v,live:true}; }
    if(S.cr){ delete S.cr; save(); }
    return {rec:DEF,live:true};
  }catch(e){ return {rec:S.cr||DEF,live:false}; }
}
function getRec(){
  if(warm&&Date.now()-warm.t<45000) return warm.p;
  var p=fetchRec(); warm={t:Date.now(),p:p};
  p.then(function(r){ if(!r.live&&warm&&warm.p===p) warm=null; });
  return p;
}

/* ---- device registry: first unlock + last open, and the "password was changed for everyone" check ---- */
var pinging=false;
async function ping(force){
  if(!ON||!S.ok||pinging) return;
  var now=Date.now();
  if(!force&&S.pa&&now-(S.la||0)<10*60*1000) return;
  if(!force&&S.pf&&now-S.pf<30*60*1000) return;
  pinging=true;
  try{
    await tok(); await ensureReg();
    var b={l:SV}; if(!S.pa){ b.a=SV; b.w=S.how||'g'; }
    await db('PATCH','lock/u/'+S.uid+'/seen',b);
    S.pa=1; S.la=Date.now(); delete S.pf; save();
  }catch(e){ S.pf=Date.now(); save(); }
  pinging=false;
}
/* "make everyone enter the new password again" (set by Admin Block) */
var lastSync=0;
async function sync(force){
  if(!ON||!S.ok||(!force&&Date.now()-lastSync<120000)) return;
  lastSync=Date.now();
  try{
    var r=await fetchRec();
    if(r.live&&r.rec&&+r.rec.fv>(+S.pv||0)) relock('The password was changed. Enter the new one to continue.');
  }catch(e){}
}

/* ---- styles ---- */
var CSS='html.sl-locked{background:#14151A;overflow:hidden!important}html.sl-locked body>*:not(#slLock){visibility:hidden!important}'
+'#slLock,#slLock *{box-sizing:border-box}'
+'#slLock{position:fixed;inset:0;z-index:100000;background:#14151A;color:#EDEBE3;font-family:Inter,system-ui,-apple-system,sans-serif;-webkit-font-smoothing:antialiased;overflow:hidden;opacity:1;transition:opacity .5s ease;-webkit-tap-highlight-color:transparent}'
+'#slLock.sl-fade{opacity:0;pointer-events:none}'
+'#slLock button,#slLock input,#slLock textarea{font-family:inherit}'
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
+'@media (prefers-reduced-motion:reduce){#slLock *,#slLock *:before,#slLock *:after{animation:none!important;transition:none!important}.sl-cf{display:none}}';
function injectCss(){
  var st=$('slLockCss'); if(!st){ st=document.createElement('style'); st.id='slLockCss'; (document.head||document.documentElement).appendChild(st); }
  st.textContent=CSS;
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
var view='form', busy=false, shakeT=0;

function formHtml(){
  return '<section class="sl-card" id="slForm" aria-labelledby="slFT">'
  +'<h1 class="sl-h" id="slFT">Welcome 👋</h1><p class="sl-p">New here? Tell Amarnath who you are to get access to Study Log. Fields marked * are required.</p>'
  +'<div class="sl-f" style="--i:1">'+lab('user','#E8A33D','rgba(232,163,61,.16)','Full name *','slN')+'<input class="sl-in" id="slN" maxlength="40" autocomplete="name" enterkeyhint="next" placeholder="Your name"></div>'
  +'<div class="sl-f" style="--i:2">'+lab('cap','#A98BC0','rgba(139,107,158,.2)','Class *','slC')+'<input class="sl-in" id="slC" maxlength="24" autocomplete="off" enterkeyhint="next" placeholder="e.g. 10th, 12th, BSc 1st year"></div>'
  +'<div class="sl-f" style="--i:3">'+lab('phone','#6FC2B4','rgba(76,154,142,.2)','Mobile number *','slM')+'<input class="sl-in" id="slM" type="tel" inputmode="tel" maxlength="20" autocomplete="tel" enterkeyhint="next" placeholder="e.g. 98765 43210"></div>'
  +'<div class="sl-f" style="--i:4">'+lab('know','#F29A85','rgba(217,112,91,.18)','Do you know AMARNATH? *')+'<div class="sl-seg" role="group" aria-label="Do you know AMARNATH?"><button type="button" data-k="y" aria-pressed="false">Yes</button><button type="button" data-k="n" aria-pressed="false">No</button></div></div>'
  +'<div class="sl-f" style="--i:5">'+lab('msg','#8FB2DB','rgba(91,127,166,.22)','Message to Admin','slX','<small>(optional)</small>')+'<textarea class="sl-in" id="slX" maxlength="300" rows="3" placeholder="Anything you want Amarnath to know…"></textarea><span class="sl-cnt" id="slCnt">0/300</span></div>'
  +'<label class="sl-chk" id="slChk" style="--i:6"><input type="checkbox" id="slO"><span class="sl-box">'+CHK+'</span><span>I allow Admin (Amarnath) to call or message me on this number. *</span></label>'
  +'<button class="sl-btn" id="slSend" type="button" disabled>Send request</button>'
  +'<div class="sl-hint" id="slHint" aria-live="polite"></div>'
  +'<div class="sl-err" id="slErr" role="alert"></div>'
  +'<p class="sl-note">Once sent, these details cannot be changed.</p>'
  +'<div class="sl-or"><span>or</span></div>'
  +'<button class="sl-btn sl-ghost" id="slAlready" type="button">Already a user</button>'
  +'</section>';
}
function passHtml(){
  return '<section class="sl-card" id="slPass" aria-labelledby="slPT" hidden>'
  +'<div class="sl-emb" id="slEmb"><span class="sl-ring"></span>'+IC.padlock+'</div>'
  +'<h1 class="sl-h" id="slPT">Enter password</h1><p class="sl-p" id="slPS"></p>'
  +'<div class="sl-sent" id="slSent" hidden>'+IC.lockc+'<div>Details sent. They can’t be changed.<b id="slWho"></b></div></div>'
  +'<div class="sl-f">'+lab('key','#E8A33D','rgba(232,163,61,.16)','Password','slPw')+'<div class="sl-pw"><input class="sl-in" id="slPw" type="password" name="slpw" autocomplete="off" autocapitalize="none" autocorrect="off" spellcheck="false" enterkeyhint="go" placeholder="Enter password"><button class="sl-eye" id="slEye" type="button" aria-label="Show password">'+IC.eye+'</button></div></div>'
  +'<div class="sl-err" id="slPErr" role="alert"></div>'
  +'<button class="sl-btn" id="slUnlock" type="button">Unlock</button>'
  +'<div id="slReqBox" hidden><div class="sl-or"><span>don’t have it?</span></div><button class="sl-btn sl-warm" id="slReq" type="button">Request password</button><div class="sl-hint" id="slReqHint" aria-live="polite"></div><div class="sl-err" id="slRErr" role="alert"></div></div>'
  +'<button class="sl-link" id="slToForm" type="button" hidden>New here? Fill the form</button>'
  +'</section>';
}

function setErr(id,msg,cls){ var e=$(id); if(!e) return; e.textContent=msg||''; e.className=(cls||'sl-err')+(msg?' show':''); }
function perr(m){ setErr('slPErr',m); }
function shake(){ var c=$('slPass'); if(!c) return; c.classList.remove('sl-shake'); void c.offsetWidth; c.classList.add('sl-shake'); }

/* form */
var ans='';
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
  var v=formVals(), miss=missing(v), b=$('slSend'), h=$('slHint'); if(!b) return;
  b.disabled=busy||miss.length>0;
  if(miss.length){ h.textContent='Still needed: '+miss.join(', ')+'.'; h.className='sl-hint'; }
  else{ h.textContent='All set. Tap Send request.'; h.className='sl-hint ok'; }
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
    S.sub=1; S.sk=0; S.regUid=S.uid; S.reg={n:v.n,c:v.c,m:v.m,k:v.k}; if(v.x) S.reg.x=v.x; save();
    b.innerHTML='Sent ✓';
    setTimeout(function(){ busy=false; card.style.pointerEvents=''; b.innerHTML='Send request'; show('pass',true,false); },700);
  }catch(e){
    busy=false; card.style.pointerEvents=''; b.innerHTML='Send request'; check();
    setErr('slErr',explain(e));
  }
}

/* password screen */
function maskPhone(m){ m=String(m||''); return m.length>3?'•'.repeat(Math.min(7,m.length-3))+m.slice(-3):m; }
var coolT=0, reqT=0;
function paintCool(){
  clearInterval(coolT); var u=$('slUnlock'); if(!u) return;
  function tick(){
    var w=Math.ceil(((S.until||0)-Date.now())/1000);
    if(w>0){ u.disabled=true; perr('Too many wrong tries. Try again in '+w+'s.'); }
    else{ clearInterval(coolT); u.disabled=busy; perr(''); }
  }
  if((S.until||0)>Date.now()){ tick(); coolT=setInterval(tick,500); } else u.disabled=busy;
}
function paintReq(){
  clearTimeout(reqT);
  var box=$('slReqBox'), btn=$('slReq'), h=$('slReqHint'), lnk=$('slToForm'); if(!box) return;
  box.hidden=!S.sub; lnk.hidden=!!S.sub||!ON;
  if(!S.sub) return;
  var left=COOL-(Date.now()-(S.ask||0));
  if(S.ask&&left>0){
    btn.disabled=true; btn.textContent='Requested ✓';
    h.textContent='Request sent. Amarnath will contact you on your number. You can ask again in '+Math.ceil(left/60000)+' min.'; h.className='sl-hint ok';
    reqT=setTimeout(paintReq,Math.min(left,60000)+200);
  }else{
    btn.disabled=false; btn.textContent=S.ask?'Request password again':'Request password';
    h.textContent='Tap to ask Amarnath for the password. He will contact you on the number you gave.'; h.className='sl-hint';
  }
}
function paintPass(){
  var sub=$('slPS'), sent=$('slSent');
  sub.textContent=typeof S.relock==='string'?S.relock:(S.sub?'Your details are with Amarnath. Enter the password he gives you.':'Enter the app password to continue.');
  sent.hidden=!S.sub||!S.reg;
  if(S.sub&&S.reg) $('slWho').textContent=S.reg.n+' · '+maskPhone(S.reg.m);
  paintReq(); paintCool();
}
function steps(){
  var s=$('slSteps'); if(!s) return;
  s.style.display=ON?'flex':'none';
  var a=$('slS1'), b=$('slS2'), u=$('slU');
  a.className=view==='form'?'on':(S.sub?'ok':''); b.className=view==='pass'?'on':'';
  a.firstChild.textContent=(view==='pass'&&S.sub)?'✓':'1'; u.className=(view==='pass'&&S.sub)?'ok':'';
}
function show(v,anim,focus){
  view=v; var f=$('slForm'), p=$('slPass'); if(!f||!p) return;
  f.hidden=v!=='form'; p.hidden=v!=='pass';
  var c=v==='form'?f:p; if(anim){ c.classList.remove('sl-enter'); void c.offsetWidth; c.classList.add('sl-enter'); }
  steps();
  if(v==='form'){ check(); }
  else{
    paintPass(); getRec();                                    /* warm up auth + password record while the person types */
    if(focus!==false) setTimeout(function(){ var i=$('slPw'); if(i&&!busy) try{ i.focus({preventScroll:true}); }catch(e){ i.focus(); } },280);
  }
  var sc=document.querySelector('#slLock .sl-scroll'); if(sc) sc.scrollTop=0;
}

async function unlock(){
  if(busy) return;
  if((S.until||0)>Date.now()){ paintCool(); return; }
  var inp=$('slPw'), pw=norm(inp.value);
  if(!pw){ perr('Enter the password.'); shake(); return; }
  busy=true; perr('');
  var b=$('slUnlock'); b.disabled=true; b.innerHTML='<span class="sl-spin"></span>Checking…';
  var r=null, h='';
  try{ r=await getRec(); h=await pbkdf2(pw,r.rec.s,+r.rec.i); }catch(e){ if(!r) r={rec:DEF,live:false}; }
  busy=false; b.textContent='Unlock'; b.disabled=false;
  if(h&&r&&h===r.rec.h){ success(r.rec); return; }
  S.fails=(S.fails||0)+1; if(S.fails>=5){ S.fails=0; S.until=Date.now()+30000; } save();
  var msg='That password is not right.';
  if(ON&&r&&!r.live) msg+=' You seem to be offline. If the password was changed, connect to the internet and try again.';
  perr(msg); shake(); try{ inp.select(); }catch(e){} paintCool();
}
function confetti(o){
  var cols=['#E8A33D','#F7BE5E','#7EC9E8','#D9705B','#7FA875','#BFE8FA'], i, e, a, d;
  for(i=0;i<26;i++){
    e=document.createElement('i'); e.className='sl-cf'; a=Math.random()*Math.PI*2; d=90+Math.random()*150;
    e.style.cssText='--c:'+cols[i%6]+';--dx:'+Math.round(Math.cos(a)*d)+'px;--dy:'+Math.round(Math.sin(a)*d-40)+'px;--r:'+Math.round(Math.random()*540-270)+'deg;animation-delay:'+(Math.random()*120|0)+'ms';
    o.appendChild(e);
  }
}
var opening=false;
function success(rec){
  if(opening) return; opening=true;
  S.ok=1; S.at=Date.now(); S.pv=+rec.v||0; S.how=S.sub?'f':'d'; S.fails=0; S.until=0; delete S.relock; save();
  var o=$('slLock'); if(!o){ document.documentElement.classList.remove('sl-locked'); return; }
  perr(''); o.classList.add('sl-open'); confetti(o);
  setTimeout(function(){
    document.documentElement.classList.remove('sl-locked'); o.classList.add('sl-fade');
    setTimeout(function(){ if(o.parentNode) o.parentNode.removeChild(o); opening=false; },560);
  },950);
  setTimeout(function(){ ping(true); },1600);
}
async function reqPw(){
  if(busy||!S.sub||Date.now()-(S.ask||0)<COOL) return;
  busy=true; setErr('slRErr','');
  var b=$('slReq'); b.disabled=true; b.innerHTML='<span class="sl-spin"></span>Sending…';
  try{ await tok(); await ensureReg(); await db('PUT','lock/u/'+S.uid+'/ask',SV); S.ask=Date.now(); save(); }
  catch(e){ setErr('slRErr',explain(e)); }
  busy=false; paintReq();
}

function buildGate(){
  var old=$('slLock'); if(old&&old.parentNode) old.parentNode.removeChild(old);
  opening=false; busy=false; ans=''; injectCss();
  var o=document.createElement('div'); o.id='slLock'; o.setAttribute('role','dialog'); o.setAttribute('aria-modal','true'); o.setAttribute('aria-label','Study Log lock');
  o.innerHTML=bgHtml()+'<div class="sl-scroll"><div class="sl-wrap">'
    +'<div class="sl-brand"><div class="sl-bt">STUDY <span>LOG</span></div><div class="sl-sig">by Amarnath</div></div>'
    +'<div class="sl-steps" id="slSteps"><b id="slS1"><i>1</i>Details</b><u id="slU"></u><b id="slS2"><i>2</i>Password</b></div>'
    +formHtml()+passHtml()+'</div></div>';
  document.body.insertBefore(o,document.body.firstChild);
  var i;
  ['slN','slC','slM','slX'].forEach(function(id){ $(id).addEventListener('input',function(){ if(id==='slM'){ var p=this.value, q=p.replace(/[^\d+\-\s().]/g,''); if(p!==q) this.value=q; } this.classList.remove('bad'); check(); }); });
  $('slN').addEventListener('blur',function(){ this.classList.toggle('bad',!!this.value.trim()&&this.value.trim().length<2); });
  $('slM').addEventListener('blur',function(){ this.classList.toggle('bad',!!this.value.trim()&&!phoneOk(cleanPhone(this.value))); });
  $('slO').addEventListener('change',check);
  Array.prototype.forEach.call(o.querySelectorAll('.sl-seg button'),function(b){ b.addEventListener('click',function(){
    ans=b.getAttribute('data-k'); Array.prototype.forEach.call(o.querySelectorAll('.sl-seg button'),function(x){ var on=x===b; x.classList.toggle('on',on); x.setAttribute('aria-pressed',on?'true':'false'); }); check();
  }); });
  $('slSend').addEventListener('click',submitForm);
  $('slAlready').addEventListener('click',function(){ if(busy) return; S.sk=1; save(); show('pass',true,true); });
  $('slToForm').addEventListener('click',function(){ if(busy) return; S.sk=0; save(); show('form',true); });
  $('slEye').addEventListener('click',function(){ var p=$('slPw'), on=p.type==='password'; p.type=on?'text':'password'; this.innerHTML=on?IC.eyeoff:IC.eye; this.classList.toggle('on',on); this.setAttribute('aria-label',on?'Hide password':'Show password'); p.focus(); });
  $('slUnlock').addEventListener('click',unlock);
  $('slPw').addEventListener('keydown',function(e){ if(e.key==='Enter'){ e.preventDefault(); unlock(); } });
  $('slPw').addEventListener('input',function(){ if($('slPErr').classList.contains('show')&&!((S.until||0)>Date.now())) perr(''); });
  $('slReq').addEventListener('click',reqPw);
  show((S.sub||S.sk||!ON)?'pass':'form',false,!S.sub);
}
function whenBody(fn){
  if(document.body) return fn();
  var mo=new MutationObserver(function(){ if(document.body){ mo.disconnect(); fn(); } });
  mo.observe(document.documentElement,{childList:true});
}
function relock(msg){
  S.ok=0; S.relock=msg||true; S.fails=0; S.until=0; if(!S.sub) S.sk=1; save();
  document.documentElement.classList.add('sl-locked');
  whenBody(buildGate);
}

/* ---- start ---- */
function boot(){
  if(S.ok===1){ setTimeout(function(){ ping(); sync(); },2500); }
  else{ document.documentElement.classList.add('sl-locked'); injectCss(); whenBody(buildGate); }
}
document.addEventListener('visibilitychange',function(){ if(!document.hidden&&S.ok===1){ ping(); sync(); } });
window.addEventListener('online',function(){ if(S.ok===1){ ping(); sync(); } });
window.SLLock={
  ON:ON, tok:tok, db:db, explain:explain, pbkdf2:pbkdf2, norm:norm, rhex:rhex, esc:esc,
  ITER_PW:ITER_PW, SV:SV,
  uid:function(){ return S.uid||''; },
  setPv:function(v){ S.pv=+v||0; save(); }
};
boot();
})();
