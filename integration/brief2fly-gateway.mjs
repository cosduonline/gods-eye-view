import http from 'node:http';
import net from 'node:net';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { spawn } from 'node:child_process';

const base = process.env.B2F_SUPABASE_URL?.replace(/\/$/, '');
const key = process.env.B2F_SUPABASE_PUBLIC_KEY;
const secret = process.env.B2F_GATEWAY_SECRET;
const port = Number(process.env.PORT || 10000);
const upstreamPort = port === 4173 ? 4174 : 4173;
const host = process.env.RENDER_EXTERNAL_HOSTNAME;
if (!base || !key || !secret || secret.length < 32 || !host || !/^https:\/\//.test(base)) {
  console.error('Gateway configuration missing; refusing to serve.'); process.exit(1);
}
const vite = spawn(process.execPath, ['node_modules/vite/bin/vite.js','--host','127.0.0.1','--port',String(upstreamPort),'--strictPort'], {
  stdio:'inherit', env:{...process.env, HOST:'127.0.0.1', PORT:String(upstreamPort), GEV_ALLOWED_HOSTS:host, GEV_KEY_SETUP_TRUSTED_PEERS:'none'}
});
vite.on('exit', () => process.exit(1));
for (const sig of ['SIGTERM','SIGINT']) process.on(sig,()=>{vite.kill(sig);process.exit(0)});
const sign = (text) => createHmac('sha256',secret).update(text).digest('base64url');
function session(token) { const val=Buffer.from(token).toString('base64url'); return val+'.'+sign(val); }
function getToken(req) {
 const cookie=(req.headers.cookie || '').split(';').map(x=>x.trim()).find(x=>x.startsWith('b2f_gev='));
 if(!cookie)return null; const [v,s,...rest]=cookie.slice(8).split('.'); if(!v||!s||rest.length)return null;
 const a=Buffer.from(sign(v)),b=Buffer.from(s); if(a.length!==b.length||!timingSafeEqual(a,b))return null;
 try{return Buffer.from(v,'base64url').toString('utf8')}catch{return null}
}
const cached = new Map();
async function isAdmin(token) {
 if(!token)return false; const c=cached.get(token); if(c && c>Date.now())return true;
 try {
  const headers={apikey:key,Authorization:'Bearer '+token};
  const u=await fetch(base+'/auth/v1/user',{headers,signal:AbortSignal.timeout(8000)}); if(!u.ok)return false;
  const user=await u.json(); if(!user.email || !user.email_confirmed_at)return false;
  const query=new URLSearchParams({select:'email,role,active,approval_status',email:'eq.'+user.email.toLowerCase(),active:'eq.true',approval_status:'eq.approved',role:'eq.admin'});
  const m=await fetch(base+'/rest/v1/app_members?'+query,{headers,signal:AbortSignal.timeout(8000)}); if(!m.ok)return false;
  const members=await m.json(); if(!Array.isArray(members)||members.length!==1)return false;
  if(cached.size>100)cached.clear(); cached.set(token,Date.now()+10000);return true;
 } catch { return false; }
}
function html(res,status,message='') {
 res.writeHead(status,{'content-type':'text/html; charset=utf-8','cache-control':'no-store','x-frame-options':'DENY','content-security-policy':"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",'x-content-type-options':'nosniff'});
 res.end(`<!doctype html><html lang="en"><meta name="viewport" content="width=device-width"><title>Brief2fly admin sign in</title><style>body{font:16px system-ui;background:#091827;color:white;display:grid;place-items:center;min-height:90vh}main{background:#102c3d;padding:2rem;border-radius:12px;width:min(80vw,380px)}input,button{display:block;box-sizing:border-box;width:100%;padding:12px;margin:12px 0;border:0;border-radius:5px}button{background:#9be5d4;font-weight:bold}p{color:#ffbf98}</style><main><h1>Brief2fly</h1><h2>God’s Eye View 3D</h2><p>${message}</p><form method="post" action="/__brief2fly/login"><label>Email<input type="email" name="email" required autocomplete="username"></label><label>Password<input type="password" name="password" required autocomplete="current-password"></label><button type="submit">Admin sign in</button></form></main></html>`);
}
const sameOrigin = (req) => req.headers.origin === 'https://'+host;
async function login(req,res) {
 if(!sameOrigin(req)){res.writeHead(403).end();return}
 let body=''; for await (const chunk of req) {body+=chunk;if(body.length>8192){res.writeHead(413).end();return}}
 try {
  const form=new URLSearchParams(body);const email=form.get('email'),password=form.get('password');
  if(!email||!password)return html(res,400,'Sign-in failed.');
  const reply=await fetch(base+'/auth/v1/token?grant_type=password',{method:'POST',headers:{apikey:key,'content-type':'application/json'},body:JSON.stringify({email,password}),signal:AbortSignal.timeout(10000)});
  if(!reply.ok)return html(res,401,'Sign-in failed.');const data=await reply.json();
  if(!data.access_token || !await isAdmin(data.access_token))return html(res,403,'Admin access required.');
  res.writeHead(303,{'location':'/','set-cookie':`b2f_gev=${session(data.access_token)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${Math.min(Number(data.expires_in)||3600,3600)}`,'cache-control':'no-store'});res.end();
 }catch{return html(res,503,'Sign-in temporarily unavailable.')}
}
function proxy(req,res) {
 const headers={...req.headers,host};delete headers.cookie;delete headers.authorization;delete headers['x-forwarded-host'];delete headers['x-forwarded-proto'];
 const p=http.request({host:'127.0.0.1',port:upstreamPort,path:req.url,method:req.method,headers},up=>{res.writeHead(up.statusCode,{...up.headers,'cache-control':'private, no-store'});up.pipe(res)});
 p.on('error',()=>{if(!res.headersSent)res.writeHead(503);res.end('Starting or unavailable')});req.pipe(p);
}
const server=http.createServer(async(req,res)=>{
 res.setHeader('cache-control','private, no-store');
 if(req.url==='/__brief2fly/login'&&req.method==='POST')return login(req,res);
 if(!await isAdmin(getToken(req)))return html(res,401);
 proxy(req,res);
});
server.on('upgrade',async(req,socket,head)=>{
 if(!sameOrigin(req)||!await isAdmin(getToken(req))){socket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');return}
 const upstream=net.connect(upstreamPort,'127.0.0.1',()=>{
  let h=`${req.method} ${req.url} HTTP/${req.httpVersion}\r\n`;
  for(let i=0;i<req.rawHeaders.length;i+=2){let name=req.rawHeaders[i],value=req.rawHeaders[i+1];if(/^(cookie|authorization|x-forwarded-host|x-forwarded-proto)$/i.test(name))continue;if(/^host$/i.test(name))value=host;h+=`${name}: ${value}\r\n`}
  upstream.write(h+'\r\n');if(head.length)upstream.write(head);socket.pipe(upstream).pipe(socket);
 });upstream.on('error',()=>socket.destroy());socket.on('error',()=>upstream.destroy());
});
server.listen(port,'0.0.0.0',()=>console.log('Brief2fly admin gateway listening'));
