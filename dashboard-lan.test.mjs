import test from 'node:test'; import assert from 'node:assert/strict'; import {request as httpRequest} from 'node:http';
import {mkdtempSync,writeFileSync,mkdirSync,statSync,rmSync} from 'node:fs'; import {rm} from 'node:fs/promises'; import {tmpdir} from 'node:os'; import {join} from 'node:path';
import {dashboardLanFile,dashboardBindAddress,readDashboardLan,writeDashboardLan,dashboardLanUrls,dashboardLoginPage,dashboardRequestSession,parseLoginForm,createDashboardSessionStore,dashboardSessionCookie,tokenDigest} from './dashboard-lan.mjs';
import {createDashboard} from './dashboard.mjs';
import {fileURLToPath} from 'node:url';
const here=join(fileURLToPath(import.meta.url),'..','..','ds4-gateway');
const workspace=t=>{const directory=mkdtempSync(join(tmpdir(),'dashboard-lan-'));t.after(()=>rm(directory,{recursive:true,force:true}));return directory;};
import {cpSync} from 'node:fs';
const assetDir=dir=>{const target=join(dir,'ui');cpSync(join(here,'ui'),target,{recursive:true});return target;};
const lanControls=(key)=>{const sessions=createDashboardSessionStore();let state=false;return {sessions,hasApiKey:Boolean(key),tokenDigest:tokenDigest(key),enabled:()=>Boolean(key)&&state,read:()=>({enabled:state,serving:Boolean(key)&&state,urls:[]}),write:async v=>{state=v;return {enabled:v,restart_required:true};}};};
const listen=async server=>{await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));return server;};
// Raw http keeps the Host header under our control, which fetch would normalize.
const request=(port,path,options={})=>new Promise((resolve,reject)=>{const headers={host:`127.0.0.1:${port}`,...(options.headers??{})};const req=httpRequest({host:'127.0.0.1',port,path,method:options.method??'GET',headers},res=>{const chunks=[];res.on('data',c=>chunks.push(c));res.on('end',()=>{const text=Buffer.concat(chunks).toString('utf8');resolve({status:res.statusCode,headers:res.headers,text});});});req.on('error',reject);if(options.body!==undefined)req.write(options.body);req.end();});
// Forge a non-loopback peer address so the session gate exercises LAN clients.
const asRemote=(server,address)=>server.on('connection',socket=>Object.defineProperty(socket,'remoteAddress',{value:address}));

test('dashboard LAN state is off by default, persists, and stays private', async t=>{
  const directory=workspace(t),file=dashboardLanFile({state_file:join(directory,'state.json')});
  assert.equal(readDashboardLan(file).enabled,false,'dashboard LAN serving stays off until explicitly enabled');
  writeFileSync(file,'',{mode:0o600});assert.throws(()=>readDashboardLan(file),/preserved|Invalid/,'a corrupt state file never silently enables or clears serving');
  assert.throws(()=>writeDashboardLan(file,true),/preserved/,'a write refuses to overwrite corrupt state without preserving it');
  rmSync(file);assert.equal(writeDashboardLan(file,true).enabled,true);assert.equal(readDashboardLan(file).enabled,true);
  assert.equal((statSync(file).mode&0o777).toString(8),'600','dashboard LAN state is owner-only');
  assert.throws(()=>writeDashboardLan(file,'yes'),/boolean/,'only a boolean toggle is accepted');
});
test('dashboard bind widens only when the toggle is on',async()=>{
  assert.equal(dashboardBindAddress(false),'127.0.0.1','the dashboard binds loopback by default');
  assert.equal(dashboardBindAddress(true),'0.0.0.0');
});
test('dashboard LAN URLs stay private and skip tunnel or virtual interfaces',()=>{
  const urls=dashboardLanUrls(30010,{en0:[{family:'IPv4',address:'192.168.10.14'},{family:'IPv4',address:'8.8.8.8',internal:false}],utun5:[{family:'IPv4',address:'10.99.0.2'}],lo0:[{family:'IPv4',address:'127.0.0.1',internal:true}]});
  assert.deepEqual(urls,['http://192.168.10.14:30010/'],'only a private, non-tunnel interface address is offered as a LAN dashboard URL');
});
test('dashboard sign-in page carries no secret and no script',()=>{
  const page=dashboardLoginPage();
  assert.ok(page.includes('/api/dashboard-login')&&page.includes('password'));
  assert.ok(!/<script/i.test(page),'the sign-in page embeds no script');
  assert.ok(!/test-key|\btoken\s*=/.test(page.replace(/name="token"/g,'')),'the sign-in page never embeds a key value');
});
test('login form, cookie parsing, and sessions behave',async()=>{
  assert.equal(parseLoginForm('token=abc123'),'abc123');assert.equal(parseLoginForm('other=1'),'');
  const parsed={headers:{cookie:`other=x; ${dashboardSessionCookie}=tok1; y=z`}};assert.equal(dashboardRequestSession(parsed),'tok1');
  assert.equal(tokenDigest('k').length,32);assert.deepEqual(tokenDigest('k'),tokenDigest('k'));
  const store=createDashboardSessionStore(1);const token=store.issue();assert.equal(store.validate(token),true);
  await new Promise(resolve=>setTimeout(resolve,10));assert.equal(store.validate(token),false,'a session expires');
  store.prune();assert.equal(store.validate(null),false);
});
test('loopback dashboard behavior is unchanged while LAN serving is off',async t=>{
  const directory=workspace(t),server=await listen(createDashboard(()=>({ok:true}),assetDir(directory),null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,lanControls('test-key')));
  const port=server.address().port;t.after(()=>new Promise(resolve=>{server.closeAllConnections();server.close(resolve);}));
  assert.equal((await request(port,'/')).status,200,'loopback keeps its location-based trust');
  const state=await request(port,'/api/dashboard-lan');const body=JSON.parse(state.text);
  assert.equal(state.status,200);assert.equal(body.available,true);assert.equal(body.enabled,false,'the toggle defaults to off');
  assert.equal((await request(port,'/api/dashboard-lan',{method:'POST',headers:{'content-type':'application/json'},body:'{"enabled":true}'})).status,403,'a toggle without the CSRF token is refused');
});
test('a LAN browser signs in with the gateway API key before seeing the dashboard',async t=>{
  const directory=workspace(t),controls=lanControls('test-key');
  const server=await listen(createDashboard(()=>({ok:true}),assetDir(directory),null,null,null,null,null,null,null,null,null,null,null,null,null,null,null,controls));
  const port=server.address().port;asRemote(server,'192.168.10.99');
  t.after(()=>new Promise(resolve=>{server.closeAllConnections();server.close(resolve);}));
  const urls=dashboardLanUrls(port);if(!urls.length)return t.skip('no private IPv4 interface on this machine');
  const host=new URL(urls[0]).host;
  assert.equal((await request(port,'/',{headers:{host}})).status,403,'a LAN request is refused while serving is off');
  await controls.write(true);
  const gate=await request(port,'/',{headers:{host}});
  assert.equal(gate.status,401,'a LAN browser without a session sees the sign-in page');
  assert.match(gate.text,/dashboard-login/);
  assert.equal((await request(port,'/api/status',{headers:{host}})).status,401,'LAN API calls require a session too');
  assert.equal((await request(port,'/api/dashboard-login',{method:'POST',headers:{host,'content-type':'application/x-www-form-urlencoded'},body:'token=nope'})).status,401,'a wrong key is refused');
  const good=await request(port,'/api/dashboard-login',{method:'POST',headers:{host,'content-type':'application/x-www-form-urlencoded'},body:'token=test-key'});
  assert.equal(good.status,303);const cookie=(good.headers['set-cookie']??[])[0]??'';
  assert.match(cookie,new RegExp('^'+dashboardSessionCookie+'='));
  assert.ok(/HttpOnly/.test(cookie)&&/SameSite=Lax/.test(cookie)&&/Max-Age=/.test(cookie),'the session cookie is HttpOnly and never holds the key');
  assert.equal((await request(port,'/',{headers:{host,cookie}})).status,200,'a signed-in LAN browser reaches the dashboard');
  assert.equal((await request(port,'/',{headers:{host:'evil.example:'+port}})).status,403,'DNS rebinding stays dead even in LAN mode');
});
