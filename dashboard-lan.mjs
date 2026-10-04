import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {randomBytes,createHash} from 'node:crypto';
export const tokenDigest=key=>createHash('sha256').update(String(key??'')).digest();

// Persisted state for the "Serve Dashboard on Local Network" toggle. The
// dashboard binds loopback by default; enabling this rebinds it to every
// interface and requires API-key sign-in for non-loopback browsers.
export const dashboardLanFile=config=>path.join(path.dirname(config.state_file),'dashboard-lan.json');
export const dashboardBindAddress=enabled=>enabled?'0.0.0.0':'127.0.0.1';
export function readDashboardLan(file,initialEnabled=false){
  let value;
  try{value=JSON.parse(fs.readFileSync(file,'utf8'));}
  catch(error){if(error.code==='ENOENT')return {schema:1,enabled:initialEnabled===true};throw new Error('Dashboard LAN state cannot be read; existing state must be preserved');}
  if(value?.schema!==1||typeof value.enabled!=='boolean')throw new Error('Invalid dashboard LAN state; existing state must be preserved');
  return {schema:1,enabled:value.enabled};
}
export function writeDashboardLan(file,enabled){
  if(typeof enabled!=='boolean')throw new Error('Dashboard LAN enabled must be boolean');
  readDashboardLan(file);
  const value={schema:1,enabled},temporary=`${file}.${randomBytes(16).toString('hex')}.tmp`;
  fs.mkdirSync(path.dirname(file),{recursive:true,mode:0o700});
  try{
    if(fs.existsSync(file))fs.copyFileSync(file,`${file}.${Date.now()}.bak`,fs.constants.COPYFILE_EXCL);
    const fd=fs.openSync(temporary,'wx',0o600);
    try{fs.writeFileSync(fd,JSON.stringify(value)+'\n');fs.fsyncSync(fd);}finally{fs.closeSync(fd);}
    fs.renameSync(temporary,file);
  }finally{try{fs.unlinkSync(temporary);}catch(error){if(error.code!=='ENOENT')throw error;}}
  return value;
}
// Private IPv4 addresses only: a public or tunnel interface is never offered
// as a LAN dashboard address.
export function dashboardLanUrls(port,interfaces=os.networkInterfaces()){
  const privateIPv4=address=>/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(address);
  return [...new Set(Object.entries(interfaces).filter(([name])=>!/^(utun|tun|tap|tailscale|docker|veth|awdl|llw|bridge|gif|stun|ipsec|firewall|lladopt)/i.test(name))
    .sort(([a],[b])=>a.localeCompare(b,undefined,{numeric:true})).flatMap(([,rows])=>(rows??[])
      .filter(row=>!row.internal&&row.family==='IPv4'&&privateIPv4(row.address)&&Number.isInteger(port)&&port>0&&port<=65535)
      .map(row=>`http://${row.address}:${port}/`)))];
}
// The sign-in page carries no secret and no script; it posts the gateway
// API key once over the form and receives an HttpOnly session cookie.
export const dashboardLoginPage=()=>`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Star Gate sign-in</title></head>
<body><h1>Star Gate dashboard</h1>
<p>This dashboard is serving on the local network. Enter the gateway API key to start a session on this device.</p>
<form method="post" action="/api/dashboard-login" enctype="application/x-www-form-urlencoded">
<label>API key <input type="password" name="token" autocomplete="current-password" autofocus></label>
<button type="submit">Unlock dashboard</button>
</form>
</body></html>`;
export const dashboardSessionCookie='dsg_dash';
export const dashboardRequestSession=(req)=>{const prefix=`${dashboardSessionCookie}=`;for(const part of String(req.headers.cookie??'').split(/;\s*/).filter(Boolean))if(part.startsWith(prefix))return part.slice(prefix.length);return null;};
export const parseLoginForm=(body)=>new URLSearchParams(String(body??'')).get('token')??'';
export const dashboardSessionTtlMs=12*60*60*1000;
export function createDashboardSessionStore(ttlMs=dashboardSessionTtlMs){
  const sessions=new Map();
  const issue=()=>{const token=randomBytes(32).toString('base64url');sessions.set(token,Date.now()+ttlMs);return token;};
  const validate=cookie=>{const expiry=sessions.get(cookie);if(!expiry)return false;if(Date.now()>expiry){sessions.delete(cookie);return false;}return true;};
  const prune=()=>{const now=Date.now();for(const [token,expiry] of sessions)if(now>expiry)sessions.delete(token);};
  return {issue,validate,prune};
}
