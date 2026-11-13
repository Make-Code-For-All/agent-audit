import worker from './src/index.js';
import { webcrypto, createHmac } from 'node:crypto';
const store = new Map();
const env = { ALLOWED_ORIGIN:'https://me.github.io', SCANNER_REPO:'me/agent-audit', SCANNER_BRANCH:'main', WORKFLOW_FILE:'scan.yml',
  GITHUB_TOKEN:'tok', CALLBACK_SECRET:'s3cret',
  SCANS:{ get:async k=>store.has(k)?store.get(k):null, put:async(k,v)=>{store.set(k,v)}, delete:async k=>{store.delete(k)} } };
const SHA='a'.repeat(40);
let dispatched=[]; let archiveAuth='unset';
globalThis.fetch = async (url, init={}) => {
  const u=String(url);
  if (u==='https://api.github.com/repos/octo/hello') return Response.json({full_name:'octo/hello',private:false,size:100,default_branch:'main'});
  if (u==='https://api.github.com/repos/octo/secret') return Response.json({full_name:'octo/secret',private:true,size:1,default_branch:'main'});
  if (u==='https://api.github.com/repos/octo/missing') return new Response('{}',{status:404});
  if (u==='https://api.github.com/repos/octo/huge') return Response.json({full_name:'octo/huge',private:false,size:9e6,default_branch:'main'});
  if (u===`https://api.github.com/repos/octo/hello/commits/${SHA}`) return Response.json({sha:SHA});
  if (u.includes('/actions/workflows/scan.yml/dispatches')) { dispatched.push(JSON.parse(init.body)); return new Response(null,{status:204}); }
  if (u.startsWith('https://api.github.com/repos/octo/hello/commits?')) return Response.json([{sha:SHA,commit:{message:'m',author:{name:'n',date:'2024-01-01T00:00:00Z'}}}]);
  if (u==='https://api.github.com/users/octo') return Response.json({type:'User',created_at:'2015-01-01T00:00:00Z',email:'private@example.com'});
  if (u==='https://api.github.com/repos/octo/hello/contributors?per_page=30') return Response.json([{login:'a'},{login:'b'}]);
  if (u===`https://codeload.github.com/octo/hello/tar.gz/${SHA}`) { archiveAuth=(init.headers||{}).Authorization; return new Response('TARBYTES'); }
  if (u===`https://codeload.github.com/octo/secret/tar.gz/${SHA}`) return new Response('',{status:404});
  throw new Error('unexpected fetch '+u);
};
const call=(path,opts={})=>worker.fetch(new Request('https://api.example'+path,{...opts,headers:{Origin:'https://me.github.io','CF-Connecting-IP':opts.ip||'1.1.1.1','Content-Type':'application/json',...(opts.headers||{})}}),env);
const scan=(body,ip)=>call('/scan',{method:'POST',body:JSON.stringify(body),ip});
let pass=0,fail=0; const ok=(c,m)=>{c?pass++:(fail++,console.log('FAIL',m))};

let r=await scan({repo:'https://github.com/octo/hello'}); let j=await r.json();
ok(r.status===200&&/^r[0-9a-f]{20}$/.test(j.jobId),'scan starts'); const id=j.jobId;
ok(r.headers.get('access-control-allow-origin')==='https://me.github.io','cors allowed origin');
ok(dispatched.length===1&&dispatched[0].inputs.run_key===id&&dispatched[0].inputs.commit===SHA&&dispatched[0].inputs.target==='octo/hello','dispatch inputs');
r=await call('/result/'+id); j=await r.json(); ok(j.status==='pending','pending result');
// duplicate request reuses job
r=await scan({repo:'octo/hello',commit:SHA}); j=await r.json(); ok(j.jobId===id&&j.cached&&dispatched.length===1,'dedupe');
// callback: bad signature
const report={schema:1,target:'octo/hello',commit:SHA,tools:{semgrep:{ok:true,findings:[]}}};
const body=JSON.stringify({status:'done',report});
const sig=createHmac('sha256','s3cret').update(body).digest('hex');
r=await call('/callback?job='+id,{method:'POST',body,headers:{'X-Signature':'sha256='+'0'.repeat(64)}}); ok(r.status===401,'bad signature rejected');
r=await call('/callback?job='+id,{method:'POST',body,headers:{}}); ok(r.status===401,'missing signature rejected');
// wrong repo in report
const bad=JSON.stringify({status:'done',report:{...report,target:'evil/x'}});
r=await call('/callback?job='+id,{method:'POST',body:bad,headers:{'X-Signature':'sha256='+createHmac('sha256','s3cret').update(bad).digest('hex')}}); ok(r.status===400,'mismatched report rejected');
r=await call('/callback?job='+id,{method:'POST',body,headers:{'X-Signature':'sha256='+sig}}); ok(r.status===200,'good callback');
r=await call('/callback?job='+id,{method:'POST',body,headers:{'X-Signature':'sha256='+sig}}); ok(r.status===409,'replay rejected');
r=await call('/result/'+id); j=await r.json(); ok(j.status==='done'&&j.report.schema===1,'done result');
r=await scan({repo:'octo/hello'}); j=await r.json(); ok(j.jobId===id&&j.status==='done','cached finished scan');
// validation
r=await scan({repo:'not a repo'}); ok(r.status===400,'bad repo');
r=await scan({repo:'octo/hello',commit:'zzz'}); ok(r.status===400,'bad commit');
r=await scan({repo:'octo/secret'}); ok(r.status===404,'private repo refused');
r=await scan({repo:'octo/missing'}); ok(r.status===404,'missing repo');
r=await scan({repo:'octo/huge'}); ok(r.status===413,'huge repo refused');
r=await worker.fetch(new Request('https://api.example/scan',{method:'POST',body:'{}',headers:{Origin:'https://evil.example','Content-Type':'application/json'}}),env); ok(r.status===403,'foreign origin refused');
r=await worker.fetch(new Request('https://api.example/scan',{method:'POST',body:'{}',headers:{'Content-Type':'application/json'}}),env); ok(r.status===403,'missing origin refused');
r=await call('/scan',{method:'POST',body:JSON.stringify({repo:'octo/hello'}),headers:{'Content-Type':'text/plain'}}); ok(r.status===415,'non-JSON content type refused');
r=await call('/result/'+id); ok(r.headers.get('x-content-type-options')==='nosniff'&&/frame-ancestors 'none'/.test(r.headers.get('content-security-policy'))&&r.headers.get('referrer-policy')==='no-referrer','security headers present');
r=await call('/scan',{method:'OPTIONS'}); ok(r.status===204&&r.headers.get('x-content-type-options')==='nosniff','preflight has headers');
r=await call('/result/nope'); ok(r.status===404,'bad id');
// failure callback + retry creates new job
dispatched=[]; r=await scan({repo:'octo/hello',commit:SHA},'2.2.2.2'); 
// same sha cached as done -> still cached; use fresh store key to simulate failure
store.clear(); r=await scan({repo:'octo/hello'},'3.3.3.3'); j=await r.json(); const id2=j.jobId;
const fb=JSON.stringify({status:'failed',message:'nope'});
r=await call('/callback?job='+id2,{method:'POST',body:fb,headers:{'X-Signature':'sha256='+createHmac('sha256','s3cret').update(fb).digest('hex')}}); ok(r.status===200,'failure callback');
r=await call('/result/'+id2); j=await r.json(); ok(j.status==='failed'&&j.message==='nope','failed result');
r=await scan({repo:'octo/hello'},'3.3.3.3'); j=await r.json(); ok(j.jobId!==id2,'failed job is retried with new id');
// per-IP limit
let last; for(let i=0;i<8;i++){ last=await scan({repo:'octo/missing'},'9.9.9.9'); } ok(last.status===429,'per-IP rate limit');
// dispatch failure cleans up
const orig=globalThis.fetch; globalThis.fetch=async(u,i)=>String(u).includes('dispatches')?new Response('boom',{status:500}):orig(u,i);
store.clear(); r=await scan({repo:'octo/hello'},'4.4.4.4'); ok(r.status===502,'dispatch failure -> 502'); ok(![...store.keys()].some(k=>k.startsWith('job:')),'no orphan job');
// quick-scan endpoints: repository details and whole-repository archive
r=await call('/repo?repo='+encodeURIComponent('https://github.com/octo/hello')); j=await r.json();
ok(r.status===200&&j.sha===SHA&&j.ref==='main'&&j.meta.default_branch==='main'&&j.contributors.length===2&&j.commits[0].commit.message==='m','repo details');
ok(j.ownerInfo.type==='User'&&!('email' in j.ownerInfo),'owner details are trimmed');
r=await call('/repo?repo=octo/secret'); ok(r.status===404,'repo details refuse private');
r=await call('/repo?repo=octo/missing'); ok(r.status===404,'repo details missing');
r=await call('/repo?repo=octo/hello&ref='+encodeURIComponent('bad ref;')); ok(r.status===400,'repo details bad ref');
r=await call('/repo?repo=octo/hello',{headers:{Origin:'https://evil.example'}}); ok(r.status===403,'repo details other origin');
r=await call(`/archive/octo/hello/${SHA}`);
ok(r.status===200&&(await r.text())==='TARBYTES'&&r.headers.get('access-control-allow-origin')==='https://me.github.io','archive passes through');
ok(archiveAuth===undefined,'archive request carries no token');
r=await call(`/archive/octo/secret/${SHA}`); ok(r.status===404,'archive private is 404');
r=await call('/archive/octo/hello/main'); ok(r.status===400,'archive needs a full commit');
r=await call(`/archive/octo/../${SHA}`); ok(r.status===400||r.status===404,'archive rejects dot-dot');
r=await call(`/archive/octo/hello/${SHA}`,{headers:{Origin:'https://evil.example'}}); ok(r.status===403,'archive other origin');
// a pending job that never reported back is abandoned after 45 minutes
store.clear(); dispatched=[]; globalThis.fetch=orig;
r=await scan({repo:'octo/hello'},'5.5.5.5'); j=await r.json(); const lostId=j.jobId;
r=await scan({repo:'octo/hello'},'5.5.5.6'); j=await r.json(); ok(j.jobId===lostId&&j.cached&&dispatched.length===1,'fresh pending job is joined');
const lost=JSON.parse(store.get('job:'+lostId)); lost.createdAt=Date.now()-46*60*1000; store.set('job:'+lostId,JSON.stringify(lost));
r=await call('/result/'+lostId); j=await r.json(); ok(j.status==='failed'&&/scan again/.test(j.message),'stale pending job reads as failed');
r=await scan({repo:'octo/hello'},'5.5.5.7'); j=await r.json(); ok(j.jobId!==lostId&&!j.cached&&dispatched.length===2,'stale pending job is replaced by a new scan');
console.log(`${pass} passed, ${fail} failed`);

process.exit(fail?1:0);
