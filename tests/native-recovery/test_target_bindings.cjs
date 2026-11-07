'use strict';
// Synthetic read-only attachment exercises the public target-hash parameterization.
const fs=require('node:fs'),path=require('node:path'),vm=require('node:vm');
const assert=require('node:assert/strict'),crypto=require('node:crypto');
const root=path.join(__dirname,'../../tools/native-recovery');
const hash=x=>crypto.createHash('sha256').update(x).digest('hex');
const names=['native_file_channel.py','trusted_admin_journal.py','permanent_recovery.py','legacy015_recovery.py','managed_service.py','runtime.py'];
const files=new Map(names.map(n=>['/opt/importer/'+n,fs.readFileSync(path.join(root,'service',n))]));
const sources=Object.fromEntries(names.map(n=>[n,hash(files.get('/opt/importer/'+n))]));
const original='a'.repeat(64),current='b'.repeat(64);
const runtime=hash('synthetic runtime'),job=hash('synthetic job');
const ACK='Trusted administrator maintenance: prior installs and rollbacks settled; no concurrent install, rollback, start, rename or file modification; ordinary container confinement; no escaped writer';
const P='uvm.public.dappnode.eth',V='uvmpublicdappnodeeth_ship_data';
function fixture(target) {
 const calls=[];
 const context=vm.createContext({TextEncoder,TextDecoder,Uint8Array,Uint32Array,DataView,AbortController,
  setTimeout,clearTimeout,performance,crypto:crypto.webcrypto,location:{hostname:'my.dappnode',protocol:'http:'},
  fetch:async(url,init)=>{
   calls.push({url,body:init.body&&JSON.parse(init.body)});
   let raw;
   if(url.startsWith('/file-download/')){
    const p=new URL('http://my.dappnode'+url).searchParams.get('path');
    raw=p==='/urbit/control/native-file-status.json'?JSON.stringify({policy:'TRUSTED_NATIVE_ADMIN_MAINTENANCE_V1',feature_retained:true,sources,generation:'c'.repeat(64),error:null,state:'MAINTENANCE',sequence:0,state_sha256:null,runtime_sha256:runtime,job_sha256:job}):files.get(p);
    assert(raw,'Unexpected file');
   }else{
    const q=JSON.parse(init.body);let result;
    if(url==='/mcp')result={tools:['dappnode_stop_package','dappnode_start_package'].map(name=>({name}))};
    else if(q.method==='autoUpdateDataGet')result={dnpsToShow:[{id:P,enabled:false},{id:'system-packages',enabled:false}]};
    else{
     assert(['packageGet','packagesGet'].includes(q.method),'Unexpected mutation');
     const pkg={dnpName:P,containers:[{containerId:current,containerName:'DAppNodePackage-ship.'+P,serviceName:'ship',state:'running',image:'ship.'+P+':fixture',volumes:[{name:V,host:'/var/lib/docker/volumes/'+V+'/_data',container:'/urbit'}]}]};
     result=q.method==='packageGet'?pkg:[pkg];
    }
    raw=JSON.stringify(url==='/mcp'?{id:q.id,result}:{result});
   }
   return new Response(raw,{headers:{'content-type':'application/json'}});
  }});
 vm.runInContext(fs.readFileSync(path.join(root,'native-controller.js'),'utf8'),context);
 const controller=context.createNativeFileRecovery(sources,ACK,target);
 assert.equal(calls.length,0);
 return {controller,calls};
}
(async()=>{
 const target={originalContainerId:original,runtimeSha256:runtime,jobSha256:job};
 const good=fixture(target);target.runtimeSha256='f'.repeat(64);
 assert.equal((await good.controller.attach()).phase,'ATTACHED');
 for(const change of [{runtimeSha256:'e'.repeat(64)},{jobSha256:'e'.repeat(64)},{originalContainerId:current}]){
  const f=fixture({originalContainerId:original,runtimeSha256:runtime,jobSha256:job,...change});
  await assert.rejects(f.controller.attach());
  assert.equal(f.controller.state().phase,'UNCERTAIN');
  assert(!f.calls.some(c=>c.body?.method==='tools/call'||c.body?.method==='copyFileToDockerContainer'));
 }
 console.log('PASS target bindings: immutable capture; exact original ID/runtime/job refusal on actual controller read-only attach; modeled wire only');
})().catch(error=>{console.error(error);process.exitCode=1;});
