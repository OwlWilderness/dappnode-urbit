// Source-only model: fetch/MCP/native lifecycle are fixtures, not appliance proof.
const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict'),crypto=require('node:crypto');
const root=__dirname,base=require('node:path').join(root,'../../tools/native-recovery/native-controller.js');
const candidate=process.argv[2]||base;
const saved={receipt:{imageFileId:'c'.repeat(64),sha256:'d'.repeat(64),sizeBytes:4096,finishedAt:'2026-01-01T00:00:00.000Z',expiresInMs:1800000}};
const diagnosis={controllerEvidence:{imageFileId:'c'.repeat(63)}};
const P='uvm.public.dappnode.eth',NAME='DAppNodePackage-ship.'+P,V='uvmpublicdappnodeeth_ship_data';
const OLD='a'.repeat(64),NEW='b'.repeat(64);
const SHA='d'.repeat(64),SIZE=4096;
const ACK='Trusted administrator maintenance: prior installs and rollbacks settled; no concurrent install, rollback, start, rename or file modification; ordinary container confinement; no escaped writer';
const names=['native_file_channel.py','trusted_admin_journal.py','permanent_recovery.py','legacy015_recovery.py','managed_service.py','runtime.py'];
const fixedNow=Date.parse(saved.receipt.finishedAt)+1000;
function setup(opts={}) {
 const calls=[],writes=[];let stopped=false,installed=false;
 const pkg=()=>({dnpName:P,containers:[{containerName:NAME,serviceName:'ship',containerId:installed?NEW:(opts.wrongId?'c'.repeat(64):OLD),state:installed?'exited':stopped?'exited':opts.state||'running',image:'ship.'+P+':'+(installed?'0.2.0':'0.1.5'),volumes:[{name:opts.wrongVolume?'foreign':V,host:'/var/lib/docker/volumes/'+V+'/_data',container:'/urbit'}]}]});
 const context={TextEncoder,TextDecoder,Uint8Array,DataView,AbortController,setTimeout,clearTimeout,performance,crypto:crypto.webcrypto,location:{hostname:'my.dappnode',protocol:'http:'},Date:class extends Date {static now(){return fixedNow;}},fetch:async(url,init)=>{
  const body=JSON.parse(init.body);let response;const method=body.method;
  if(url==='/mcp') {
   const tool=body.params?.name;calls.push(tool||method);
   if(method==='tools/list')response={tools:[{name:'dappnode_stop_package'},{name:'dappnode_start_package'}]};
   else {writes.push(tool);stopped=!opts.stopFailure;response={content:[{type:'text',text:JSON.stringify({dnpName:P,results:[{container:opts.wrongStopContainer?'wrong':NAME,ok:!opts.stopFailure}]})}]};}
   response={id:body.id,result:response};
  } else {
   calls.push(method);
   if(method==='packageGet')response={result:pkg()};
   else if(method==='packagesGet')response={result:[pkg()]};
   else if(method==='autoUpdateDataGet')response={result:{dnpsToShow:[{id:P,enabled:false},{id:'system-packages',enabled:false}]}};
   else if(method==='packageInstallDev') {writes.push(method);calls.push({submitted:body.params[0].imageFileId});if(opts.rpcFailure)response={error:{code:-32603,message:opts.rpcFailure==='missing'?'No uploaded file found for imageFileId '+body.params[0].imageFileId:'PRIVATE CONFIG VALUE',data:'PRIVATE STACK'}};else {installed=true;response={};}}
   else throw Error('Unexpected RPC '+method);
  }
  const bytes=new TextEncoder().encode(JSON.stringify(response));let read=false;
  return {ok:true,headers:{get:()=> 'application/json'},body:{getReader:()=>({read:async()=>read?{done:true}:(read=true,{done:false,value:bytes})})}};
 }};
 vm.createContext(context);vm.runInContext(fs.readFileSync(candidate,'utf8'),context);
 const target=opts.target||{originalContainerId:OLD,runtimeSha256:'e'.repeat(64),jobSha256:'f'.repeat(64)};
 const controller=context.createNativeFileRecovery(Object.fromEntries(names.map(n=>[n,'a'.repeat(64)])),ACK,target);
 const args={manifest:{name:P,version:'0.2.0'},compose:'reviewed fixture',imageFileId:saved.receipt.imageFileId,stagedReceipt:structuredClone(saved.receipt),artifactSha256:SHA,expectedArtifactSizeBytes:SIZE};
 return {controller,args,calls,writes,context};
}
async function attempt(x){try{return {value:await x.controller.stopAndInstall(x.args)};}catch(e){return {error:e};}}
let failures=0,total=0;
async function test(name,fn){total++;try{await fn();console.log('PASS '+name);}catch(e){failures++;console.log('FAIL '+name+': '+e.message);}}
(async()=>{
 await test('public target bindings required, strict, and captured immutably',async()=>{
  for(const target of [{},{originalContainerId:'a'.repeat(63),runtimeSha256:'e'.repeat(64),jobSha256:'f'.repeat(64)}, {originalContainerId:OLD,runtimeSha256:'E'.repeat(64),jobSha256:'f'.repeat(64)}, {originalContainerId:OLD,runtimeSha256:'e'.repeat(64),jobSha256:'f'.repeat(64),extra:true}])assert.throws(()=>setup({target}),/Exact retained/);
  const target={originalContainerId:OLD,runtimeSha256:'e'.repeat(64),jobSha256:'f'.repeat(64)};
  const x=setup({target});target.originalContainerId='f'.repeat(64);const r=await attempt(x);assert.equal(r.error,undefined,r.error?.message);
 });
 await test('receipt preparation requires independent artifact authorization',async()=>{
  const x=setup();vm.runInContext(fs.readFileSync(require('node:path').join(root,'../../tools/native-recovery/receipt-invocation.js'),'utf8'),x.context);
  for(const args of [{},{artifactSha256:'f'.repeat(63),expectedArtifactSizeBytes:4096},{artifactSha256:SHA,expectedArtifactSizeBytes:0}])await assert.rejects(x.context.prepareNativeReceiptInstall(args),/Independent reviewed/);
  assert.equal(x.writes.length,0);
 });
 await test('synthetic shortened ID never reaches native writes',async()=>{const x=setup();x.args.imageFileId=diagnosis.controllerEvidence.imageFileId;x.args.stagedReceipt.imageFileId=x.args.imageFileId;const r=await attempt(x);assert.equal(x.writes.length,0,'native writes reached: '+JSON.stringify(x.writes)+'; submitted length '+x.calls.find(c=>c.submitted)?.submitted.length);assert(r.error);});
 await test('receipt admission controls before any write',async()=>{for(const mutate of [a=>delete a.stagedReceipt,a=>a.stagedReceipt.sha256='f'.repeat(64),a=>a.stagedReceipt.sizeBytes++,a=>a.stagedReceipt.expiresInMs=0,a=>a.stagedReceipt.finishedAt='invalid',a=>a.stagedReceipt.finishedAt=new Date(fixedNow-1800001).toISOString(),a=>a.imageFileId=diagnosis.controllerEvidence.imageFileId,a=>a.stagedReceipt.imageFileId=a.stagedReceipt.imageFileId.toUpperCase()]){const x=setup();mutate(x.args);const r=await attempt(x);assert(r.error);assert.equal(x.writes.length,0);}});
 await test('exact already-exited original requires fresh Stop observation then install',async()=>{const x=setup({state:'exited'}),r=await attempt(x);assert.equal(r.error,undefined,r.error?.message);assert.equal(r.value.phase,'INSTALLED_STOPPED');assert.deepEqual(x.writes,['dappnode_stop_package','packageInstallDev']);const stop=x.calls.indexOf('dappnode_stop_package'),install=x.calls.indexOf('packageInstallDev');assert(x.calls.slice(stop+1,install).includes('packageGet'));assert(x.calls.slice(stop+1,install).includes('packagesGet'));assert(x.calls.slice(stop+1,install).includes('autoUpdateDataGet'));assert.equal(x.calls.find(c=>c.submitted).submitted,saved.receipt.imageFileId);await assert.rejects(()=>x.controller.stopAndInstall(x.args),/Consumed/);});
 await test('wrong identity volume state or Stop proof cannot install',async()=>{for(const opts of [{wrongId:true},{wrongVolume:true},{state:'created'},{state:'paused'},{state:'exited',stopFailure:true},{state:'exited',wrongStopContainer:true}]){const x=setup(opts);await attempt(x);assert(!x.writes.includes('packageInstallDev'));assert.equal(x.controller.state().phase,'UNCERTAIN');}});
 await test('running original still installs with native void success',async()=>{const x=setup();{vm.runInContext(fs.readFileSync(require('node:path').join(root,'../../tools/native-recovery/receipt-invocation.js'),'utf8'),x.context);const textFile=text=>({text:async()=>text});x.args=await x.context.prepareNativeReceiptInstall({manifestFile:textFile(JSON.stringify({name:P,version:'0.2.0'})),composeFile:textFile('reviewed fixture'),stagedReceiptFile:textFile(JSON.stringify(saved)),artifactSha256:SHA,expectedArtifactSizeBytes:SIZE});assert.equal(x.args.stagedReceipt.imageFileId,saved.receipt.imageFileId);assert.equal(x.args.expectedArtifactSizeBytes,SIZE);assert.equal(x.args.artifactSha256,SHA);assert.equal(Object.hasOwn(x.args,'imageFileId'),false);}const r=await attempt(x);assert.equal(r.error,undefined,r.error?.message);assert.equal(r.value.phase,'INSTALLED_STOPPED');assert.equal(x.context.parseNativeFileRpc('copyFileToDockerContainer','{}'),undefined);});
 await test('install RPC failure retains only bounded safe causality and fences retry',async()=>{for(const rpcFailure of ['missing','other']){const x=setup({rpcFailure}),r=await attempt(x);assert(r.error);const evidence=JSON.parse(x.controller.evidence()),event=evidence.events.find(e=>e.method==='packageInstallDev-failure');assert(event,'missing safe failure event');assert.equal(event.result.method,'packageInstallDev');assert.equal(event.result.classification,rpcFailure==='missing'?'UPLOADED_FILE_NOT_FOUND':'RPC_ERROR');assert.match(event.result.bodySha256,/^[a-f0-9]{64}$/);assert(event.result.bodyLengthBytes>0);assert(!JSON.stringify(evidence).includes('PRIVATE'));assert(!String(r.error).includes('PRIVATE'));assert.equal(x.controller.state().phase,'UNCERTAIN');}});
 console.log(JSON.stringify({total,passed:total-failures,failed:failures,scope:'source-only mocked native boundary; no network/engine/appliance'}));process.exitCode=failures?1:0;
})();
