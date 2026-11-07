'use strict';
// In-memory native-wire fixture only. No socket/fetch outside this VM.
const fs=require('node:fs'),vm=require('node:vm'),crypto=require('node:crypto'),assert=require('node:assert/strict'),path=require('node:path');
const root=require('node:path').join(__dirname,'../../tools/native-recovery'),hash=x=>crypto.createHash('sha256').update(x).digest('hex');
const names=['native_file_channel.py','trusted_admin_journal.py','permanent_recovery.py','legacy015_recovery.py','managed_service.py','runtime.py'];
const sources=Object.fromEntries(names.map(n=>[n,hash(fs.readFileSync(path.join(root,'service',n)))]));
const ACK='Trusted administrator maintenance: prior installs and rollbacks settled; no concurrent install, rollback, start, rename or file modification; ordinary container confinement; no escaped writer';
const P='uvm.public.dappnode.eth',NAME='DAppNodePackage-ship.'+P,old='a'.repeat(64),current='b'.repeat(64);
let generation='c'.repeat(64),state='running',durable,loseAck=false,serial=0;
const events=[],files=new Map();
files.set('/urbit/control/runtime.json',Buffer.from('{"state":"STOPPED"}\n'));
files.set('/urbit/control/job.json',Buffer.from('{"fixture":"not actual committed job"}'));
for(const n of names)files.set('/opt/importer/'+n,fs.readFileSync(path.join(root,'service',n)));
const c=()=>({containerId:current,containerName:NAME,serviceName:'ship',state,image:'ship.'+P+':fixture',volumes:[{name:'uvmpublicdappnodeeth_ship_data',host:'/var/lib/docker/volumes/uvmpublicdappnodeeth_ship_data/_data',container:'/urbit'}]});
function commit(command,raw) {
  durable={state:command.operation==='start'?'WRITER_ADMITTED':'REPAIRED',generation,
    native_old_container_id:old,native_container_id:current,native_sequence:command.sequence,
    native_command_raw:raw,native_pending:command,native_command_sha256:hash(raw),native_outcome:'COMPLETE'};
  files.set('/urbit/control/legacy-recovery-state.json',Buffer.from(JSON.stringify(durable)));
}
const initialProof='{"fixture":"previous retained native receipt, not native truth"}';
files.set('/opt/importer/native-receipt-'+ '1'.repeat(32)+'.json',Buffer.from(initialProof));
const prior={policy:'TRUSTED_NATIVE_ADMIN_MAINTENANCE_V1',generation,sequence:1,transaction:'1'.repeat(32),operation:'repair',old_container_id:old,container_id:current,sources,native_receipt_sha256:hash(initialProof)};
commit(prior,JSON.stringify(prior));
function status() {return {policy:'TRUSTED_NATIVE_ADMIN_MAINTENANCE_V1',feature_retained:true,sources,generation,error:null,
  state:durable.state,sequence:durable.native_sequence,durable_generation:durable.generation,command_sha256:durable.native_command_sha256,
  state_sha256:hash(files.get('/urbit/control/legacy-recovery-state.json')),outcome:durable.native_outcome,
  runtime_sha256:hash(files.get('/urbit/control/runtime.json')),job_sha256:hash(files.get('/urbit/control/job.json'))};}
function response(raw,type='application/json') {const bytes=Buffer.isBuffer(raw)?raw:Buffer.from(raw);let done=false;
  return {ok:true,headers:{get:()=>type},body:{getReader:()=>({async read(){if(done)return {done:true};done=true;return {done:false,value:new Uint8Array(bytes)};},async cancel(){}})}};}
async function fixtureFetch(url,opts) {
  events.push({url,body:opts.body&&JSON.parse(opts.body)});
  if(url.startsWith('/file-download/')) {const p=new URL('http://my.dappnode'+url).searchParams.get('path');
    if(p==='/urbit/control/native-file-status.json')return response(JSON.stringify(status()));
    assert.ok(files.has(p),'unknown fixture file '+p);return response(files.get(p));}
  const q=JSON.parse(opts.body);
  if(url==='/mcp') {
    if(q.method==='tools/list')return response(JSON.stringify({id:q.id,result:{tools:['dappnode_stop_package','dappnode_start_package'].map(name=>({name}))}}));
    const tool=q.params.name;assert.ok(['dappnode_stop_package','dappnode_start_package'].includes(tool));
    if(tool==='dappnode_stop_package')state='exited';else {state='running';generation=(++serial).toString(16).padStart(64,'0');}
    return response(JSON.stringify({id:q.id,result:{content:[{type:'text',text:JSON.stringify({dnpName:P,results:[{container:NAME,ok:true}]})}]}}));
  }
  assert.equal(url,'/rpc');const p=q.params[0];let result;
  switch(q.method) {
    case 'packageGet':result={dnpName:P,containers:[c()]};break;
    case 'packagesGet':result=[{dnpName:P,containers:[c()]}];break;
    case 'autoUpdateDataGet':result={dnpsToShow:[{id:P,enabled:false},{id:'system-packages',enabled:false}]};break;
    case 'copyFileToDockerContainer': {
      const raw=Buffer.from(p.dataUri.split(',')[1],'base64');files.set(p.toPath,raw);
      if(p.toPath==='/opt/importer/native-command.json') {
        const command=JSON.parse(raw);assert.equal(command.old_container_id,old);assert.equal(command.container_id,current);
        const receiptPath='/opt/importer/native-receipt-'+command.transaction+'.json';assert.ok(files.has(receiptPath),'receipt must precede root command');
        assert.equal(hash(files.get(receiptPath)),command.native_receipt_sha256);
        if(command.operation==='reconcile') {
          const proof=JSON.parse(files.get(receiptPath));
          assert.equal(proof.resume.stopped_container_id,current);assert.equal(proof.resume.boot_generation,generation);
          assert.notEqual(proof.resume.before_stop_generation,generation);
          assert.equal(command.prior_state_sha256,status().state_sha256);
          const stop=proof.events.findIndex(x=>x.method==='dappnode_stop_package');
          const exited=proof.events.findIndex((x,i)=>i>stop&&x.method==='packageGet/packagesGet'&&x.result.state==='exited');assert.ok(stop>=0&&exited>stop);
        }
        commit(command,raw.toString());
        if(loseAck){loseAck=false;throw Error('fixture lost acknowledgement AFTER recorded completion');}
      }
      return response('{}');
    }
    default:throw Error('Unexpected native method '+q.method);
  }
  return response(JSON.stringify({result}));
}
const context=vm.createContext({Uint8Array,Uint32Array,DataView,TextEncoder,TextDecoder,URL,AbortController,setTimeout,clearTimeout,performance,
  location:{hostname:'my.dappnode',protocol:'http:'},crypto:crypto.webcrypto,fetch:fixtureFetch,
  btoa:x=>Buffer.from(x,'binary').toString('base64'),unescape,encodeURIComponent});
vm.runInContext(fs.readFileSync(path.join(root,'native-controller.js'),'utf8'),context);
(async()=>{
  assert.equal(context.parseNativeFileRpc('copyFileToDockerContainer','{}'),undefined);
  assert.throws(()=>context.parseNativeFileRpc('packageGet','{}'));
  let controller=context.createNativeFileRecovery(sources,ACK,{originalContainerId:old,runtimeSha256:'d'.repeat(64),jobSha256:'e'.repeat(64)});assert.equal(events.length,0);
  const attached=await controller.attach();assert.equal(attached.phase,'ATTACHED');
  assert.equal(events.filter(e=>e.body?.method==='tools/call'||e.body?.method==='copyFileToDockerContainer').length,0,'attach must not mutate');
  await assert.rejects(()=>controller.start('wrong'));assert.equal(controller.state().phase,'ATTACHED');
  const reconciled=await controller.reconcileAfterNativeStop();assert.equal(reconciled.phase,'REPAIRED');assert.equal(reconciled.newId,current);
  loseAck=true;await assert.rejects(()=>controller.start('Start the retained pier after native legacy015 repair'),/lost acknowledgement/);
  assert.equal(controller.state().phase,'UNCERTAIN');assert.equal(durable.state,'WRITER_ADMITTED');
  controller=context.createNativeFileRecovery(sources,ACK,{originalContainerId:old,runtimeSha256:'d'.repeat(64),jobSha256:'e'.repeat(64)});await controller.attach();
  const again=await controller.reconcileAfterNativeStop();assert.equal(again.phase,'REPAIRED');assert.equal(durable.native_sequence,4);
  assert.equal(events.filter(e=>e.body?.method==='packageInstallDev').length,0);
  console.log('PASS controller wire fixture: read-only attach, exact current-ID Stop/exited + same-ID fresh boot, receipt-before-command, lost-ack fresh attach/reconcile; NO native network/dispatcher qualification.');
})().catch(e=>{console.error(e);process.exitCode=1;});
