/* Execute ONLY in the authorized my.dappnode browser origin. No credentials,
 * worker/Admin-origin requests, arbitrary exec, injected container code, or engine.
 * Native stop/start are real /mcp tools, not packageStartStop's retry-unsafe toggle.
 * Nothing runs on load. Each mutation is a separately explicit method invocation.
 */
// SHA-256 over downloaded bytes. Native my.dappnode may be HTTP: do not depend
// on secure-context-only crypto.subtle or randomUUID. Compared with Node's
// actual SHA-256 over this source closure by the focused local check.
function nativeFileSha256(input) {
  const bytes=input instanceof Uint8Array?input:new Uint8Array(input);
  const K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  const h=[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  const size=Math.ceil((bytes.length+9)/64)*64, padded=new Uint8Array(size);padded.set(bytes);padded[bytes.length]=128;
  const view=new DataView(padded.buffer);view.setUint32(size-8,Math.floor(bytes.length/0x20000000));view.setUint32(size-4,bytes.length*8);
  const R=(x,n)=>(x>>>n)|(x<<(32-n)), w=new Uint32Array(64);
  for(let off=0;off<size;off+=64){
    for(let i=0;i<16;i++)w[i]=view.getUint32(off+4*i);
    for(let i=16;i<64;i++){const x=w[i-15],y=w[i-2];w[i]=(w[i-16]+(R(x,7)^R(x,18)^(x>>>3))+w[i-7]+(R(y,17)^R(y,19)^(y>>>10)))>>>0;}
    let [a,b,c,d,e,f,g,z]=h;
    for(let i=0;i<64;i++){const t=(z+(R(e,6)^R(e,11)^R(e,25))+((e&f)^(~e&g))+K[i]+w[i])>>>0;
      const u=((R(a,2)^R(a,13)^R(a,22))+((a&b)^(a&c)^(b&c)))>>>0;
      z=g;g=f;f=e;e=(d+t)>>>0;d=c;c=b;b=a;a=(t+u)>>>0;}
    [a,b,c,d,e,f,g,z].forEach((x,i)=>h[i]=(h[i]+x)>>>0);
  }
  return h.map(x=>x.toString(16).padStart(8,'0')).join('');
}
function parseNativeFileRpc(method,text,imageFileId) {
  let x;
  try {x=JSON.parse(text);} catch {
    if(method!=='packageInstallDev')throw Error('Native RPC error');
  }
  if(!x||Array.isArray(x)||typeof x!=='object'||x.error) {
    const error=Error('Native RPC error');
    if(method==='packageInstallDev') {
      const bytes=new TextEncoder().encode(text);
      // Actual getRpcHandler envelope: {error:{code,message,data:stack}}.
      // Never retain message, stack, raw body or arbitrary server fields.
      error.nativeRpcFailure={method,classification:
        /^[a-f0-9]{64}$/.test(imageFileId)&&x?.error?.code===-32603&&
        x.error.message==='No uploaded file found for imageFileId '+imageFileId
          ?'UPLOADED_FILE_NOT_FOUND':'RPC_ERROR',
        bodySha256:nativeFileSha256(bytes),bodyLengthBytes:bytes.length};
    }
    throw error;
  }
  // Actual handler returns {result: await handler(...)}, serialized by Express.
  // These two Promise<void> calls therefore return {}, NOT {result:null}.
  if((method==='packageInstallDev'||method==='copyFileToDockerContainer')&&Object.keys(x).length===0)return undefined;
  if(!Object.prototype.hasOwnProperty.call(x,'result')||Object.keys(x).some(k=>k!=='result'))throw Error('Native RPC result absent');
  return x.result;
}
function createNativeFileRecovery(expectedSources, acceptance, target) {
  'use strict';
  // Capture independently retained original bindings, never infer them from current state.
  if (!target || Object.keys(target).sort().join('|') !== 'jobSha256|originalContainerId|runtimeSha256' ||
      Object.values(target).some(x => typeof x !== 'string' || !/^[a-f0-9]{64}$/.test(x)))
    throw Error('Exact retained original container and journal hashes required');
  target = Object.freeze({...target});
  const POLICY='TRUSTED_NATIVE_ADMIN_MAINTENANCE_V1';
  const ACK='Trusted administrator maintenance: prior installs and rollbacks settled; no concurrent install, rollback, start, rename or file modification; ordinary container confinement; no escaped writer';
  if (location.hostname!=='my.dappnode' || !['http:','https:'].includes(location.protocol)) throw Error('Native origin only');
  if (acceptance!==ACK) throw Error('Explicit changed trust model acceptance required');
  const P='uvm.public.dappnode.eth', NAME='DAppNodePackage-ship.uvm.public.dappnode.eth';
  const V='uvmpublicdappnodeeth_ship_data', HOST='/var/lib/docker/volumes/'+V+'/_data';
  const ORIGINAL=target.originalContainerId;
  const START='Start the retained pier after native legacy015 repair';
  const enc=new TextEncoder(), receipt={policy:POLICY,acceptance,events:[]};
  let phase='NEW', oldId, newId, generation, manifestVersion, last, lastCommandHash, n=0;
  const names=['native_file_channel.py','trusted_admin_journal.py','permanent_recovery.py','legacy015_recovery.py','managed_service.py','runtime.py'];
  const keys=x=>Object.keys(x).sort().join('|');
  const canonical=x=>JSON.stringify(x&&typeof x==='object'?Object.fromEntries(Object.keys(x).sort().map(k=>[k,JSON.parse(canonical(x[k]))])):x);
  if (keys(expectedSources)!==keys(Object.fromEntries(names.map(x=>[x,0]))) ||
      names.some(x=>!/^\w{64}$/.test(expectedSources[x]) || !/^[a-f0-9]+$/.test(expectedSources[x]))) throw Error('Exact published source index required');
  const hex=async bytes=>nativeFileSha256(bytes);
  const transaction=()=>Array.from(crypto.getRandomValues(new Uint8Array(16)),b=>b.toString(16).padStart(2,'0')).join('');
  const same=(a,b)=>keys(a)===keys(b)&&Object.keys(a).every(k=>a[k]===b[k]);
  const record=(method,result)=>{receipt.events.push({method,at:new Date().toISOString(),result});return result;};
  async function request(url,body,limit=1048576,timeout=15000) {
    if (!url.startsWith('/') || url.startsWith('//')) throw Error('Fixed same-origin route required');
    const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),timeout);
    try {
      const r=await fetch(url,{method:body===undefined?'GET':'POST',credentials:'same-origin',redirect:'error',
        headers:body===undefined?{}:{'Content-Type':'application/json','Accept':'application/json, text/event-stream'},
        ...(body===undefined?{}:{body:JSON.stringify(body)}),signal:controller.signal});
      if (!r.ok) throw Error('Native route failed');
      const chunks=[],reader=r.body.getReader();let size=0;
      for (;;) {const {done,value}=await reader.read();if(done)break;size+=value.length;
        if(size>limit){await reader.cancel();throw Error('Native response bound');}chunks.push(value);}
      const raw=new Uint8Array(size);let off=0;for(const x of chunks){raw.set(x,off);off+=x.length;}
      return {raw,text:new TextDecoder().decode(raw),type:r.headers.get('content-type')||''};
    } finally {clearTimeout(timer);}
  }
  async function rpc(method,params,timeout=15000) {
    let r;
    try {
      r=await request('/rpc',{method,params:params===undefined?[]:[params]},1048576,timeout);
      return parseNativeFileRpc(method,r.text,params?.imageFileId);
    } catch(error) {
      if(method==='packageInstallDev')record('packageInstallDev-failure',error.nativeRpcFailure||{
        method,classification:r?'RPC_RESPONSE_INVALID':'TRANSPORT_OR_HTTP_ERROR',
        ...(r?{bodySha256:nativeFileSha256(r.raw),bodyLengthBytes:r.raw.length}:{})});
      throw error;
    }
  }
  async function mcp(method,params) {
    const id=++n,r=await request('/mcp',{jsonrpc:'2.0',id,method,params},1048576,120000);
    let response;
    if(r.type.includes('text/event-stream')) {
      const frames=r.text.split(/\r?\n\r?\n/).flatMap(frame=>{
        const lines=frame.split(/\r?\n/).filter(x=>x.startsWith('data:')).map(x=>x.slice(5).trimStart());
        if(!lines.length)return [];try{return [JSON.parse(lines.join('\n'))];}catch{return [];}
      });
      const found=frames.filter(x=>x.id===id);if(found.length!==1)throw Error('MCP receipt missing/ambiguous');response=found[0];
    } else response=JSON.parse(r.text);
    if(response.id!==id||response.error||response.result?.isError)throw Error('MCP refused/uncertain');
    return response.result;
  }
  async function lifecycle(tool) {
    const x=await mcp('tools/call',{name:tool,arguments:{dnpName:P}});
    if(x.content?.length!==1||x.content[0].type!=='text')throw Error('Unexpected native receipt');
    const result=JSON.parse(x.content[0].text);
    if(result.dnpName!==P||result.results?.length!==1||result.results[0].container!==NAME||result.results[0].ok!==true||result.results[0].error)throw Error('Positive exact-service native completion absent');
    record(tool,result);return result;
  }
  function one(pkg) {
    if(pkg.dnpName!==P||pkg.containers?.length!==1)throw Error('Sole original package required');
    const c=pkg.containers[0];
    if(c.containerName!==NAME||c.serviceName!=='ship'||! /^[a-f0-9]{64}$/.test(c.containerId))throw Error('Container identity mismatch');
    if(c.volumes?.length!==1||c.volumes[0].name!==V||c.volumes[0].host!==HOST||c.volumes[0].container!=='/urbit')throw Error('Unchanged exact retained volume required');
    return c;
  }
  function safe(c){return {containerId:c.containerId,containerName:c.containerName,serviceName:c.serviceName,
    state:c.state,image:c.image,exitCode:c.exitCode,volumes:c.volumes};}
  async function updates() {
    const data=await rpc('autoUpdateDataGet');
    for(const id of [P,'system-packages']) {
      const rows=data.dnpsToShow.filter(x=>x.id===id);
      if(rows.length!==1||rows[0].enabled!==false)throw Error('Effective native updates must be OFF');
    }
    record('autoUpdateDataGet',{target:false,system:false});
  }
  async function observe(id,states) {
    const c=one(await rpc('packageGet',{dnpName:P}));
    if(c.containerId!==id||!states.includes(c.state))throw Error('Exact native identity/state not settled');
    const all=await rpc('packagesGet');
    const containers=all.flatMap(p=>p.containers||[]);
    const consumers=containers.filter(x=>(x.volumes||[]).some(v=>v.name===V||v.host===HOST));
    if(consumers.length!==1||consumers[0].containerId!==id)throw Error('Native package volume consumer ambiguity');
    if(newId&&containers.some(x=>x.containerId===oldId))throw Error('Predecessor remains in native package listing');
    record('packageGet/packagesGet',safe(c));await updates();return c;
  }
  async function file(path) {return request('/file-download/'+encodeURIComponent(NAME)+'?path='+encodeURIComponent(path),undefined,131072);}
  async function status(allowRefused=false) {
    const x=JSON.parse((await file('/urbit/control/native-file-status.json')).text);
    if(x.policy!==POLICY||x.feature_retained!==true||!same(x.sources,expectedSources)||! /^[a-f0-9]{64}$/.test(x.generation)||
       (x.error!==null&&!(allowRefused&&x.error==='REFUSED_OR_UNCERTAIN')))throw Error('Native worker status/source mismatch');
    return x;
  }
  async function settleWorker(state,sequence) {
    const deadline=performance.now()+15000;
    while(performance.now()<deadline) {
      const x=await status(true);
      if(x.generation!==generation)throw Error('Worker process generation changed');
      if(x.state===state&&x.sequence===sequence&&x.outcome==='COMPLETE'&&x.command_sha256===lastCommandHash){record('native-worker-status',x);return x;}
      if(x.sequence===sequence&&x.outcome==='INTERRUPTED')throw Error('Worker mutation uncertain');
      await new Promise(r=>setTimeout(r,500));
    }
    throw Error('Worker completion not positively read back; do not retry');
  }
  async function installedSources() {
    for(const name of names)if(await hex((await file('/opt/importer/'+name)).raw)!==expectedSources[name])throw Error('Actual installed source readback mismatch');
  }
  async function discover() {
    const list=await mcp('tools/list',{});
    for(const name of ['dappnode_stop_package','dappnode_start_package'])if(!list.tools?.some(x=>x.name===name))throw Error('Native MCP mutation tool unavailable');
  }
  async function retained(s) {
    if(s.state==='MAINTENANCE'&&s.sequence===0&&s.state_sha256===null) {
      if(s.runtime_sha256!==target.runtimeSha256||
         s.job_sha256!==target.jobSha256)throw Error('Unmutated original journals required');
      record('unmutated-original',{generation:s.generation,runtime_sha256:s.runtime_sha256,job_sha256:s.job_sha256});return null;
    }
    const raw=(await file('/urbit/control/legacy-recovery-state.json')).raw;
    if(await hex(raw)!==s.state_sha256)throw Error('Durable state readback changed');
    const r=JSON.parse(new TextDecoder().decode(raw));
    if(r.native_old_container_id!==ORIGINAL||r.native_container_id!==newId||r.native_sequence!==s.sequence||
       r.generation!==s.durable_generation||r.native_command_sha256!==s.command_sha256||
       !['COMPLETE','PENDING','INTERRUPTED'].includes(r.native_outcome)||
       !['REPAIRED','WRITER_ADMITTED','UNCERTAIN'].includes(r.state))throw Error('Unknown durable outcome; fenced');
    if(typeof r.native_command_raw!=='string'||await hex(enc.encode(r.native_command_raw))!==r.native_command_sha256)throw Error('Prior command bytes changed');
    const prior=JSON.parse(r.native_command_raw);
    if(canonical(prior)!==canonical(r.native_pending)||prior.sequence!==s.sequence||prior.policy!==POLICY||prior.generation!==r.generation||
       !/^[a-f0-9]{32}$/.test(prior.transaction)||prior.old_container_id!==ORIGINAL||prior.container_id!==newId||
       !same(prior.sources,expectedSources))throw Error('Prior command/source binding mismatch');
    const proof=(await file('/opt/importer/native-receipt-'+prior.transaction+'.json')).raw;
    if(await hex(proof)!==prior.native_receipt_sha256)throw Error('Prior real native receipt unavailable');
    record('prior-durable-outcome',{sha256:s.state_sha256,command_sha256:s.command_sha256,sequence:s.sequence,
      state:r.state,outcome:r.native_outcome,generation:r.generation,receipt_sha256:prior.native_receipt_sha256});
    return r;
  }
  async function send(operation,confirmation) {
    const c=await observe(newId,['running']);
    if(c.image!=='ship.'+P+':'+manifestVersion)throw Error('Installed version tag mismatch (not an immutable image proof)');
    const s=await status(operation==='reconcile');if(s.generation!==generation)throw Error('Stale generation');
    if(operation==='reconcile') {
      await retained(s);
      receipt.resume.prior_state_sha256=s.state_sha256;
      receipt.resume.prior_command_sha256=s.command_sha256;
    }
    const rawRuntime=(await file('/urbit/control/runtime.json')).raw,rawJob=(await file('/urbit/control/job.json')).raw;
    if(await hex(rawRuntime)!==s.runtime_sha256||await hex(rawJob)!==s.job_sha256)throw Error('Journal readback not stable');
    const receiptRaw=JSON.stringify(receipt);
    const command={policy:POLICY,generation,sequence:s.sequence+1,transaction:transaction(),operation,
      expires:Math.floor(Date.now()/1000)+120,old_container_id:oldId,container_id:newId,sources:expectedSources,
      native_receipt_sha256:await hex(enc.encode(receiptRaw)),runtime_sha256:s.runtime_sha256,job_sha256:s.job_sha256,
      confirmation:confirmation??null,prior_state_sha256:operation==='reconcile'?s.state_sha256:null};
    const raw=JSON.stringify(command),bytes=enc.encode(raw);
    if(enc.encode(receiptRaw).length>65536||bytes.length>65536)throw Error('Protected-file size bound');
    lastCommandHash=await hex(bytes);
    // This uses the native File Manager's normal authenticated root copy route.
    // Unique basename avoids the native transfer-dir filename collision. The exact
    // destination is new code-dir control, NEVER /urbit/control/job/runtime.json.
    const filename='native-command-'+command.transaction+'.json';
    // Retain real native observations BEFORE issuing authority, through the same
    // normal native copy route. Worker verifies strict root metadata and this hash.
    const receiptName='native-receipt-'+command.transaction+'.json';
    await rpc('copyFileToDockerContainer',{containerName:NAME,filename:receiptName,
      toPath:'/opt/importer/'+receiptName,dataUri:'data:application/json;base64,'+btoa(unescape(encodeURIComponent(receiptRaw)))});
    if((await file('/opt/importer/'+receiptName)).text!==receiptRaw)throw Error('Native receipt retention/readback failed');
    record('native-command-issued',{command,sha256:await hex(bytes)});
    await rpc('copyFileToDockerContainer',{containerName:NAME,filename,toPath:'/opt/importer/native-command.json',
      dataUri:'data:application/json;base64,'+btoa(raw)});
    if((await file('/opt/importer/native-command.json')).text!==raw)throw Error('Native command exact readback failed');
    return command;
  }
  async function exclusive(expected,action) {
    if(phase!==expected)throw Error('Consumed/wrong native phase; no retry');
    phase='UNCERTAIN'; // Lost response or exception permanently fences this controller.
    return action();
  }
  return Object.freeze({
    async attach() {
      // Read-only attachment. Never infer that an uncertain Start may be retried.
      return exclusive('NEW',async()=>{
        await discover();
        const c=one(await rpc('packageGet',{dnpName:P}));
        if(c.containerId===ORIGINAL||!['running','exited','created'].includes(c.state)||
           !c.image.startsWith('ship.'+P+':'))throw Error('Installed recovery service required');
        oldId=ORIGINAL;newId=c.containerId;manifestVersion=c.image.slice(('ship.'+P+':').length);
        await observe(newId,['running','exited','created']);await installedSources();
        const s=await status(true);await retained(s);
        generation=s.generation;last=s;phase='ATTACHED';
        return {phase,oldId,newId,generation,state:s.state,sequence:s.sequence,outcome:s.outcome};
      });
    },
    async reconcileAfterNativeStop() {
      return exclusive('ATTACHED',async()=>{
        await discover();await observe(newId,['running','exited','created']);
        const before=await status(true);await retained(before);
        await lifecycle('dappnode_stop_package');
        await observe(newId,['exited']); // exact CURRENT full ID, not original ID
        await lifecycle('dappnode_start_package'); // idle service boot, not ship Start
        await observe(newId,['running']);await installedSources();
        const deadline=performance.now()+15000;let boot;
        do {
          boot=await status(true);
          if(boot.generation!==before.generation)break;
          await new Promise(r=>setTimeout(r,500));
        } while(performance.now()<deadline);
        if(boot.generation===before.generation)throw Error('Fresh boot generation not observed');
        generation=boot.generation;const prior=await retained(boot);
        if(prior===null) {last=boot;phase='IDLE';return {phase,oldId,newId,generation,sequence:0};}
        receipt.resume={stopped_container_id:newId,before_stop_generation:before.generation,boot_generation:generation};
        const command=await send('reconcile');
        last=await settleWorker('REPAIRED',command.sequence);
        await observe(newId,['running']);phase='REPAIRED';
        return {phase,oldId,newId,generation,sequence:last.sequence};
      });
    },
    async stopAndInstall({manifest,compose,stagedReceipt,artifactSha256,expectedArtifactSizeBytes,...extra}) {
      return exclusive('NEW',async()=>{
        // The saved finish receipt is mandatory authority for the upload ID.
        // A redundant legacy ID is consistency-checked, never used as a fallback.
        if(!stagedReceipt||typeof stagedReceipt!=='object'||Array.isArray(stagedReceipt))throw Error('Structured staged receipt required');
        const {imageFileId,sha256,sizeBytes,finishedAt,expiresInMs}=stagedReceipt;
        const finished=typeof finishedAt==='string'?Date.parse(finishedAt):NaN;
        const expires=finished+expiresInMs;
        const fresh=()=>Number.isFinite(finished)&&typeof expiresInMs==='number'&&Number.isFinite(expiresInMs)&&expiresInMs>0&&
          Number.isFinite(expires)&&finished<=Date.now()&&Date.now()<expires;
        if(manifest?.name!==P||typeof compose!=='string'||typeof imageFileId!=='string'||! /^[a-f0-9]{64}$/.test(imageFileId)||
           !/^[a-f0-9]{64}$/.test(artifactSha256)||sha256!==artifactSha256||
           !Number.isSafeInteger(expectedArtifactSizeBytes)||expectedArtifactSizeBytes<=0||sizeBytes!==expectedArtifactSizeBytes||
           (Object.prototype.hasOwnProperty.call(extra,'imageFileId')&&extra.imageFileId!==imageFileId)||!fresh())
          throw Error('Exact reviewed unexpired staged artifact receipt required');
        receipt.artifactSha256=artifactSha256;receipt.manifest=manifest;receipt.compose=compose;receipt.imageFileId=imageFileId;
        receipt.stagedReceipt={imageFileId,sha256,sizeBytes,finishedAt,expiresInMs};
        manifestVersion=manifest.version;
        // Preflight discovery must succeed before native Stop; never enable MCP tools here.
        const list=await mcp('tools/list',{});
        for(const name of ['dappnode_stop_package','dappnode_start_package'])if(!list.tools?.some(x=>x.name===name))throw Error('Native MCP mutation tool unavailable; no Stop/install attempted');
        const c=one(await rpc('packageGet',{dnpName:P}));
        if(c.containerId!==ORIGINAL||!['running','exited'].includes(c.state)||c.image!=='ship.'+P+':0.1.5')throw Error('Saved exact original container not current');
        oldId=c.containerId;record('original',safe(c));await updates();
        await lifecycle('dappnode_stop_package');
        await observe(oldId,['exited']);
        // An awaited exact native install owns only THIS transaction. Disabled
        // updates + administrator noninterference cover other admissions; this
        // is NOT a universal installer drain or enforced hostile-host exclusion.
        if(!fresh())throw Error('Staged receipt expired during native Stop; no install');
        record('packageInstallDev-begin',{oldId});
        await rpc('packageInstallDev',{manifest,compose,imageFileId},600000);
        record('packageInstallDev-completed',{completed:true});
        const next=one(await rpc('packageGet',{dnpName:P}));
        if(next.containerId===oldId||!['created','exited'].includes(next.state))throw Error('Install did not retain stopped-service preference');
        newId=next.containerId;await observe(newId,['created','exited']);
        phase='INSTALLED_STOPPED';return {phase,oldId,newId};
      });
    },
    async bootIdle() {
      return exclusive('INSTALLED_STOPPED',async()=>{
        await observe(newId,['created','exited']);
        await lifecycle('dappnode_start_package'); // service boot ONLY, never ship Start
        await observe(newId,['running']);
        for(const name of names)if(await hex((await file('/opt/importer/'+name)).raw)!==expectedSources[name])throw Error('Actual installed source readback mismatch');
        const s=await status();
        if(s.state!=='MAINTENANCE'||s.sequence!==0)throw Error('Prior mutation/uncertain state requires separate reconciliation');
        generation=s.generation;
        // Actual exact native journal bytes must equal the retained original capture.
        if(s.runtime_sha256!==target.runtimeSha256||
           s.job_sha256!==target.jobSha256)throw Error('Original committed journals changed');
        last=s;record('idle-generation',s);phase='IDLE';return {phase,generation};
      });
    },
    async repair() {
      return exclusive('IDLE',async()=>{
        const command=await send('repair');
        last=await settleWorker('REPAIRED',command.sequence);
        await observe(newId,['running']);phase='REPAIRED';return {phase,generation,sequence:last.sequence};
      });
    },
    async start(confirmation) {
      return exclusive('REPAIRED',async()=>{
        if(confirmation!==START)throw Error('Owner-original explicit confirmation required; not automatic');
        const command=await send('start',confirmation);
        last=await settleWorker('WRITER_ADMITTED',command.sequence);phase='STARTED';return {phase,generation,sequence:last.sequence};
      });
    },
    async stopOwned() {
      return exclusive('STARTED',async()=>{
        const command=await send('stop');last=await settleWorker('REPAIRED',command.sequence);
        phase='REPAIRED';return {phase,generation,sequence:last.sequence};
      });
    },
    evidence(){return JSON.stringify({...receipt,phase,oldId,newId,generation},null,2);},
    state(){return {phase,oldId,newId,generation};}
  });
}
