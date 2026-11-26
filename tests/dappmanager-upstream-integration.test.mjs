import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import os from 'node:os';
import {pathToFileURL} from 'node:url';
import {stripTypeScriptTypes} from 'node:module';

const root = process.env.UVM_DAPPMANAGER_CHECKOUT;
assert.ok(root, 'set UVM_DAPPMANAGER_CHECKOUT to the pinned scratch checkout');
const source = path.join(root, 'packages/dockerApi/src/uvmLifecycle.mjs');
const api = await import(pathToFileURL(source));
const read = relative => fs.readFileSync(path.join(root, relative), 'utf8');

test('actual backupRestore refuses protected identities before extraction, shell or file access', async t => {
  const ordinary = {Name:'/ordinary',Config:{Labels:{}},Mounts:[]};
  const cases = [
    {name:'package', dnpName:api.UVM_PACKAGE},
    {name:'normalized package alias', dnpName:'UVMpublicDAPPNODEeth'},
    {name:'resolved package', resolvedName:api.UVM_PACKAGE},
    {name:'container name', containerName:'DAppNodePackage-ship.'+api.UVM_PACKAGE},
    {name:'inspected label', info:{...ordinary,Config:{Labels:{'dappnode.dnp.dnpName':api.UVM_PACKAGE}}}},
    {name:'inspected volume alias', info:{...ordinary,Mounts:[{Name:'uvmpublicdappnodeeth_ship_data'}]}},
    {name:'inspected bind alias', info:{...ordinary,Mounts:[{Source:'/data/uvm.public.dappnode.eth'}]}},
    {name:'unselected second service', second:true},
    {name:'inspect uncertainty', inspectError:true, error:/inspect unavailable/}
  ];
  for (const scenario of cases) await t.test(scenario.name, async () => {
    const effects=[];
    const containers=[{containerName:scenario.containerName || 'opaque-id',serviceName:'ship'}];
    if (scenario.second) containers.push({containerName:'protected-id',serviceName:'other'});
    const restore = actualFunction('packages/dappmanager/src/calls/backupRestore.ts','backupRestore',{
      path, params:{TEMP_TRANSFER_DIR:'/must-not-write'},
      assertUnmanaged:api.assertUnmanaged, assertUnmanagedContainer:api.assertUnmanagedContainer,
      dockerContainerInspect:async name => {
        if(scenario.inspectError) throw Error('inspect unavailable');
        return scenario.second && name==='protected-id'
          ? {...ordinary,Config:{Labels:{'dappnode.dnp.dnpName':api.UVM_PACKAGE}}}
          : (scenario.info || ordinary);
      },
      listPackage:async()=>({dnpName:scenario.resolvedName || 'ordinary.eth',containers}),
      validateBackupArray:()=>{}, logs:{error:()=>{}},
      db:{fileTransferPath:{get:()=>{effects.push('transfer lookup');return '/uploaded.tar.xz';}}},
      fs:{existsSync:()=>{effects.push('file read');return true;},lstatSync:()=>({isDirectory:()=>false})},
      shell:async command=>{effects.push(command);},
      packageRestart:async()=>{effects.push('restart');}
    });
    let error;
    try {
      await restore({dnpName:scenario.dnpName || 'ordinary.eth',fileId:'fixture',
        backup:[{name:'runtime',path:'/urbit/control/runtime.json',service:'ship'}]});
    } catch(caught) {error=caught;}
    assert.deepEqual(effects, [], 'protected backup restore reached a side-effect boundary');
    assert.match(String(error?.message),scenario.error || /HOST_LIFECYCLE_REQUIRED/);
  });
});

test('actual backupRestore retains ordinary package restore path', async () => {
  const effects=[];
  const restore=actualFunction('packages/dappmanager/src/calls/backupRestore.ts','backupRestore',{
    path, params:{TEMP_TRANSFER_DIR:'/fixture'},
    assertUnmanaged:api.assertUnmanaged, assertUnmanagedContainer:api.assertUnmanagedContainer,
    dockerContainerInspect:async()=>({Name:'/ordinary',Config:{Labels:{}},Mounts:[]}),
    listPackage:async()=>({dnpName:'ordinary.eth',containers:[{containerName:'ordinary-id',serviceName:'ship'}]}),
    validateBackupArray:()=>{}, logs:{error:()=>{}},
    db:{fileTransferPath:{get:()=>'/uploaded.tar.xz'}},
    fs:{existsSync:()=>true,lstatSync:()=>({isDirectory:()=>false})},
    shell:async command=>{effects.push(command);}, packageRestart:async()=>{effects.push('restart');}
  });
  await restore({dnpName:'ordinary.eth',fileId:'fixture',backup:[{name:'data',path:'/app/data',service:'ship'}]});
  assert.ok(effects.some(command=>command.startsWith('docker cp ')));
  assert.equal(effects.at(-1),'restart');
});

function actualFunction(relative, name, dependencies) {
  const js = stripTypeScriptTypes(read(relative)).replace(/^import[\s\S]*?;\s*$/gm, '').replace(/\bexport /g, '');
  return new Function(...Object.keys(dependencies), js + '; return ' + name)(...Object.values(dependencies));
}

test('low-disk daemon stops ordinary packages through guarded API but preserves protected ship', async () => {
  const effects=[];
  const cache=new Map();
  const notices=[];
  let available='4000000';
  const infos={
    'ordinary-id':{Name:'/ordinary',Config:{Labels:{}},Mounts:[]},
    'protected-id':{Name:'/opaque',Config:{Labels:{'dappnode.dnp.dnpName':api.UVM_PACKAGE}},Mounts:[]}
  };
  const guardedStop=actualFunction('packages/dockerApi/src/api/container.ts', 'dockerContainerStop', {
    assertUnmanagedContainer:api.assertUnmanagedContainer,
    docker:{getContainer:id=>({inspect:async()=>infos[id],stop:async()=>{effects.push('engine-stop:'+id);}})}
  });
  const monitor=actualFunction('packages/daemons/src/diskUsage/index.ts', 'monitorDiskUsage', {
    shell:async cmd=>{
      effects.push(cmd);
      if(cmd.startsWith('df ')) return available;
      if(cmd.startsWith('docker ps ')) return 'ordinary-id DAppNodePackage-ordinary.eth\nprotected-id DAppNodePackage-ship.uvm.public.dappnode.eth';
      if(cmd.startsWith('docker stop')) return 'DAppNodePackage-ordinary.eth\nDAppNodePackage-ship.uvm.public.dappnode.eth';
      throw Error('unexpected shell');
    },
    dockerContainerStop:async id=>{effects.push('guarded:'+id); await guardedStop(id);},
    db:{diskUsageThreshold:{get:id=>cache.get(id),set:(id,value)=>cache.set(id,value)}},
    logs:{warn:()=>{},error:()=>{}},
    notifications:{sendNotification:async notice=>{notices.push(notice);}},
    eventBus:{requestPackages:{emit:()=>{}}},
    params:{dappmanagerDnpName:'dappmanager.dnp.dappnode.eth'},
    prettyDnpName:name=>name, Category:{hardware:'hardware'}, Priority:{critical:'critical'},
    Status:{triggered:'triggered'}
  });
  await monitor();
  assert.ok(effects.some(x=>x.startsWith('docker ps ')), 'read-only selection was not reached');
  assert.deepEqual(effects.filter(x=>x.startsWith('guarded:')), ['guarded:ordinary-id','guarded:protected-id']);
  assert.deepEqual(effects.filter(x=>x.startsWith('engine-stop:')), ['engine-stop:ordinary-id']);
  assert.ok(!effects.some(x=>x.startsWith('docker stop')), 'raw stop bypassed guarded API');
  assert.equal(notices.length,1);
  assert.match(notices[0].body,/ordinary.eth/);
  assert.doesNotMatch(notices[0].body,/uvm.public.dappnode.eth/);
  available='7000000';
  effects.length=0;
  await monitor();
  assert.deepEqual(effects.filter(x=>x.startsWith('docker ps ') || x.startsWith('guarded:') || x.startsWith('docker stop')), []);
  available='500000';
  effects.length=0;
  notices.length=0;
  await monitor();
  assert.deepEqual(effects.filter(x=>x.startsWith('guarded:')),
    ['guarded:ordinary-id','guarded:protected-id','guarded:ordinary-id','guarded:protected-id']);
  assert.deepEqual(effects.filter(x=>x.startsWith('engine-stop:')),
    ['engine-stop:ordinary-id','engine-stop:ordinary-id']);
  assert.ok(!effects.some(x=>x.startsWith('docker stop')));
  assert.equal(notices.length,2);
  assert.ok(notices.every(x=>!x.body.includes('uvm.public.dappnode.eth')));
});

test('actual File Manager owner certificate upload reaches broker, never shell docker cp', async () => {
  const calls = [];
  const info = {Id:'a'.repeat(64), Name:'/DAppNodePackage-ship.uvm.public.dappnode.eth',
    Config:{Labels:{'dappnode.dnp.dnpName':api.UVM_PACKAGE}}, Mounts:[]};
  const upload = actualFunction('packages/dockerApi/src/api/copyFileTo.ts', 'copyFileToDockerContainer', {
    path, fs, params:{TEMP_TRANSFER_DIR:'/must-not-write'},
    docker:{getContainer:() => ({inspect:async()=>info})},
    assertUnmanagedContainer:api.assertUnmanagedContainer,
    uploadUvmCertificate:async (...args) => {
      assert.equal(typeof api.uploadUvmCertificate, 'function');
      return api.uploadUvmCertificate(...args, async request => {calls.push(request); return {ok:true,
        state:'CERTIFICATE_STORED', container:info.Id, filename:request.filename};});
    },
    shell:() => assert.fail('stock shell copy reached'),
    dataUriToBuffer:() => assert.fail('stock staging reached')
  });
  const content = Buffer.from('public certificate bytes checked by host').toString('base64');
  for (const filename of ['root-ca.pem','server.pem']) {
    await upload({containerName:info.Id, dataUri:'data:application/x-pem-file;base64,'+content,
      filename:'local-name.pem', toPath:'/urbit/control/owner-tls-public/'+filename});
  }
  assert.deepEqual(calls.map(x=>x.filename), ['root-ca.pem','server.pem']);
  assert.ok(calls.every(x => x.operation==='certificate' && x.container===info.Id && x.content===content));
});

test('actual normal/core dependency installer refuses manager self-update before writes/downloads', async () => {
  let resolved = 0;
  const effects = new Proxy({}, {get(){return () => assert.fail('update side effect reached');}});
  const install = actualFunction('packages/installer/src/calls/packageInstall.ts', 'packageInstall', {
    params:{ALWAYS_DAPPGETBASIC:false}, getLogUi:()=>()=>{}, logUiClear:()=>{},
    logs:{info:()=>{},debug:()=>{}}, assertManagerUpdateAllowed:api.assertManagerUpdateAllowed,
    getInstallerPackagesData:effects.any, checkInstallRequirements:async()=>{},
  });
  const manager = {dnpName:'dappmanager.dnp.dappnode.eth', signedSafe:true, isCore:true, warnings:{}};
  await assert.rejects(install({getReleasesResolved:async()=>{
    resolved++; return {releases:[manager],state:{},currentVersions:{}};
  }}, {name:'core.dnp.dappnode.eth'}), /MANAGER_SELF_UPDATE_FROZEN/);
  assert.equal(resolved,1);
});

test('certificate path routing rejects broad writes, inspector failures and broker uncertainty', async () => {
  const info = {Id:'a'.repeat(64), Name:'/protected', Config:{Labels:{'dappnode.dnp.dnpName':api.UVM_PACKAGE}}};
  const container = {inspect:async()=>info};
  let requests=0;
  const request=async()=>{requests++; throw Error('lost acknowledgement');};
  const dataUri='data:;base64,'+Buffer.from('public PEM goes to host validator').toString('base64');
  for(const toPath of ['/urbit/control/auth.json', '/urbit/pier/x', '', 'server.pem',
      '/urbit/control/owner-tls-public/../server.pem', '/urbit/control/owner-tls-public/server.key',
      '/urbit/control/owner-tls-public/request.pem'])
    await assert.rejects(api.uploadUvmCertificate(container,{toPath,filename:'server.pem',dataUri},request), /PUBLIC_CERTIFICATE_REQUIRED/);
  assert.equal(requests,0);
  await assert.rejects(api.uploadUvmCertificate(container,{toPath:'/urbit/control/owner-tls-public',filename:'server.pem',dataUri},request), /lost acknowledgement/);
  assert.equal(requests,1);
  await assert.rejects(api.uploadUvmCertificate({inspect:async()=>{throw Error('inspect refused');}}, {}, request), /inspect refused/);
  assert.equal(await api.uploadUvmCertificate({inspect:async()=>({Name:'/ordinary',Config:{Labels:{}}})}, {},request),false);
  assert.equal(requests,1);
});

test('manager restart helper and low-level mutations cannot bypass the freeze', async () => {
  const params={dappmanagerDnpName:'dappmanager.dnp.dappnode.eth',DNCORE_DIR:'/must-not-write',
    restartDnpName:'restart.dnp.dappnode.eth', restartContainerName:'restart'};
  const restart=actualFunction('packages/installer/src/installer/restartPatch.ts', 'restartDappmanagerPatch', {
    path, params, assertManagerUpdateAllowed:api.assertManagerUpdateAllowed,
    fs:new Proxy({}, {get(){assert.fail('manager update wrote files');}}),
    getDockerComposePath:()=>assert.fail('restart launch reached')
  });
  await assert.rejects(restart({composePath:'/stock.yml',restartCommand:'untrusted',restartLaunchCommand:'untrusted'}), /MANAGER_SELF_UPDATE_FROZEN/);
  for(const identity of [params.dappmanagerDnpName,'DAppNodeCore-'+params.dappmanagerDnpName])
    assert.throws(()=>api.assertUnmanaged(identity), /MANAGER_SELF_UPDATE_FROZEN/);
  await assert.rejects(api.assertUnmanagedContainer({inspect:async()=>({Name:'/id',Config:{Labels:{'dappnode.dnp.dnpName':params.dappmanagerDnpName}}})}), /MANAGER_SELF_UPDATE_FROZEN/);
  assert.doesNotThrow(()=>api.assertManagerUpdateAllowed('ordinary.public.dappnode.eth'));
});

test('protected package and storage aliases never fall through to stock lifecycle', () => {
  for (const name of ['uvm.public.dappnode.eth', 'DAppNodePackage-ship.uvm.public.dappnode.eth',
                      'uvmpublicdappnodeeth_ship_data'])
    assert.throws(() => api.assertUnmanaged(name), /HOST_LIFECYCLE_REQUIRED/);
  assert.doesNotThrow(() => api.assertUnmanaged('other.public.dappnode.eth'));
});

test('installer handoff precedes stock Compose create and skips stock rollback', () => {
  const run = read('packages/installer/src/installer/runPackages.ts');
  assert.ok(run.indexOf('await activateUvm(pkg.compose)') > 0, 'activation call missing');
  assert.ok(run.indexOf('await activateUvm(pkg.compose)') < run.indexOf('await dockerComposeUp('));
  assert.match(run, /if \(pkg.dnpName === UVM_PACKAGE\)[\s\S]*?await activateUvm\(pkg.compose\);[\s\S]*?continue;/);
  const rollback = read('packages/installer/src/installer/rollbackPackages.ts');
  assert.ok(rollback.indexOf('packagesData = packagesData.filter') > 0, 'rollback refusal missing');
  assert.ok(rollback.indexOf('packagesData = packagesData.filter') < rollback.indexOf('fs.copyFileSync'));
});

test('stock Compose, direct container mutations and writable transfers guard before engine mutation', () => {
  const cli = read('packages/dockerApi/src/compose/cli.ts');
  assert.match(cli, /if \(subcommand !== "config"\) assertUnmanagedCompose\(dcPath\);/);
  const containers = read('packages/dockerApi/src/api/container.ts');
  assert.equal((containers.match(/await assertUnmanagedContainer\(docker.getContainer\(containerNameOrId\)\)/g) || []).length, 5);
  for (const [file, boundary] of [
    ['api/volume.ts', 'await assertUnmanagedVolume(volume)'],
    ['api/putArchive.ts', 'await assertUnmanagedContainer(container)'],
    ['api/copyFileTo.ts', 'await assertUnmanagedContainer(docker.getContainer(containerName))'],
    ['removeNamedVolume.ts', 'assertUnmanaged(volName)']
  ]) assert.ok(read('packages/dockerApi/src/' + file).includes(boundary), file);
  for (const file of ['packageSetEnvironment', 'packageRemove'])
    assert.ok(read('packages/installer/src/calls/' + file + '.ts').includes('assertUnmanaged(dnpName);'));
});

test('container ID and custom volume aliases are checked using actual inspect metadata', async () => {
  let inspected = 0;
  await assert.rejects(api.assertUnmanagedContainer({inspect: async () => {
    inspected++;
    return {Name: '/innocent', Config: {Labels: {}}, Mounts: [{Name: 'uvmpublicdappnodeeth_ship_data'}]};
  }}), /HOST_LIFECYCLE_REQUIRED/);
  assert.equal(inspected, 1);
  await assert.rejects(api.assertUnmanagedVolume({inspect: async () => ({Name:'x', Labels:{owner:'uvm.public.dappnode.eth'}})}), /HOST_LIFECYCLE_REQUIRED/);
});

test('actual installer and rollback function bodies refuse stock fallback (header-only type erasure)', async () => {
  const source = read('packages/installer/src/installer/runPackages.ts');
  const body = source.slice(source.indexOf('export async function runPackages'))
    .replace('export async function runPackages(packagesData: InstallPackageData[], log: Log): Promise<void>',
             'async function runPackages(packagesData, log)');
  const pkg = {dnpName: api.UVM_PACKAGE, compose: {services:{ship:{}}}};
  let called = 0;
  const invoke = new Function('UVM_PACKAGE', 'activateUvm', 'dockerComposeUp',
      body + '; return runPackages;');
  const run = invoke(api.UVM_PACKAGE, async compose => {called++; assert.equal(compose, pkg.compose);},
      () => assert.fail('stock create reached'));
  await run([pkg], () => {});
  assert.equal(called, 1);
  const failed = invoke(api.UVM_PACKAGE, async () => {throw new Error('broker unavailable');},
      () => assert.fail('stock fallback reached'));
  await assert.rejects(failed([pkg], () => {}), /broker unavailable/);
  await assert.rejects(run([{...pkg, fileUploads:{ship:{'/any/path':'data'}}}], () => {}), /not admitted/);
  assert.equal(called, 1);
  const rollbackSource = read('packages/installer/src/installer/rollbackPackages.ts');
  const rollbackBody = rollbackSource.slice(rollbackSource.indexOf('export async function rollbackPackages'))
    .replace('export async function rollbackPackages(packagesData: InstallPackageDataPaths[], log: Log): Promise<void>',
             'async function rollbackPackages(packagesData, log)');
  const rollback = new Function('UVM_PACKAGE', 'fs', rollbackBody + '; return rollbackPackages;')(
      api.UVM_PACKAGE, new Proxy({}, {get(){assert.fail('rollback touched files');}}));
  await rollback([pkg], () => {});
});

test('real Unix transport returns exact activation receipt; refusals have no fallback', async () => {
  const scratch = fs.mkdtempSync(path.join(process.env.IMPORTER_TEST_SCRATCH || os.tmpdir(), 'uvm-rpc-'));
  const address = path.join(scratch, 's');
  let response = {ok:true, state:'ACTIVE', container:'a'.repeat(64)};
  const requests = [];
  const server = net.createServer(socket => {
    let data = '';
    socket.on('data', chunk => {
      data += chunk.toString();
      if (!data.endsWith('\n')) return;
      requests.push(JSON.parse(data));
      socket.end(JSON.stringify(response) + '\n');
    });
  });
  await new Promise(resolve => server.listen(address, resolve));
  try {
    const request = {package:api.UVM_PACKAGE, operation:'activate', compose:{services:{ship:{}}}};
    const result = await api.requestUvm(request, () => net.createConnection(address));
    assert.equal(result.container, 'a'.repeat(64));
    assert.deepEqual(requests[0], request);
    response = {ok:false, error:'refused'};
    await assert.rejects(api.requestUvm(request, () => net.createConnection(address)), /UNCERTAIN/);
    assert.equal(requests.length, 2);
    response = {ok:true, state:'RECOVERED_STOPPED'};
    const recovered = await api.requestUvm({...request, operation:'recover'}, () => net.createConnection(address));
    assert.equal(recovered.state, 'RECOVERED_STOPPED');
    assert.equal(requests.length, 3);
    const certificate={package:api.UVM_PACKAGE,operation:'certificate',container:'a'.repeat(64),filename:'root-ca.pem',content:'YQ=='};
    response={ok:true,state:'CERTIFICATE_STORED',container:certificate.container,filename:certificate.filename};
    assert.equal((await api.requestUvm(certificate,()=>net.createConnection(address))).state,'CERTIFICATE_STORED');
    response={...response,filename:'server.pem'};
    await assert.rejects(api.requestUvm(certificate,()=>net.createConnection(address)), /UNCERTAIN/);
    response={ok:true,state:'CERTIFICATE_STORED',container:'b'.repeat(64),filename:certificate.filename};
    await assert.rejects(api.requestUvm(certificate,()=>net.createConnection(address)), /UNCERTAIN/);
  } finally {
    await new Promise(resolve => server.close(resolve));
    fs.rmSync(scratch, {recursive:true});
  }
});
