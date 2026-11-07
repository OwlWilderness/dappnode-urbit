'use strict';
// LOCAL FIXTURES ONLY: no browser, appliance, engine, or network access.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const crypto = require('node:crypto');
const path = require('node:path');
const ROOT = __dirname;
const reference = path.join(ROOT, '../../tools/native-recovery/native-controller.js');
const referenceBytes = fs.readFileSync(reference);
// Public source parity is checked by the focused runner.
const P = 'uvm.public.dappnode.eth', NAME = 'DAppNodePackage-ship.' + P;
const ID = 'b'.repeat(64);
const V = 'uvmpublicdappnodeeth_ship_data';
const clone = x => JSON.parse(JSON.stringify(x));
function modelEdit(params) {
  const {id, enabled, applyToAll} = params[0]; // installed handler spreads params once
  return id === 'system-packages' && typeof enabled === 'boolean' && applyToAll === false
    ? {} : {error: {code: -32603, message: 'Argument id is required or generalSettings must be true'}};
}
async function run() {
  if (process.argv[2] === '--baseline') {
    const call = (method, params) => ({method, params: params === undefined ? [] : [params]});
    const body = call('autoUpdateSettingsEdit', [{id: 'system-packages', enabled: false, applyToAll: false}]);
    assert.equal(Array.isArray(body.params[0]), true);
    const actual = modelEdit(body.params);
    assert.equal(actual.error.code, -32603);
    console.log('Observed exact nested params [[object]]; modeled native RPC rejects id; no mutation.');
    assert.deepEqual(actual, {}, 'RED: observed double-wrapped call cannot complete the requested pause');
    return;
  }
  const source = fs.readFileSync(path.join(ROOT, '../../tools/native-recovery/maintenance-wire.js'), 'utf8');
  function fixture(options = {}) {
    let flags = {'system-packages': true, 'my-packages': false, [P]: options.uvmOn === true};
    let container = {containerId: ID, containerName: NAME, serviceName: 'ship', state: 'exited',
      image: 'ship.' + P + ':0.1.5', volumes: [{name: V, host: '/var/lib/docker/volumes/' + V + '/_data', container: '/urbit'}]};
    if (options.container) options.container(container);
    const calls = [];
    let release;
    const context = vm.createContext({TextEncoder, TextDecoder, Uint8Array, DataView, AbortController,
      setTimeout, clearTimeout, location: {hostname: 'my.dappnode', protocol: 'http:'},
      fetch: async (url, init) => {
        const body = JSON.parse(init.body); calls.push({url, body});
        let output;
        if (url === '/rpc') {
          if (body.method === 'autoUpdateDataGet') {
            if (options.readVoid) return new Response('{}');
            output = {result: {dnpsToShow: Object.entries(flags).map(([id, enabled]) => ({id, enabled}))}};
          } else if (body.method === 'autoUpdateSettingsEdit') {
            assert.deepEqual(body.params, [{id: 'system-packages', enabled: body.params[0].enabled, applyToAll: false}]);
            const response = modelEdit(body.params); assert.deepEqual(response, {});
            if (options.hold) await new Promise(r => {release = r;});
            if (!options.mismatch) flags['system-packages'] = body.params[0].enabled;
            if (options.otherChanged) flags['my-packages'] = true;
            if (options.http) return new Response('private fixture body', {status: options.http});
            if (options.rpcError) return new Response(JSON.stringify({error: {code: -32603, message: 'private fixture', data: 'private stack'}}));
            output = {};
          } else if (body.method === 'packageGet') output = {result: {dnpName: P, containers: [clone(container)]}};
          else if (body.method === 'packagesGet') output = {result: [{dnpName: P, containers: [clone(container)]},
            ...(options.consumer ? [{dnpName: 'other', containers: [clone(container)]}] : [])]};
          else throw Error('Unexpected fixture RPC method');
        } else {
          assert.equal(url, '/mcp');
          assert.deepEqual(body.params, {name: 'dappnode_start_package', arguments: {dnpName: P}});
          const result = {dnpName: P, results: [{container: NAME, ok: !options.startError,
            ...(options.startError ? {error: '(HTTP code 304) container already started - private fixture'} : {})}]};
          if (!options.startError) container.state = 'running';
          if (options.afterID) container.containerId = 'f'.repeat(64);
          output = {jsonrpc: '2.0', id: body.id, result: {content: [{type: 'text', text: JSON.stringify(result)}]}};
          if (options.sse) return new Response('event: message\r\ndata: ' + JSON.stringify(output) + '\r\n\r\n', {headers: {'content-type': 'text/event-stream'}});
        }
        return new Response(JSON.stringify(output), {headers: {'content-type': 'application/json'}});
      }});
    vm.runInContext(referenceBytes.toString(), context);
    vm.runInContext(source, context);
    const helper = vm.runInContext('createNativeMaintenanceWire({originalContainerId: "' + ID + '"})', context);
    assert.equal(calls.length, 0, 'load and construction perform no requests');
    return {helper, calls, context, release: () => release(), off: () => {flags['system-packages'] = false;}};
  }
  // One composed boundary test, grouped output; public factory uses actual candidate code.
  let f = fixture();
  for (const arg of ['[]', 'null', 'true', 'new Date()', '"bad"']) {
    assert.throws(() => vm.runInContext(`nativeMaintenanceRpcBody('autoUpdateSettingsEdit', ${arg})`, f.context), /plain object/);
  }
  assert.equal(f.calls.length, 0);
  assert.deepEqual(JSON.parse(vm.runInContext('JSON.stringify(nativeMaintenanceRpcBody("autoUpdateDataGet"))', f.context)), {method: 'autoUpdateDataGet', params: []});
  const before = await f.helper.readUpdates(); assert.equal(before.system, true);
  await assert.rejects(f.helper.setSystemUpdates('false'), /boolean/);
  await f.helper.setSystemUpdates(false); await f.helper.setSystemUpdates(before.system);
  assert.equal((await f.helper.readUpdates()).system, true);
  assert.equal(f.calls.filter(c => c.body.method === 'autoUpdateSettingsEdit').length, 2);
  console.log('PASS wire: arrays rejected before fetch; object once; pause/restore explicit false applyToAll; void {} + fresh readback');
  for (const options of [{mismatch: true}, {otherChanged: true}, {http: 503}, {rpcError: true}]) {
    f = fixture(options);
    await assert.rejects(f.helper.setSystemUpdates(false));
    const count = f.calls.length;
    await assert.rejects(f.helper.setSystemUpdates(false), /fenced/);
    assert.equal(f.calls.length, count, 'uncertain mutation cannot retry');
    const evidence = JSON.stringify(f.helper.evidence());
    assert.ok(!evidence.includes('private'));
    if (options.http) assert.ok(evidence.includes('HTTP_ERROR') && evidence.includes('503'));
    if (options.rpcError) assert.ok(evidence.includes('RPC_ERROR') && evidence.includes('-32603'));
  }
  f = fixture({readVoid: true}); await assert.rejects(f.helper.readUpdates(), /RPC_RESULT_ABSENT/);
  f = fixture({hold: true}); const pending = f.helper.setSystemUpdates(false);
  while (!f.calls.some(c => c.body.method === 'autoUpdateSettingsEdit')) await new Promise(r => setTimeout(r, 0));
  await assert.rejects(f.helper.startOriginalIdle(), /in flight/); f.release(); await pending;
  console.log('PASS fences: mismatch/other flag/HTTP/RPC, void only edit, one mutation in flight, no automatic retry');
  f = fixture({sse: true}); f.off();
  const started = await f.helper.startOriginalIdle(); assert.equal(started.containerId, ID); assert.equal(started.state, 'running');
  const count = f.calls.length; await assert.rejects(f.helper.startOriginalIdle(), /consumed/); assert.equal(f.calls.length, count);
  for (const options of [{container: c => c.containerId = 'a'.repeat(64)}, {container: c => c.state = 'running'},
    {container: c => c.image = 'ship.' + P + ':0.1.6'}, {container: c => c.volumes[0].host = '/wrong'},
    {container: c => c.containerName = 'wrong'}, {consumer: true}, {updatesOn: true}, {uvmOn: true}]) {
    f = fixture(options); if (!options.updatesOn) f.off();
    await assert.rejects(f.helper.startOriginalIdle()); assert.equal(f.calls.filter(c => c.url === '/mcp').length, 0);
  }
  f = fixture({startError: true}); f.off(); await assert.rejects(f.helper.startOriginalIdle(), /POSITIVE_EXACT_SERVICE/);
  assert.equal(f.calls.filter(c => c.url === '/mcp').length, 1);
  const evidence = JSON.stringify(f.helper.evidence()); assert.ok(evidence.includes('HTTP_304')); assert.ok(evidence.includes('errorSha256'));
  assert.ok(!evidence.includes('private'));
  await assert.rejects(f.helper.startOriginalIdle(), /fenced/); assert.equal(f.calls.filter(c => c.url === '/mcp').length, 1);
  f = fixture({afterID: true}); f.off(); await assert.rejects(f.helper.startOriginalIdle());
  console.log('PASS original idle: exact ID/name/version/volume/exited/sole consumer/updates gates, reviewed SSE, positive receipt + same-ID running; negative 304 captured, no retry');
  console.log('PASS 1 composed local fixture test (3 logical groups); no appliance qualification or live action');
}
run().catch(error => {console.error(error); process.exitCode = 1;});
