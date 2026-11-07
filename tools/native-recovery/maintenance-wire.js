/* Native my.dappnode browser helper. No requests or actions on load.
 * Load unchanged reviewed native-controller.js first for nativeFileSha256.
 * Caller must SAVE readUpdates() and its restore obligation BEFORE any write.
 * No source/TLS/journal/startup attestation: those gates belong to the operator.
 * startOriginalIdle starts only the native original management container; never
 * invokes Vere/ship Start, Stop, install, repair, or any process-launch bypass.
 */
function nativeMaintenanceRpcBody(method, argument) {
  if (argument !== undefined && (argument === null || typeof argument !== 'object' ||
      Object.getPrototypeOf(argument) !== Object.prototype)) throw Error('RPC argument must be a plain object or undefined');
  return {method, params: argument === undefined ? [] : [argument]};
}
function createNativeMaintenanceWire(target) {
  'use strict';
  if (!target || Object.keys(target).join('|') !== 'originalContainerId' ||
      typeof target.originalContainerId !== 'string' || !/^[a-f0-9]{64}$/.test(target.originalContainerId))
    throw Error('Exact retained original container ID required');
  target = Object.freeze({...target});
  if (location.hostname !== 'my.dappnode' || !['http:', 'https:'].includes(location.protocol)) throw Error('Native origin only');
  if (typeof nativeFileSha256 !== 'function') throw Error('Load reviewed nativeFileSha256 first');
  const P = 'uvm.public.dappnode.eth', NAME = 'DAppNodePackage-ship.' + P;
  const ID = target.originalContainerId;
  const V = 'uvmpublicdappnodeeth_ship_data', HOST = '/var/lib/docker/volumes/' + V + '/_data';
  const events = [], enc = new TextEncoder();
  let inFlight = false, fenced = false, startConsumed = false, n = 0;
  const record = event => { if (events.length === 32) events.shift(); events.push(event); };
  const digest = text => { const bytes = enc.encode(text); return {bodySha256: nativeFileSha256(bytes), bodyLengthBytes: bytes.length}; };
  function fail(classification, detail = {}) {
    record({classification, ...detail});
    throw Error(classification);
  }
  async function request(route, body, timeout = 15000) {
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(), timeout);
    let r;
    try {
      try {
        r = await fetch(route, {method: 'POST', credentials: 'same-origin', redirect: 'error',
          headers: {'Content-Type': 'application/json', 'Accept': 'application/json, text/event-stream'},
          body: JSON.stringify(body), signal: controller.signal});
      } catch { fail(controller.signal.aborted ? 'TIMEOUT' : 'TRANSPORT_ERROR', {route}); }
      const chunks = [], reader = r.body?.getReader(); let size = 0;
      if (!reader) fail('RESPONSE_BODY_ABSENT', {route, status: r.status});
      for (;;) {
        let part;
        try { part = await reader.read(); } catch { fail(controller.signal.aborted ? 'TIMEOUT' : 'BODY_READ_ERROR', {route, status: r.status}); }
        if (part.done) break;
        size += part.value.length;
        if (size > 1048576) { try { await reader.cancel(); } catch {} fail('RESPONSE_BOUND', {route, status: r.status}); }
        chunks.push(part.value);
      }
      const raw = new Uint8Array(size); let off = 0;
      for (const chunk of chunks) { raw.set(chunk, off); off += chunk.length; }
      const text = new TextDecoder().decode(raw);
      if (!r.ok) fail('HTTP_ERROR', {route, status: r.status, ...digest(text)});
      return {text, type: r.headers.get('content-type') || ''};
    } finally { clearTimeout(timer); }
  }
  async function rpc(method, argument) {
    const body = nativeMaintenanceRpcBody(method, argument); // arrays rejected BEFORE fetch
    const r = await request('/rpc', body); let x;
    try { x = JSON.parse(r.text); } catch { fail('RPC_INVALID_JSON', {method, ...digest(r.text)}); }
    if (!x || typeof x !== 'object' || Array.isArray(x)) fail('RPC_INVALID_ENVELOPE', {method, ...digest(r.text)});
    if (x.error) fail('RPC_ERROR', {method, ...digest(r.text),
      ...(Number.isSafeInteger(x.error.code) ? {code: x.error.code} : {})});
    // Source-verified Promise<void> serializes to {} ONLY for this method here.
    if (method === 'autoUpdateSettingsEdit' && Object.keys(x).length === 0) return;
    if (!Object.prototype.hasOwnProperty.call(x, 'result') || Object.keys(x).some(k => k !== 'result'))
      fail('RPC_RESULT_ABSENT', {method, ...digest(r.text)});
    return x.result;
  }
  async function readUpdates() {
    const data = await rpc('autoUpdateDataGet');
    function flag(id) {
      const rows = data?.dnpsToShow?.filter(x => x.id === id);
      if (rows?.length !== 1 || typeof rows[0].enabled !== 'boolean') fail('UPDATE_ROW_INVALID');
      return rows[0].enabled;
    }
    const result = {system: flag('system-packages'), uvm: flag(P), my: flag('my-packages')};
    record({method: 'autoUpdateDataGet', ...result}); return result;
  }
  async function mutation(action) {
    if (fenced) throw Error('Mutation fenced after uncertain/failed attempt; no retry');
    if (inFlight) throw Error('Mutation in flight; no duplicate');
    inFlight = true;
    try { return await action(); } catch (error) { fenced = true; throw error; }
    finally { inFlight = false; }
  }
  function one(pkg, state) {
    const c = pkg?.containers?.[0];
    if (pkg?.dnpName !== P || pkg.containers.length !== 1 || c.containerId !== ID ||
        c.containerName !== NAME || c.serviceName !== 'ship' || c.state !== state || c.image !== 'ship.' + P + ':0.1.5')
      fail('EXACT_ORIGINAL_IDENTITY_STATE_REQUIRED');
    if (c.volumes?.length !== 1 || c.volumes[0].name !== V || c.volumes[0].host !== HOST || c.volumes[0].container !== '/urbit')
      fail('EXACT_ORIGINAL_VOLUME_REQUIRED');
    return c;
  }
  async function observe(state) {
    one(await rpc('packageGet', {dnpName: P}), state);
    const all = await rpc('packagesGet');
    if (!Array.isArray(all)) fail('PACKAGE_LIST_INVALID');
    const consumers = all.flatMap(p => p.containers || []).filter(c =>
      (c.volumes || []).some(v => v.name === V || v.host === HOST));
    if (consumers.length !== 1) fail('SOLE_VOLUME_CONSUMER_REQUIRED');
    one({dnpName: P, containers: consumers}, state);
    const flags = await readUpdates();
    if (flags.system || flags.uvm) fail('SYSTEM_UVM_UPDATES_MUST_BE_OFF');
    return {containerId: ID, state};
  }
  async function startNative() {
    const id = ++n, r = await request('/mcp', {jsonrpc: '2.0', id, method: 'tools/call',
      params: {name: 'dappnode_start_package', arguments: {dnpName: P}}}, 120000);
    let response;
    // Unchanged SSE parsing logic from SHA c687c78a... reviewed controller.
    if(r.type.includes('text/event-stream')) {
      const frames=r.text.split(/\r?\n\r?\n/).flatMap(frame=>{
        const lines=frame.split(/\r?\n/).filter(x=>x.startsWith('data:')).map(x=>x.slice(5).trimStart());
        if(!lines.length)return [];try{return [JSON.parse(lines.join('\n'))];}catch{return [];}
      });
      const found=frames.filter(x=>x.id===id);if(found.length!==1)fail('MCP_RECEIPT_MISSING_AMBIGUOUS', digest(r.text));response=found[0];
    } else { try { response=JSON.parse(r.text); } catch { fail('MCP_INVALID_JSON', digest(r.text)); } }
    if (!response || response.id !== id || response.error || response.result?.isError)
      fail('MCP_ERROR_OR_UNCERTAIN', digest(r.text));
    const x = response.result; let result;
    if (x?.content?.length !== 1 || x.content[0].type !== 'text') fail('MCP_CONTENT_INVALID', digest(r.text));
    try { result = JSON.parse(x.content[0].text); } catch { fail('MCP_CONTENT_INVALID_JSON', digest(r.text)); }
    // Capture bounded per-container classification BEFORE positive validation.
    const rows = Array.isArray(result?.results) ? result.results : [];
    record({method: 'dappnode_start_package', resultCount: rows.length, results: rows.slice(0, 8).map(row => {
      const error = typeof row?.error === 'string' ? row.error : row?.error === undefined ? '' : JSON.stringify(row.error);
      const bytes = enc.encode(error);
      return {exactContainer: row?.container === NAME, ok: row?.ok === true,
        classification: error ? (/\(HTTP code 304\)/.test(error) ? 'HTTP_304' : 'CONTAINER_ERROR') : 'NO_ERROR',
        ...(error ? {errorSha256: nativeFileSha256(bytes), errorLengthBytes: bytes.length} : {})};
    })});
    if (result?.dnpName !== P || rows.length !== 1 || rows[0].container !== NAME || rows[0].ok !== true || rows[0].error)
      fail('POSITIVE_EXACT_SERVICE_COMPLETION_REQUIRED');
  }
  return Object.freeze({
    readUpdates,
    async setSystemUpdates(enabled) {
      if (typeof enabled !== 'boolean') throw Error('enabled must be boolean');
      return mutation(async () => {
        const before = await readUpdates(); // caller still must save restore obligation first
        record({method: 'autoUpdateSettingsEdit', requested: enabled, before});
        await rpc('autoUpdateSettingsEdit', {id: 'system-packages', enabled, applyToAll: false});
        const after = await readUpdates();
        if (after.system !== enabled || after.uvm !== before.uvm || after.my !== before.my) fail('UPDATE_READBACK_MISMATCH');
        return after;
      });
    },
    async startOriginalIdle() {
      return mutation(async () => {
        if (startConsumed) throw Error('Original idle Start consumed; no duplicate');
        startConsumed = true;
        await observe('exited');
        await startNative(); // exactly one explicit native management-idle Start; no retry
        return observe('running');
      });
    },
    evidence() { return JSON.parse(JSON.stringify({inFlight, fenced, startConsumed, events})); }
  });
}
