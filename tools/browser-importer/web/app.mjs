export const CHUNK_BYTES = 1048576;

function requireOK(response) {
  if (!response.ok) {
    const error = new Error(response.status === 401 ? 'Session expired. Sign in again; server upload is retained.' : `Request refused (HTTP ${response.status}). Refresh status before retrying.`);
    error.status = response.status;
    throw error;
  }
}

export async function uploadChunks({ file, job, csrf, fetchImpl = globalThis.fetch, signal, onProgress = () => {} }) {
  if (!Number.isSafeInteger(file.size) || file.size <= 0 || file.size !== job.total_bytes) throw new Error('Selected ZIP size does not match the job');
  if (!Number.isSafeInteger(job.offset) || job.offset < 0 || job.offset > file.size) throw new Error('Invalid durable offset');
  let current = { ...job };
  for (let offset = 0; offset < job.offset;) {
    signal?.throwIfAborted();
    const body = file.slice(offset, Math.min(offset + CHUNK_BYTES, job.offset));
    const response = await fetchImpl(`/api/jobs/${encodeURIComponent(job.id)}/verify?offset=${offset}`, {
      method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/octet-stream', 'X-CSRF-Token': csrf }, body, signal
    });
    requireOK(response);
    const result = await response.json();
    if (result.verified !== offset + body.size) throw new Error('Incorrect prefix acknowledgement');
    offset = result.verified;
  }
  while (current.offset < file.size) {
    signal?.throwIfAborted();
    const body = file.slice(current.offset, Math.min(current.offset + CHUNK_BYTES, file.size));
    const response = await fetchImpl(`/api/jobs/${encodeURIComponent(current.id)}/chunk?offset=${current.offset}`, {
      method: 'PUT', credentials: 'same-origin', headers: { 'Content-Type': 'application/octet-stream', 'X-CSRF-Token': csrf }, body, signal
    });
    requireOK(response);
    const next = await response.json();
    if (next.offset !== current.offset + body.size || next.id !== current.id) throw new Error('Incorrect upload acknowledgement');
    current = next;
    onProgress(current.offset);
  }
  return current;
}

export function mountImporter(doc, { fetchImpl = globalThis.fetch, schedule = globalThis.setTimeout, unschedule = globalThis.clearTimeout } = {}) {
  const el = id => doc.getElementById(id);
  let csrf = '', authenticated = false, status = null, timer = null, disposed = false, busy = false, controller = null;
  let reachability = 'UNKNOWN', nativeMode = el('importer')?.dataset?.mode === 'native-file';
  let accessEpoch = 0, accessTimer = null, accessController = null;
  const uploading = job => job?.state === 'UPLOADING';
  const native = () => nativeMode;
  const managed = () => !native() && status?.security_gate === 'OWNER_SELECTED_OFFICIAL_RISK' && Boolean(status?.runtime);
  const canRevealCode = () => authenticated && status?.runtime?.state === 'RUNNING' &&
    (native() ? status?.capabilities?.access_code === true : managed()) && !disposed;
  const canStopRuntime = () => managed() && (['RUNNING', 'FAULT'].includes(status?.runtime?.state) ||
    (status?.provisioning?.state === 'ATTEMPTED' && status?.runtime?.state === 'STARTING'));
  const acceptsUpload = () => !native() && status && ['IDLE', 'LOCKED', 'UPLOADING'].includes(status.state) && (!status.job || uploading(status.job));
  function render() {
    const canReveal = canRevealCode();
    const setText = (id, text) => { const node = el(id); if (node) node.textContent = text; };
    // Optional dashboard nodes keep existing importer integrations compatible.
    if (el('provision-panel')) el('provision-panel').hidden = !authenticated || native() || !status?.planet_identity;
    setText('planet-target', status?.planet_identity ? `Configured public planet: ${status.planet_identity}` : 'No planet configured.');
    setText('provision-result', status?.provisioning ? `${status.provisioning.state} — refresh; never replay interrupted initialization.` : 'No creation attempt recorded.');
    if (el('provision')) el('provision').disabled = !authenticated || busy || status?.provision_available !== true || !el('confirm-unused')?.checked;
    if (el('planet-key')) el('planet-key').disabled = busy || status?.provision_available !== true;
    if (el('confirm-unused')) el('confirm-unused').disabled = busy || status?.provision_available !== true;
    if (el('owner-actions')) el('owner-actions').hidden = !authenticated;
    if (el('runtime-controls')) el('runtime-controls').hidden = native();
    if (el('native-guidance')) el('native-guidance').hidden = !native();
    if (el('import-status')) el('import-status').hidden = native();
    setText('management-state', reachability === 'REACHABLE' ? 'Reachable — authenticated status received.' :
      reachability === 'STATUS_UNAVAILABLE' ? 'Reachable — status unavailable; the manager responded but observations could not be read.' :
      reachability === 'UNREACHABLE' ? 'Unreachable — last status request failed; refresh to observe again.' :
      reachability === 'SIGN_IN' ? 'Reachable — owner sign in required.' : 'UNKNOWN — no status response yet.');
    const observed = authenticated && reachability === 'REACHABLE' ?
      (native() ? status?.observations?.ship_state : status?.runtime?.state) : null;
    const knownStates = ['STOPPED', 'STARTING', 'RUNNING', 'FAULT', 'RECOVERY_REQUIRED'];
    setText('ship-state', `${knownStates.includes(observed) ? observed : 'UNKNOWN'} — local process observation, not ship health.`);
    setText('http-readiness', 'UNKNOWN — ship HTTP readiness has not been measured.');
    setText('recovery-state', authenticated && status ? ((!native() && ['PENDING', 'COMPLETE', 'REFUSED'].includes(status.local_recovery?.outcome) ? `Local lifecycle: ${status.local_recovery.outcome} (retained result)` : null) || status.maintenance?.state ||
      (status.runtime?.state === 'RECOVERY_REQUIRED' || status.state === 'RECOVERY_REQUIRED' ? 'RECOVERY_REQUIRED' : 'No recovery result reported.')) : 'UNKNOWN — sign in / refresh to read retained state.');
    const operation = status?.native_operation;
    setText('native-result', authenticated && operation ?
      `Sequence ${Number.isSafeInteger(operation.sequence) ? operation.sequence : 'unknown'} · ${['repair', 'start', 'stop', 'reconcile'].includes(operation.operation) ? operation.operation : 'no operation'} · ${['COMPLETE', 'PENDING', 'INTERRUPTED'].includes(operation.outcome) ? operation.outcome : 'no durable outcome'} · ${operation.current_generation === true ? 'current generation' : 'prior generation / not bound to this worker'}${['REFUSED_OR_UNCERTAIN', 'CHANNEL_UNAVAILABLE'].includes(operation.error) ? ` · ${operation.error}` : ''}` :
      'No authenticated durable result available. Sign in / refresh; no operation has been inferred.');
    if (!canReveal) clearAccessCode();
    el('access-panel').hidden = !canReveal;
    el('reveal-access-code').disabled = !canReveal || busy || Boolean(accessController);
    el('access-password').disabled = !canReveal || Boolean(accessController);
    el('login-panel').hidden = authenticated;
    el('transfer-panel').hidden = !authenticated || native();
    el('start').disabled = true;
    el('gate').textContent = 'BLOCKED_EMBEDDED_OPENSSL — Start is unavailable, including after a successful import.';
    el('confirm-start').disabled = !authenticated || busy || !managed() || !status.start_available;
    el('stop-runtime').disabled = !authenticated || busy || !canStopRuntime();
    el('runtime-state').textContent = managed() ? `Runtime: ${status.runtime.state} (process state, not boot-health verification).` : 'No runtime is managed by this standalone importer.';
    const canRecover = authenticated && !busy && managed() && status?.local_recovery_available === true;
    if (el('confirm-recover')) el('confirm-recover').disabled = !canRecover;
    if (el('recover-runtime')) el('recover-runtime').disabled = !canRecover || !el('confirm-recover')?.checked;
    const recovery = authenticated && !native() ? status?.local_recovery : null;
    setText('local-recovery-result', recovery && ['PENDING', 'COMPLETE', 'REFUSED'].includes(recovery.outcome) ?
      `Local operation ${Number.isSafeInteger(recovery.sequence) ? recovery.sequence : 'unknown'} · ${recovery.outcome}${recovery.outcome === 'COMPLETE' ? ' — recovery left Vere stopped; Start is separate. This retained result is not current ship health.' : ' — Start remains fenced until ownership and durable state permit it.'}` :
      (status?.local_recovery_guidance || (status?.local_recovery_available === true ?
        'Local lifecycle recovery is available. Verified management-only boot or the current owned child is required; Recover leaves the ship stopped.' :
        'No durable local recovery result. Unknown ownership stays fenced; restart the package into management mode first.')));
    if (managed()) {
      el('gate').textContent = status.runtime_selection === 'retained-amd64-curl-baseline' ?
        'Pinned issue3 OpenSSL 3.5.9 / curl 8.23.0 candidate. Runtime health and distribution clearance are separate qualification gates. Initialization never auto-starts; confirm no other instance before Start.' :
        'Official stable Vere — embedded dependency maintenance risk remains disclosed. Import completion never starts the ship. Confirm no other instance is running before each explicit Start.';
      el('start').disabled = !authenticated || busy || status.start_available !== true || status.runtime.state !== 'STOPPED' || !el('confirm-start').checked;
    }
    const job = status?.job;
    const state = job?.state || status?.state;
    if (authenticated && !native() && state === 'READY_LOCKED') el('message').textContent = 'Import committed. Runtime remains locked by BLOCKED_EMBEDDED_OPENSSL; Start is unavailable.';
    if (authenticated && state === 'READY_LOCKED' && managed()) el('message').textContent = 'Import committed. Explicit Start is required; process launch does not prove a healthy boot.';
    if (authenticated && state === 'RECOVERY_REQUIRED') el('message').textContent = 'Recovery required. Upload, cancellation and Start are blocked; operator recovery is needed.';
    if (authenticated && state === 'FAILED') el('message').textContent = 'Import failed. Review server status; cancel the incomplete job before trying again.';

    el('transfer').disabled = !authenticated || busy || !acceptsUpload();
    el('pause').disabled = !controller;
    el('logout').disabled = busy;
    el('refresh').disabled = busy;
    el('zip').disabled = busy;
    el('stopped').disabled = busy;
    el('budget').disabled = busy || Boolean(job);
    el('cancel').disabled = native() || !authenticated || busy || !job || !['UPLOADING', 'FAILED'].includes(job.state);
    el('state').textContent = authenticated ? (job?.state || status?.state || 'UNKNOWN') : 'Sign in to read server status.';
    el('upload-progress').max = job?.total_bytes || 1;
    el('upload-progress').value = job?.offset || 0;
    el('upload-count').textContent = `${job?.offset || 0} / ${job?.total_bytes || 0} bytes`;
    el('extract-progress').max = job?.expanded_limit || 1;
    el('extract-progress').value = job?.expanded_bytes || 0;
    el('extract-count').textContent = `${job?.expanded_bytes || 0} expanded bytes · ${job?.files || 0} files`;
    if (authenticated && status?.capacity) {
      const c = status.capacity;
      el('capacity').textContent = `Upload free: ${c.upload_free} bytes · Pier free: ${c.pier_free} bytes · Shared filesystem: ${c.same_filesystem ? 'yes' : 'no'} · Free inodes: ${c.free_inodes}`;
    }
  }
  function showError(error) {
    clearAccessCode();
    const hadSession = Boolean(csrf);
    if (error.status === 401) { csrf = ''; authenticated = false; status = null; }
    el('message').textContent = error.status === 401 ? (hadSession ? 'Session expired. Sign in again; retained server data is unchanged.' : 'Sign in to read private owner status.') : 'Request failed. Refresh server status before retrying.';
    render();
  }
  async function request(url, method = 'GET', body) {
    const options = { method, credentials: 'same-origin', cache: 'no-store', headers: {} };
    if (method !== 'GET') {
      options.headers = { 'Content-Type': 'application/json' };
      if (url !== '/api/login') options.headers['X-CSRF-Token'] = csrf;
      options.body = JSON.stringify(body ?? {});
    }
    const response = await fetchImpl(url, options);
    requireOK(response);
    return response.json();
  }
  async function refresh() {
    if (disposed) return false;
    if (timer !== null) { unschedule(timer); timer = null; }
    try {
      status = await request('/api/status');
      reachability = 'REACHABLE';
      nativeMode = nativeMode || status.capabilities?.mode === 'native-file';
      if (status.csrf && status.csrf !== csrf) clearAccessCode();
      csrf = status.csrf || csrf;
      authenticated = Boolean(csrf);
      if (authenticated && native()) el('message').textContent = 'Read-only native status. Start, Stop and Recover require the attended owner guidance below; no lifecycle action has been sent.';
      render();
      if (!disposed && !busy && authenticated && (['VALIDATING', 'COMMITTING'].includes(status.job?.state || status.state) ||
          (status.provisioning?.state === 'ATTEMPTED' && status.runtime?.state === 'STARTING'))) {
        timer = schedule(() => { timer = null; return refresh(); }, 1000);
      }
      return true;
    } catch (error) {
      reachability = error.status === 401 ? 'SIGN_IN' : error.status ? 'STATUS_UNAVAILABLE' : 'UNREACHABLE';
      status = null;
      showError(error); return false;
    }
  }
  async function login() {
    clearAccessCode();
    // Clear the field before starting the request; retain no password variable.
    const options = { method: 'POST', credentials: 'same-origin', cache: 'no-store', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: el('password').value }) };
    el('password').value = '';
    el('login').disabled = true;
    try {
      const pending = fetchImpl('/api/login', options);
      options.body = undefined;
      const response = await pending;
      requireOK(response);
      const result = await response.json();
      csrf = result.csrf || '';
      await refresh();
      if (authenticated && acceptsUpload()) el('message').textContent = 'Signed in. Select a local ZIP to upload or resume.';
      render();
    } catch (error) { showError(error); }
    finally { el('login').disabled = false; }
  }
  async function transfer() {
    if (native() || busy || !authenticated) return;
    const file = el('zip').files[0];
    if (!file || !/\.zip$/i.test(file.name) || file.size <= 0) { el('message').textContent = 'Select a nonempty local .zip file.'; return; }
    if (!el('stopped').checked) { el('message').textContent = 'Confirm that the source is stopped and no second instance is running at transfer time.'; return; }
    const budget = Number(el('budget').value);
    if (!status?.job && (!Number.isFinite(budget) || budget <= 0 || budget > 64)) { el('message').textContent = 'Expanded budget must be greater than 0 and no more than 64 GiB.'; return; }
    busy = true;
    controller = new AbortController();
    const signal = controller.signal;
    render();
    try {
      if (!await refresh() || !authenticated) return;
      signal.throwIfAborted();
      if (status.chunk_bytes !== CHUNK_BYTES) throw new Error('Unsupported chunk protocol');
      if (!acceptsUpload()) { el('message').textContent = 'This job cannot accept uploads. Read its status before taking further action.'; return; }
      if (!status.job) {
        if (!Number.isFinite(budget) || budget <= 0 || budget > 64 || Math.floor(budget * 1024 ** 3) < 1) { el('message').textContent = 'Expanded budget must be greater than 0 and no more than 64 GiB.'; return; }
        status.job = await request('/api/jobs', 'POST', { total_bytes: file.size, expanded_limit: Math.floor(budget * 1024 ** 3), stopped: true });
      }
      el('message').textContent = status.job.offset ? 'Verifying every retained byte before resuming…' : 'Uploading bounded chunks…';
      status.job = await uploadChunks({ file, job: status.job, csrf, fetchImpl, signal, onProgress: offset => { status.job.offset = offset; render(); } });
      signal.throwIfAborted();
      status.job = await request(`/api/jobs/${encodeURIComponent(status.job.id)}/validate`, 'POST');
      el('message').textContent = 'Server validation requested. Import completion will remain locked.';
      render();
    } catch (error) {
      if (error.name === 'AbortError') el('message').textContent = 'Paused. Refreshing the durable server offset; re-confirm stopped state before resuming.';
      else showError(error);
    } finally {
      controller = null;
      busy = false;
      el('stopped').checked = false;
      await refresh();
      render();
    }
  }
  async function logout() {
    clearAccessCode();
    if (busy || !authenticated) return;
    busy = true;
    render();
    try {
      await request('/api/logout', 'POST');
      csrf = '';
      authenticated = false;
      status = null;
      el('password').value = '';
      el('zip').value = '';
      el('file-meta').textContent = 'No ZIP selected.';
      el('stopped').checked = false;
      await refresh();
      el('message').textContent = native() ? 'Signed out. Retained native recovery data is unchanged.' : 'Signed out. Any incomplete server upload is retained; sign in and reselect the original ZIP to resume.';
    } catch (error) { showError(error); }
    finally { busy = false; render(); }
  }
  async function cancel() {
    if (native() || busy || !authenticated) return;
    busy = true;
    render();
    try {
      if (!await refresh() || !authenticated) return;
      const job = status.job;
      if (!job || !['UPLOADING', 'FAILED'].includes(job.state)) return;
      await request(`/api/jobs/${encodeURIComponent(job.id)}`, 'DELETE');
      el('message').textContent = 'Cancellation requested. Reading server state back.';
      el('stopped').checked = false;
    } catch (error) { showError(error); }
    finally { busy = false; await refresh(); render(); }
  }
  async function provisionPlanet() {
    if (native() || busy || !authenticated || status?.provision_available !== true || !el('confirm-unused')?.checked) return;
    let file = el('planet-key')?.files[0];
    if (!file || !Number.isSafeInteger(file.size) || file.size < 1 || file.size > 65536) {
      el('message').textContent = 'Select a nonempty keyfile of at most 64 KiB.'; return;
    }
    busy = true;
    render();
    const options = { method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: { 'Content-Type': 'application/octet-stream', 'X-CSRF-Token': csrf,
        'X-Planet-Identity': status.planet_identity, 'X-Confirm-Unused': 'true' }, body: file };
    el('planet-key').value = '';
    file = null;
    try {
      // One request only. Never retry creation after errors/lost acknowledgement.
      const pending = fetchImpl('/api/provision', options);
      options.body = undefined;
      const response = await pending;
      requireOK(response);
      el('message').textContent = 'Initialization requested once. Reading durable state; Start remains separate.';
    } catch (error) { showError(error); }
    finally {
      options.body = undefined;
      el('confirm-unused').checked = false;
      busy = false;
      await refresh(); render();
    }
  }
  async function startRuntime() {
    if (native() || busy || !authenticated || !el('confirm-start').checked) return;
    busy = true;
    render();
    try {
      if (!await refresh() || !managed() || status.start_available !== true || status.runtime.state !== 'STOPPED') return;
      await request('/api/start', 'POST', { confirmed_stopped: true });
    } catch (error) { showError(error); }
    finally { el('confirm-start').checked = false; busy = false; await refresh(); render(); }
  }
  async function revealAccessCode() {
    if (disposed || busy || accessController || !canRevealCode()) return;
    const options = { method: 'POST', credentials: 'same-origin', cache: 'no-store',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
      body: JSON.stringify({ password: el('access-password').value }) };
    clearAccessCode();
    const epoch = accessEpoch, session = csrf;
    accessController = new AbortController();
    options.signal = accessController.signal;
    accessTimer = schedule(() => { clearAccessCode(); render(); }, 10000);
    render();
    try {
      const pending = fetchImpl('/api/access-code', options);
      options.body = undefined;
      const response = await pending;
      if (epoch !== accessEpoch || session !== csrf || disposed || !authenticated) return;
      requireOK(response);
      const result = await response.json();
      if (epoch !== accessEpoch || session !== csrf || disposed || !authenticated) return;
      if (typeof result.code !== 'string' || !/^(?:[a-z]{3}|[a-z]{6}(?:-[a-z]{6}){0,3})$/.test(result.code)) throw new Error('Invalid code response');
      if (accessTimer !== null) unschedule(accessTimer);
      el('access-code').textContent = result.code;
      el('access-code').hidden = false;
      accessTimer = schedule(() => { clearAccessCode(); render(); }, 30000);
    } catch (error) {
      if (epoch === accessEpoch) showError(error);
    } finally {
      options.body = undefined;
      if (epoch === accessEpoch) accessController = null;
      render();
    }
  }
  function clearAccessCode() {
    accessEpoch += 1;
    accessController?.abort();
    accessController = null;
    if (accessTimer !== null) unschedule(accessTimer);
    accessTimer = null;
    el('access-code').textContent = '';
    el('access-code').hidden = true;
    el('access-password').value = '';
  }
  async function stopRuntime() {
    clearAccessCode();
    if (busy || !authenticated || !canStopRuntime()) return;
    busy = true;
    render();
    try { await request('/api/stop', 'POST'); }
    catch (error) { showError(error); }
    finally { el('confirm-start').checked = false; busy = false; await refresh(); render(); }
  }
  async function recoverRuntime() {
    clearAccessCode();
    if (native() || busy || !authenticated || !managed() ||
        status?.local_recovery_available !== true || !el('confirm-recover')?.checked) return;
    busy = true;
    el('confirm-start').checked = false;
    render();
    try {
      const bytes = new Uint8Array(16);
      globalThis.crypto.getRandomValues(bytes);
      const operation_id = Array.from(bytes, n => n.toString(16).padStart(2, '0')).join('');
      await request('/api/recover', 'POST', { operation_id });
    } catch (error) { showError(error); }
    finally {
      el('confirm-recover').checked = false;
      busy = false;
      await refresh();
      render();
    }
  }
  function pause() {
    controller?.abort();
    el('message').textContent = 'Pausing the current request. Server data is retained; the durable offset will be refreshed.';
  }
  const run = fn => event => { event.preventDefault(); return fn(); };
  el('provision-form')?.addEventListener('submit', run(provisionPlanet));
  el('confirm-unused')?.addEventListener('change', render);
  el('login-form').addEventListener('submit', run(login));
  el('access-form').addEventListener('submit', run(revealAccessCode));
  el('hide-access-code').addEventListener('click', run(() => { clearAccessCode(); render(); }));
  doc.defaultView?.addEventListener('pagehide', clearAccessCode);
  el('refresh').addEventListener('click', run(refresh));
  el('pause').addEventListener('click', run(pause));
  el('cancel').addEventListener('click', run(cancel));
  el('logout').addEventListener('click', run(logout));
  el('start').addEventListener('click', run(startRuntime));
  el('stop-runtime').addEventListener('click', run(stopRuntime));
  el('recover-runtime')?.addEventListener('click', run(recoverRuntime));
  el('confirm-recover')?.addEventListener('change', render);
  el('confirm-start').addEventListener('change', render);
  el('transfer-form').addEventListener('submit', run(transfer));
  el('zip').addEventListener('change', () => {
    const file = el('zip').files[0];
    el('file-meta').textContent = file ? `${file.name} · ${file.size} bytes · local selection only` : 'No ZIP selected.';
    render();
  });
  render();
  const ready = refresh();
  return { ready, login, refresh, transfer, pause, cancel, logout, provision: provisionPlanet, reveal: revealAccessCode, start: startRuntime, stop: stopRuntime, recover: recoverRuntime,
    dispose() { disposed = true; clearAccessCode(); doc.defaultView?.removeEventListener('pagehide', clearAccessCode); if (timer !== null) unschedule(timer); } };
}

if (typeof document !== 'undefined' && document.getElementById('importer')) mountImporter(document);
