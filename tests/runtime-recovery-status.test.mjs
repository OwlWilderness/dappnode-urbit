import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { mountImporter } from '../tools/browser-importer/web/app.mjs';

function status(runtimeState = 'RECOVERY_REQUIRED', overrides = {}) {
  return {
    csrf: 'synthetic-session', state: 'READY_LOCKED',
    job: { id: 'committed-job', state: 'READY_LOCKED', total_bytes: 42, offset: 42 },
    security_gate: 'OWNER_SELECTED_OFFICIAL_RISK',
    runtime: { state: runtimeState }, start_available: runtimeState === 'STOPPED',
    ...overrides
  };
}

function fixture(initial) {
  const nodes = new Map();
  const html = fs.readFileSync(new URL('../tools/browser-importer/web/index.html', import.meta.url), 'utf8');
  for (const [, id] of html.matchAll(/\bid="([^"]+)"/g)) nodes.set(id, {
    value: '', textContent: '', hidden: false, disabled: false, checked: false, files: [],
    listeners: {}, addEventListener(type, fn) { this.listeners[type] = fn; }
  });
  let current = initial, httpStatus = 200;
  const calls = [];
  const app = mountImporter({ getElementById: id => nodes.get(id) }, {
    schedule() { throw new Error('Unexpected scheduled work'); }, unschedule() {},
    async fetchImpl(url, options) {
      calls.push({ url, method: options.method });
      assert.equal(url, '/api/status');
      assert.equal(options.method, 'GET', 'Rendering must never mutate server state');
      return { ok: httpStatus === 200, status: httpStatus, json: async () => current };
    }
  });
  return { app, nodes, calls, set(next, code = 200) { current = next; httpStatus = code; } };
}

function readOnly(f) {
  assert.ok(f.calls.length > 0);
  assert.ok(f.calls.every(call => call.url === '/api/status' && call.method === 'GET'));
}

test('committed import with runtime recovery explains the blocked Start without changing import truth', async t => {
  const source = status(), before = structuredClone(source);
  const f = fixture(source); t.after(() => f.app.dispose());
  await f.app.ready;
  assert.match(f.nodes.get('message').textContent, /Runtime recovery required/i);
  assert.match(f.nodes.get('message').textContent, /Import committed\./);
  assert.match(f.nodes.get('message').textContent, /Start is blocked/);
  assert.match(f.nodes.get('message').textContent, /reviewed.*outside.scope.*operator recovery/i);
  assert.match(f.nodes.get('message').textContent, /preserve.*evidence/i);
  assert.doesNotMatch(f.nodes.get('message').textContent, /Explicit Start is required|corrupt|auto.?repair|delete|reimport/i);
  assert.equal(f.nodes.get('state').textContent, 'READY_LOCKED');
  assert.match(f.nodes.get('runtime-state').textContent, /Runtime: RECOVERY_REQUIRED/);
  assert.equal(f.nodes.get('start').disabled, true);
  assert.equal(f.nodes.get('confirm-start').disabled, true);
  assert.equal(f.nodes.get('cancel').disabled, true);
  assert.deepEqual(source, before);
  readOnly(f);
});

test('recovery to STOPPED clears recovery guidance but still requires available Start and owner confirmation', async t => {
  const f = fixture(status()); t.after(() => f.app.dispose());
  await f.app.ready;
  f.nodes.get('confirm-start').checked = true;
  f.nodes.get('confirm-start').listeners.change();
  assert.equal(f.nodes.get('start').disabled, true);
  f.set(status('STOPPED', { start_available: false }));
  await f.app.refresh();
  assert.equal(f.nodes.get('start').disabled, true);
  f.nodes.get('confirm-start').checked = false;
  f.set(status('STOPPED'));
  await f.app.refresh();
  assert.match(f.nodes.get('message').textContent, /Import committed\. Explicit Start is required/);
  assert.doesNotMatch(f.nodes.get('message').textContent, /recovery|Start is blocked/i);
  assert.equal(f.nodes.get('confirm-start').disabled, false);
  assert.equal(f.nodes.get('start').disabled, true);
  f.nodes.get('confirm-start').checked = true;
  f.nodes.get('confirm-start').listeners.change();
  assert.equal(f.nodes.get('start').disabled, false);
  assert.equal(f.nodes.get('state').textContent, 'READY_LOCKED');
  readOnly(f);
});

test('RUNNING remains a process-state report with Start disabled and no recovery action', async t => {
  const f = fixture(status('RUNNING')); t.after(() => f.app.dispose());
  await f.app.ready;
  assert.match(f.nodes.get('runtime-state').textContent, /Runtime: RUNNING \(process state, not boot-health verification\)/);
  assert.match(f.nodes.get('message').textContent, /Import committed\./);
  assert.doesNotMatch(f.nodes.get('message').textContent, /Runtime recovery required|outside.scope/i);
  assert.equal(f.nodes.get('start').disabled, true);
  assert.equal(f.nodes.get('confirm-start').disabled, true);
  assert.equal(f.nodes.get('stop-runtime').disabled, false);
  readOnly(f);
});

for (const runtimeState of ['STOPPED', 'RECOVERY_REQUIRED']) {
  test(`import uncertainty stays distinct when runtime is ${runtimeState}`, async t => {
    const f = fixture(status(runtimeState, {
      state: 'RECOVERY_REQUIRED', job: { id: 'uncertain-job', state: 'RECOVERY_REQUIRED' }, start_available: false
    }));
    t.after(() => f.app.dispose()); await f.app.ready;
    assert.equal(f.nodes.get('message').textContent, 'Recovery required. Upload, cancellation and Start are blocked; operator recovery is needed.');
    assert.doesNotMatch(f.nodes.get('message').textContent, /Import committed|Runtime recovery required/);
    assert.equal(f.nodes.get('state').textContent, 'RECOVERY_REQUIRED');
    for (const id of ['start', 'confirm-start', 'transfer', 'cancel']) assert.equal(f.nodes.get(id).disabled, true);
    readOnly(f);
  });
}

test('unauthenticated status does not disclose recovery guidance or enable Start', async t => {
  const f = fixture(status('RECOVERY_REQUIRED', { csrf: '' }));
  t.after(() => f.app.dispose()); await f.app.ready;
  assert.equal(f.nodes.get('state').textContent, 'Sign in to read server status.');
  assert.equal(f.nodes.get('message').textContent, '');
  assert.equal(f.nodes.get('transfer-panel').hidden, true);
  assert.equal(f.nodes.get('start').disabled, true);
  assert.equal(f.nodes.get('confirm-start').disabled, true);
  readOnly(f);
});

test('session expiry replaces recovery guidance with sign-in instructions and keeps Start blocked', async t => {
  const f = fixture(status()); t.after(() => f.app.dispose()); await f.app.ready;
  f.set({}, 401);
  assert.equal(await f.app.refresh(), false);
  assert.equal(f.nodes.get('message').textContent, 'Session expired. Sign in again; the server retains the upload.');
  assert.equal(f.nodes.get('state').textContent, 'Sign in to read server status.');
  assert.equal(f.nodes.get('start').disabled, true);
  assert.equal(f.nodes.get('confirm-start').disabled, true);
  readOnly(f);
});
