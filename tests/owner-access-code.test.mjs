import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { mountImporter } from '../src/manager/web/app.mjs';

const CODE = 'sampel-sampel-sampel-sampel';
const response = (body, status = 200) => ({ ok: status === 200, status, json: async () => body });
function fixture({ revealResponse = async () => response({ code: CODE }), state = 'RUNNING' } = {}) {
  const nodes = new Map();
  const html = fs.readFileSync(new URL('../src/manager/web/index.html', import.meta.url), 'utf8');
  for (const match of html.matchAll(/\bid="([^"]+)"/g)) nodes.set(match[1], {
    value: '', textContent: '', hidden: false, disabled: false, checked: false, files: [],
    listeners: {}, addEventListener(type, fn) { this.listeners[type] = fn; }
  });
  const events = new Map();
  const doc = { getElementById: id => nodes.get(id), defaultView: {
    addEventListener: (type, fn) => events.set(type, fn),
    removeEventListener: type => events.delete(type)
  }};
  let loggedIn = true, csrf = 'synthetic-csrf';
  const calls = [], timers = new Map();
  let next = 0;
  const app = mountImporter(doc, {
    schedule(fn, delay) { timers.set(++next, { fn, delay }); return next; },
    unschedule(id) { timers.delete(id); },
    async fetchImpl(url, options) {
      calls.push({ url, ...options });
      if (url === '/api/access-code') return revealResponse();
      if (url === '/api/logout') { loggedIn = false; return response({ logged_out: true }); }
      return loggedIn ? response({ csrf, runtime: { state }, security_gate: 'OWNER_SELECTED_OFFICIAL_RISK' }) : response({}, 401);
    }
  });
  return { app, nodes, calls, timers, events, session(value) { csrf = value; }, expire() { loggedIn = false; } };
}

const actions = {
  logout: f => f.app.logout(),
  hide: f => f.nodes.get('hide-access-code').listeners.click?.({ preventDefault() {} }),
  pagehide: f => f.events.get('pagehide')?.(),
  expiry: async f => { f.expire(); await f.app.refresh(); },
  session: async f => { f.session('synthetic-new-session'); await f.app.refresh(); },
  dispose: f => f.app.dispose(),
  timeout: f => [...f.timers.values()].find(timer => [10000, 30000].includes(timer.delay))?.fn()
};
for (const [name, act] of Object.entries(actions)) {
  test(`displayed code cleared on ${name}`, async () => {
    const f = fixture(); await f.app.ready;
    f.nodes.get('access-password').value = 'synthetic-owner-password';
    await f.app.reveal();
    await act(f);
    assert.equal(f.nodes.get('access-code').textContent, '');
    assert.equal(f.nodes.get('access-code').hidden, true);
    f.app.dispose();
  });
  test(`late reveal response discarded after ${name}`, async () => {
    let resolve;
    const f = fixture({ revealResponse: () => new Promise(done => { resolve = done; }) });
    await f.app.ready;
    f.nodes.get('access-password').value = 'synthetic-owner-password';
    const pending = f.app.reveal();
    await act(f);
    resolve(response({ code: CODE }));
    await pending;
    assert.equal(f.nodes.get('access-code').textContent, '');
    assert.equal(f.nodes.get('access-password').value, '');
    f.app.dispose();
  });
}

test('password is removed before a pending request and duplicate reveals are blocked', async () => {
  let resolve;
  const f = fixture({ revealResponse: () => new Promise(done => { resolve = done; }) });
  await f.app.ready;
  f.nodes.get('access-password').value = 'synthetic-owner-password';
  const pending = f.app.reveal();
  assert.equal(f.nodes.get('access-password').value, '');
  await f.app.reveal();
  assert.equal(f.calls.filter(call => call.url === '/api/access-code').length, 1);
  resolve(response({ code: CODE })); await pending; f.app.dispose();
});

test('reveal is unavailable outside RUNNING and controls are wired', async () => {
  const f = fixture({ state: 'STOPPED' }); await f.app.ready;
  f.nodes.get('access-password').value = 'synthetic-owner-password';
  await f.app.reveal();
  assert.equal(f.calls.filter(call => call.url === '/api/access-code').length, 0);
  assert.equal(f.nodes.get('reveal-access-code').disabled, true);
  assert.equal(typeof f.nodes.get('access-form').listeners.submit, 'function');
  f.app.dispose();
});

test('late JSON body cannot restore code after hiding', async () => {
  let resolveBody;
  const f = fixture({ revealResponse: async () => ({ ok: true, status: 200,
    json: () => new Promise(done => { resolveBody = done; }) }) });
  await f.app.ready;
  f.nodes.get('access-password').value = 'synthetic-owner-password';
  const pending = f.app.reveal();
  while (!resolveBody) await Promise.resolve();
  await actions.hide(f);
  resolveBody({ code: CODE });
  await pending;
  assert.equal(f.nodes.get('access-code').textContent, '');
  f.app.dispose();
});

for (const status of [401, 403, 409, 429]) test(`reveal refusal ${status} clears secrets without reflecting its body`, async () => {
  const f = fixture({ revealResponse: async () => response({ error: CODE }, status) });
  await f.app.ready;
  f.nodes.get('access-password').value = 'synthetic-owner-password';
  await f.app.reveal();
  assert.equal(f.nodes.get('access-code').textContent, '');
  assert.equal(f.nodes.get('access-password').value, '');
  assert.equal(f.nodes.get('message').textContent.includes(CODE), false);
  f.app.dispose();
});

test('owner reenters password and reveals only via a no-store fixed POST', async () => {
  const f = fixture();
  await f.app.ready;
  assert.equal(typeof f.app.reveal, 'function', 'scaffold: reveal control missing');
  f.nodes.get('access-password').value = 'synthetic-owner-password';
  await f.app.reveal();
  assert.equal(f.nodes.get('access-code').textContent, CODE);
  assert.equal(f.nodes.get('access-password').value, '');
  const request = f.calls.find(call => call.url === '/api/access-code');
  assert.equal(request.method, 'POST');
  assert.equal(request.cache, 'no-store');
  assert.equal(request.credentials, 'same-origin');
  assert.equal(request.headers['X-CSRF-Token'], 'synthetic-csrf');
  f.app.dispose();
});
