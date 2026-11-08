import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { mountImporter } from '../../tools/browser-importer/web/app.mjs';

test('fresh owner form sends one binary body, clears selection, polls and never auto-starts', async () => {
  const html = fs.readFileSync(new URL('../../tools/browser-importer/web/index.html', import.meta.url), 'utf8');
  const nodes = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(m => [m[1], {
    value: '', textContent: '', hidden: false, disabled: false, checked: false, files: [],
    addEventListener() {}
  }]));
  assert.ok(nodes.has('provision-form'), 'browser-first fresh form missing');
  let status = { csrf: 'fixture-csrf', state: 'LOCKED', runtime: { state: 'STOPPED' },
    security_gate: 'OWNER_SELECTED_OFFICIAL_RISK', planet_identity: '~sample-planet',
    provision_available: true, runtime_selection: 'retained-amd64-curl-baseline' };
  const calls = [];
  const app = mountImporter({ getElementById: id => nodes.get(id) }, {
    fetchImpl: async (url, options) => {
      calls.push({ url, ...options });
      if (url === '/api/provision') status = { ...status, runtime: { state: 'STARTING' }, provision_available: false, provisioning: { state: 'ATTEMPTED' } };
      return { ok: true, status: 200, json: async () => structuredClone(status) };
    }, schedule: () => 1, unschedule: () => {}
  });
  await app.ready;
  const file = new Blob(['synthetic-secret']);
  nodes.get('planet-key').files = [file];
  nodes.get('planet-key').value = 'local-only';
  await app.provision();
  assert.equal(calls.filter(c => c.url === '/api/provision').length, 0);
  nodes.get('confirm-unused').checked = true;
  await app.provision();
  const requests = calls.filter(c => c.url === '/api/provision');
  assert.equal(requests.length, 1);
  assert.equal(requests[0].body, file);
  assert.equal(requests[0].headers['X-CSRF-Token'], 'fixture-csrf');
  assert.equal(requests[0].headers['X-Planet-Identity'], '~sample-planet');
  assert.equal(nodes.get('planet-key').value, '');
  assert.equal(nodes.get('confirm-unused').checked, false);
  assert.equal(nodes.get('stop-runtime').disabled, false, 'owner can interrupt initialization, retaining fence');
  await app.provision();
  assert.equal(calls.filter(c => c.url === '/api/provision').length, 1);
  assert.equal(calls.filter(c => c.url === '/api/start').length, 0);
  app.dispose();
});
