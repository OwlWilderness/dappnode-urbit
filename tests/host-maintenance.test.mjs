import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync, existsSync} from 'node:fs';
import {parseYaml, validateDappnodeCompose} from '../scripts/sdk.mjs';

test('host-managed overlay disables copy-up without changing default installation', () => {
  assert.ok(existsSync('host-maintenance.compose.yml'), 'host-managed nocopy descriptor is missing');
  const base = parseYaml(readFileSync('docker-compose.yml', 'utf8'));
  const overlay = parseYaml(readFileSync('host-maintenance.compose.yml', 'utf8'));
  assert.equal(base.services.ship.volumes[0], 'ship_data:/urbit');
  assert.deepEqual(overlay.services.ship.volumes, [{type:'volume', source:'ship_data', target:'/urbit', volume:{nocopy:true}}]);
  assert.deepEqual(Object.keys(overlay.services), ['ship']);
  assert.deepEqual(Object.keys(overlay.services.ship), ['volumes']);
  const composed = structuredClone(base);
  composed.services.ship.volumes = overlay.services.ship.volumes;
  validateDappnodeCompose(base, JSON.parse(readFileSync('dappnode_package.json')));
  // The pinned Dappnode SDK only accepts short-volume strings. This separate
  // host-orchestrator input is validated with Docker Compose, never SDK-packed.
  assert.throws(() => validateDappnodeCompose(composed, JSON.parse(readFileSync('dappnode_package.json'))), /volume\.split/);
  assert.equal(composed.services.ship.restart, 'unless-stopped');
});
