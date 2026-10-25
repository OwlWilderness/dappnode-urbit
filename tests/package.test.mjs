import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { readPackage, validateSetupWizardSchema } from '../scripts/sdk.mjs';

const [pkg] = readPackage();

test('UVM retains the volume key without exposing host administration ports', () => {
  assert.equal(pkg.manifest.name, 'uvm.public.dappnode.eth');
  assert.equal(pkg.manifest.mainService, 'ship');
  assert.deepEqual(Object.keys(pkg.compose.services), ['ship']);
  const service = pkg.compose.services.ship;
  assert.deepEqual(service.volumes, ['ship_data:/urbit']);
  assert.deepEqual(Object.keys(pkg.compose.volumes), ['ship_data']);
  assert.equal(service.ports, undefined);
  assert.deepEqual(service.expose, ['8443/tcp', '34343/udp']);
  assert.deepEqual(service.cap_drop, ['ALL']);
  assert.equal(service.logging.driver, 'none');
  assert.equal(pkg.manifest.backup, undefined, 'Do not advertise unsafe live pier backups');
});

test('UVM identity, wizard, links and launcher agree on distinct private origins', () => {
  const admin = 'https://uvm.public.dappnode.private:8443';
  const ship = 'https://ship.uvm.public.dappnode.private:8443';
  const service = pkg.compose.services[pkg.manifest.mainService];
  assert.deepEqual(pkg.images, [{ type: 'local',
    imageTag: `ship.uvm.public.dappnode.eth:${pkg.manifest.version}` }]);
  assert.equal(service.image, pkg.images[0].imageTag,
    'Direct Compose builds and SDK release exports must use the same image tag');
  assert.equal(pkg.manifest.shortDescription, 'UVM — Urbit Vere Manager');
  assert.equal(service.environment.IMPORTER_ORIGIN, admin);
  assert.equal(service.environment.URBIT_SHIP_ORIGIN, ship);
  assert.equal(pkg.manifest.links.admin, admin);
  assert.equal(pkg.manifest.links.landscape, ship);
  for (const [id, origin] of [['importerOrigin', admin], ['shipOrigin', ship]]) {
    assert.ok(pkg.setupWizard.fields.find(field => field.id === id).description.includes(origin));
  }
  const result = spawnSync('python3', ['-B', '-c', `
import json, sys
sys.path.insert(0, 'tools/browser-importer')
from package_service import make_parser, validate_routes
args = make_parser({}).parse_args([
    '--pier-root', '/unused/pier', '--uploads-root', '/unused/uploads',
    '--control-root', '/unused/control', '--password-hash-file', '/unused/auth.json'])
validate_routes(args.origin, args.ship_origin, args.bind, args.port,
                args.importer_port, args.ship_port)
print(json.dumps([args.origin, args.ship_origin]))
`], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  assert.deepEqual(JSON.parse(result.stdout), [admin, ship]);
  const metadata = JSON.parse(readFileSync('package.json', 'utf8'));
  const lock = JSON.parse(readFileSync('package-lock.json', 'utf8'));
  assert.equal(metadata.name, 'uvm-development');
  assert.equal(lock.name, metadata.name);
  assert.equal(lock.packages[''].name, metadata.name);
});

test('wizard loads through the SDK and configures digests, not boot-key upload', () => {
  assert.ok(pkg.setupWizard);
  validateSetupWizardSchema(pkg.setupWizard);
  assert.equal(existsSync('setup-wizard.yml'), false);
  const fields = pkg.setupWizard.fields;
  assert.equal(fields.length, 4);
  for (const field of fields) {
    assert.equal(field.target.type, 'environment');
    assert.equal(field.target.service, 'ship');
    assert.ok(Object.hasOwn(pkg.compose.services.ship.environment, field.target.name));
  }
  assert.equal(pkg.compose.services.ship.environment.OWNER_CA_SHA256, '');
  assert.equal(pkg.compose.services.ship.environment.IMPORTER_BOOTSTRAP_SHA256, '');
  assert.notEqual(pkg.compose.services.ship.environment.IMPORTER_ORIGIN,
    pkg.compose.services.ship.environment.URBIT_SHIP_ORIGIN);
});

test('entrypoint delegates to volume refusal before any supervisor or ship startup', () => {
  const script = readFileSync('build/docker-entrypoint.sh', 'utf8');
  assert.match(script, /exec python3 \/opt\/importer\/volume_guard\.py "\$@"/);
  assert.doesNotMatch(script, /boot\.key|PLANET_NAME|rm |mv |urbit \$/);
  const dockerfile = readFileSync('build/Dockerfile', 'utf8');
  assert.match(dockerfile, /USER 10000:10000/);
  assert.match(dockerfile, /COPY --chown=0:0 build\/volume_guard.py/);
  assert.doesNotMatch(dockerfile, /FROM tloncorp\/urbit/);
});

test('Docker context is an explicit allowlist and every local COPY input exists', () => {
  const ignore = readFileSync('.dockerignore', 'utf8').trim().split('\n');
  assert.equal(ignore[0], '**');
  const allowed = new Set(ignore.filter(line => line.startsWith('!') && !line.endsWith('/')).map(line => line.slice(1)));
  // check_docker_context.py additionally exercises Docker's actual matcher.
  for (const directory of ['build', 'tools', 'tools/browser-importer', 'tools/browser-importer/web']) {
    assert.equal(ignore[ignore.indexOf(`!${directory}/`) + 1], `${directory}/**`);
  }
  assert.ok(!allowed.has('tools/browser-importer/bootstrap-authority.html'));
  const dockerfile = readFileSync('build/Dockerfile', 'utf8');
  for (const line of dockerfile.split('\n').filter(line => line.startsWith('COPY ') && !line.includes('--from='))) {
    const inputs = line.split(/\s+/).slice(1, -1).filter(value => !value.startsWith('--'));
    for (const input of inputs) {
      if (input.endsWith('/')) {
        assert.equal(input, 'THIRD_PARTY/', 'Only the reviewed notice directory may use directory COPY');
        const manifest = JSON.parse(readFileSync('build/notice-files.json', 'utf8'));
        const files = Object.keys(manifest.files).filter(name => name.startsWith(input));
        assert.ok(files.length > 0, 'Notice directory must have a nonempty exact file inventory');
        for (const file of files) assert.ok(allowed.has(file), `Notice input not allowlisted: ${file}`);
        assert.ok(ignore.includes(`!${input}`), 'Notice directory traversal is not allowlisted');
      } else {
        assert.ok(allowed.has(input), `COPY input not allowlisted: ${input}`);
      }
      assert.ok(existsSync(input), `COPY input missing: ${input}`);
    }
  }
});
