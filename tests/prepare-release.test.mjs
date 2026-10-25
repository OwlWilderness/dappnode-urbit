import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync, symlinkSync, renameSync, lstatSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { spawnSync } from 'node:child_process';
import childProcess from 'node:child_process';

const scratch = process.env.RELEASE_TEST_SCRATCH || process.env.IMPORTER_TEST_SCRATCH;
assert.ok(scratch, 'Set RELEASE_TEST_SCRATCH to an approved scratch directory; fixtures are retained');
const retained = mkdtempSync(join(resolve(scratch), 'release-descriptors-'));
console.log(`Retained release fixtures: ${retained}`);
const modulePath = resolve('scripts/prepare-release.mjs');
const tag = 'ship.uvm.public.dappnode.eth:0.1.3';
const files = ['dappnode_package.json', 'docker-compose.yml', 'setup-wizard.yaml', 'avatar-urbit.png'];
const outputFiles = ['dappnode_package.json', 'docker-compose.yml', 'setup-wizard.json', 'avatar.png'];
function fixture() {
  const dir = mkdtempSync(join(retained, 'case-'));
  const rootDir = join(dir, 'source');
  mkdirSync(rootDir);
  const manifest = { name: 'uvm.public.dappnode.eth', version: '0.1.3', type: 'service', description: 'Synthetic descriptor fixture', author: 'Fixture', license: 'GPL v3', architectures: ['linux/amd64'], mainService: 'ship' };
  const compose = { version: '3.5', services: { ship: { image: tag, build: { context: '.', dockerfile: 'build/Dockerfile' }, environment: { FIXTURE: '' } } } };
  const wizard = { version: '2', fields: [{ id: 'fixture', title: 'Fixture', description: 'Synthetic public field', target: { type: 'environment', name: 'FIXTURE', service: 'ship' } }] };
  for (const [name, value] of [[files[0], manifest], [files[1], compose], [files[2], wizard]]) writeFileSync(join(rootDir, name), JSON.stringify(value));
  writeFileSync(join(rootDir, files[3]), Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+jRZkAAAAASUVORK5CYII=', 'base64'));
  return { dir, rootDir, outputDir: join(dir, 'output'), manifest, compose, wizard };
}
async function prepare(options) {
  assert.ok(existsSync(modulePath), 'scaffold RED: release preparer module is not implemented');
  return (await import(modulePath)).prepareRelease(options);
}

for (const [label, file, change] of [
  ['package', 'manifest', m => { m.name = 'other.public.dappnode.eth'; }],
  ['version', 'manifest', m => { m.version = '0.1.4'; }],
  ['architecture', 'manifest', m => { m.architectures = ['linux/arm64']; }],
  ['main service', 'manifest', m => { m.mainService = 'other'; }],
  ['service', 'compose', c => { c.services.other = c.services.ship; delete c.services.ship; }],
  ['source image tag', 'compose', c => { c.services.ship.image = 'uvm.public.dappnode.eth:0.1.3'; }],
  ['manifest schema', 'manifest', m => { m.type = 'invalid'; }],
  ['Dappnode Compose rules', 'compose', c => { c.services.ship.privileged = true; }],
  ['wizard schema', 'wizard', w => { w.version = 'invalid'; }]
]) {
  test(`refuses wrong ${label} before output creation`, async () => {
    const f = fixture();
    change(f[file]);
    writeFileSync(join(f.rootDir, { manifest: files[0], compose: files[1], wizard: files[2] }[file]), JSON.stringify(f[file]));
    await assert.rejects(prepare(f));
    assert.equal(existsSync(f.outputDir), false);
  });
}

const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');

for (const name of files) {
  test(`refuses symlink input ${name} without output`, async () => {
    const f = fixture();
    renameSync(join(f.rootDir, name), join(f.dir, name));
    symlinkSync(join(f.dir, name), join(f.rootDir, name));
    await assert.rejects(prepare(f), /symlink/i);
    assert.equal(existsSync(f.outputDir), false);
  });
}
for (const kind of ['empty directory', 'populated directory', 'file', 'symlink', 'dangling symlink']) {
  test(`refuses existing output ${kind} unchanged`, async () => {
    const f = fixture();
    if (kind.includes('directory')) mkdirSync(f.outputDir);
    if (kind === 'populated directory') writeFileSync(join(f.outputDir, 'keep'), 'retained');
    if (kind === 'file') writeFileSync(f.outputDir, 'retained');
    if (kind.includes('symlink')) symlinkSync(kind === 'symlink' ? f.rootDir : join(f.dir, 'missing'), f.outputDir);
    const before = lstatSync(f.outputDir);
    await assert.rejects(prepare(f), /exist/i);
    assert.equal(lstatSync(f.outputDir).ino, before.ino);
    if (kind === 'empty directory') assert.deepEqual(readdirSync(f.outputDir), []);
    if (kind === 'populated directory') assert.equal(readFileSync(join(f.outputDir, 'keep'), 'utf8'), 'retained');
    if (kind === 'file') assert.equal(readFileSync(f.outputDir, 'utf8'), 'retained');
  });
}
test('refuses source root and descendant outputs', async () => {
  const f = fixture();
  await assert.rejects(prepare({ ...f, outputDir: f.rootDir }), /source/i);
  const outputDir = join(f.rootDir, 'new-output');
  await assert.rejects(prepare({ ...f, outputDir }), /source/i);
  assert.equal(existsSync(outputDir), false);
});
test('refuses a case-aliased source descendant on case-insensitive filesystems', async t => {
  const f = fixture();
  const alias = join(f.dir, 'SOURCE');
  if (!existsSync(alias)) return t.skip('Filesystem is case-sensitive');
  const outputDir = join(alias, 'new-output');
  await assert.rejects(prepare({ ...f, outputDir }), /source/i);
  assert.equal(existsSync(outputDir), false);
});

test('refuses symlink source directory and output parent', async () => {
  const f = fixture();
  const alias = join(f.dir, 'alias');
  symlinkSync(f.rootDir, alias);
  await assert.rejects(prepare({ ...f, rootDir: alias }), /symlink/i);
  await assert.rejects(prepare({ ...f, outputDir: join(alias, 'new-output') }), /symlink|source/i);
  assert.equal(existsSync(join(f.rootDir, 'new-output')), false);
});
test('requires an absolute output path before creating anything', async () => {
  const f = fixture();
  // Existing relative directory avoids accidental repository writes in RED.
  await assert.rejects(prepare({ ...f, outputDir: '.' }), /absolute/i);
});

test('reads only fixed public source files and launches no subprocess', async () => {
  const f = fixture();
  // These generated decoys must never be read or copied, including an SDK
  // optional file that the unrestricted package reader would discover.
  for (const name of ['.env', 'notifications.yaml', 'dappnode_package.extra.json', 'setup-wizard.extra.yaml']) writeFileSync(join(f.rootDir, name), 'SYNTHETIC_DO_NOT_READ');
  await import(modulePath);
  const originalRead = fs.readFileSync;
  const seen = new Set();
  const methods = ['exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync', 'fork'];
  const originals = Object.fromEntries(methods.map(name => [name, childProcess[name]]));
  fs.readFileSync = (path, ...args) => {
    if (typeof path === 'string' && path.startsWith(f.rootDir + '/')) {
      assert.ok(files.includes(path.slice(f.rootDir.length + 1)), 'Unexpected source read');
      seen.add(path.slice(f.rootDir.length + 1));
    }
    return originalRead(path, ...args);
  };
  for (const name of methods) childProcess[name] = () => { throw new Error('Forbidden subprocess'); };
  syncBuiltinESMExports();
  try { await prepare(f); }
  finally {
    fs.readFileSync = originalRead;
    Object.assign(childProcess, originals);
    syncBuiltinESMExports();
  }
  assert.deepEqual([...seen].sort(), files.slice(0, 3).sort());
  assert.deepEqual(readdirSync(join(f.outputDir, 'assets')).sort(), [...outputFiles].sort());
});

test('retains partial output and reports an inventory-write failure distinctly', async () => {
  const f = fixture();
  await import(modulePath);
  const original = fs.writeFileSync;
  fs.writeFileSync = (path, ...args) => {
    if (path === join(f.outputDir, 'inventory.json')) throw new Error('synthetic inventory write failure');
    return original(path, ...args);
  };
  syncBuiltinESMExports();
  try {
    await assert.rejects(prepare(f), error => error.code === 'PREPARE_RELEASE_PARTIAL' && error.outputDir === f.outputDir && /retained/i.test(error.message));
  } finally {
    fs.writeFileSync = original;
    syncBuiltinESMExports();
  }
  assert.equal(existsSync(join(f.outputDir, 'inventory.json')), false);
  assert.deepEqual(readdirSync(join(f.outputDir, 'assets')).sort(), [...outputFiles].sort());
  await assert.rejects(prepare(f), /exist/i);
});
test('CLI prepares descriptors and rejects reuse and unsupported arguments', () => {
  const f = fixture();
  const run = args => spawnSync(process.execPath, [modulePath, ...args], { cwd: f.rootDir, env: process.env, encoding: 'utf8' });
  const success = run(['--output', f.outputDir]);
  assert.equal(success.status, 0, success.stderr);
  assert.equal(JSON.parse(success.stdout).status, 'DESCRIPTORS_ONLY_IMAGE_UNBOUND');
  assert.equal(existsSync(join(f.outputDir, 'inventory.json')), true);
  assert.equal(run(['--output', f.outputDir]).status, 1);
  assert.equal(run(['--upload']).status, 1);
});

test('removes build instructions from release Compose without editing source', async () => {
  const f = fixture();
  await prepare(f);
  const expected = structuredClone(f.compose);
  delete expected.services.ship.build;
  assert.deepEqual(JSON.parse(readFileSync(join(f.outputDir, 'assets', files[1]))), expected);
  assert.deepEqual(JSON.parse(readFileSync(join(f.rootDir, files[1]))), f.compose);
});

test('writes deterministic descriptors, unbound inventory and SDK-readable wizard', async () => {
  const f = fixture();
  const inventory = await prepare(f);
  assert.equal(inventory.status, 'DESCRIPTORS_ONLY_IMAGE_UNBOUND');
  assert.equal(inventory.image_binding, null);
  assert.deepEqual(inventory.expected_image, { repo_tag: tag, filename: 'uvm.public.dappnode.eth_0.1.3_linux-amd64.txz', architecture: 'linux/amd64' });
  assert.equal(inventory.package, f.manifest.name);
  assert.equal(inventory.version, '0.1.3');
  assert.deepEqual(readdirSync(join(f.outputDir, 'assets')).sort(), [...outputFiles].sort());
  const expectedCompose = structuredClone(f.compose);
  delete expectedCompose.services.ship.build;
  assert.deepEqual(JSON.parse(readFileSync(join(f.outputDir, 'assets', files[1]))), expectedCompose);
  assert.deepEqual(JSON.parse(readFileSync(join(f.outputDir, 'assets', 'setup-wizard.json'))), f.wizard);
  assert.deepEqual(readFileSync(join(f.outputDir, 'assets', 'avatar.png')), readFileSync(join(f.rootDir, 'avatar-urbit.png')));
  for (const name of files) {
    assert.equal(inventory.inputs[name], sha256(readFileSync(join(f.rootDir, name))));
  }
  for (const name of outputFiles) {
    assert.equal(inventory.outputs[`assets/${name}`], sha256(readFileSync(join(f.outputDir, 'assets', name))));
  }
  const { parseYaml, validateSetupWizardSchema, readCompose, releaseFilesDefaultNames } = await import('../scripts/sdk.mjs');
  const dir = join(f.outputDir, 'assets');
  assert.equal(releaseFilesDefaultNames.setupWizard, 'setup-wizard.json');
  assert.equal(releaseFilesDefaultNames.avatar, 'avatar.png');
  // The SDK source reader rejects .json filenames; release readers use YAML
  // syntax, which accepts the JSON serialization, independently of that suffix.
  const wizard = parseYaml(readFileSync(join(dir, 'setup-wizard.json'), 'utf8'));
  validateSetupWizardSchema(wizard);
  assert.deepEqual(wizard, f.wizard);
  assert.deepEqual(readCompose([{ dir, composeFileName: 'docker-compose.yml' }]), expectedCompose);
  const other = join(f.dir, 'other');
  await prepare({ rootDir: f.rootDir, outputDir: other });
  for (const name of ['inventory.json', ...outputFiles.map(n => `assets/${n}`)]) assert.deepEqual(readFileSync(join(other, name)), readFileSync(join(f.outputDir, name)));
});
