import { readFileSync, mkdirSync, writeFileSync, lstatSync, openSync, closeSync, fstatSync, constants } from 'node:fs';
import { resolve, join, dirname, isAbsolute, sep } from 'node:path';
import { createHash } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import assert from 'node:assert/strict';
import { readReleaseDescriptors, getComposePackageImages, getImageFileName, releaseFilesDefaultNames, validateManifestSchema, validateDappnodeCompose, validateSetupWizardSchema } from './sdk.mjs';

const inputNames = ['dappnode_package.json', 'docker-compose.yml', 'setup-wizard.yaml', 'avatar-urbit.png'];
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
const json = value => Buffer.from(`${JSON.stringify(value, null, 2)}\n`);

// Local, quiescent checkout only: do not run against directories being changed
// by another process. SDK readers reopen these fixed paths during parsing.
function checkDirectory(path) {
  const parent = dirname(path);
  if (parent !== path) checkDirectory(parent);
  const stat = lstatSync(path);
  assert.ok(!stat.isSymbolicLink(), 'Refusing symlink directory');
  assert.ok(stat.isDirectory(), 'Expected existing directory');
}
function readPublicFile(path) {
  const stat = lstatSync(path);
  assert.ok(!stat.isSymbolicLink(), 'Refusing symlink input');
  assert.ok(stat.isFile(), 'Expected regular input file');
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = fstatSync(fd);
    assert.ok(opened.isFile() && opened.ino === stat.ino && opened.dev === stat.dev, 'Input changed');
    return readFileSync(fd);
  } finally { closeSync(fd); }
}

export async function prepareRelease({ rootDir = resolve('.'), outputDir } = {}) {
  assert.ok(typeof outputDir === 'string' && isAbsolute(outputDir), 'Output must be an absolute new directory');
  rootDir = resolve(rootDir);
  outputDir = resolve(outputDir);
  checkDirectory(rootDir);
  assert.ok(outputDir !== rootDir && !outputDir.startsWith(`${rootDir}${sep}`), 'Output cannot be source directory or descendant');
  checkDirectory(dirname(outputDir));
  // Compare physical directory identities as well as lexical paths (APFS may
  // accept differently-cased paths to the same source directory).
  const sourceStat = lstatSync(rootDir);
  for (let parent = dirname(outputDir); ; parent = dirname(parent)) {
    const stat = lstatSync(parent);
    assert.ok(stat.dev !== sourceStat.dev || stat.ino !== sourceStat.ino, 'Output cannot be inside source directory');
    if (dirname(parent) === parent) break;
  }
  assert.equal(lstatSync(outputDir, { throwIfNoEntry: false }), undefined, 'Output already exists');
  const inputs = Object.fromEntries(inputNames.map(name => [name, readPublicFile(join(rootDir, name))]));
  const { manifest, compose, setupWizard } = readReleaseDescriptors(rootDir);
  for (const name of inputNames) assert.deepEqual(readPublicFile(join(rootDir, name)), inputs[name], 'Input changed during parsing');
  assert.equal(manifest.name, 'uvm.public.dappnode.eth', 'Unexpected package');
  assert.equal(manifest.version, '0.1.3', 'Unexpected version');
  assert.deepEqual(manifest.architectures, ['linux/amd64'], 'Unexpected architecture');
  assert.equal(manifest.mainService, 'ship', 'Unexpected main service');
  assert.deepEqual(Object.keys(compose.services), ['ship'], 'Unexpected service set');
  const [image] = getComposePackageImages(compose, manifest);
  assert.equal(image.imageTag, 'ship.uvm.public.dappnode.eth:0.1.3', 'Unexpected SDK image tag');
  assert.equal(compose.services.ship.image, image.imageTag, 'Unexpected source image tag');
  validateManifestSchema(manifest);
  // Deliberately omit validateComposeSchema/getFileValidationTask: those spawn
  // `docker compose config`. These are SDK file-only rules, NOT Docker validation.
  validateDappnodeCompose(compose, manifest);
  assert.ok(setupWizard, 'Missing setup wizard');
  validateSetupWizardSchema(setupWizard);
  const releaseCompose = structuredClone(compose);
  for (const service of Object.values(releaseCompose.services)) delete service.build;
  const outputs = {
    [releaseFilesDefaultNames.manifest]: json(manifest),
    [releaseFilesDefaultNames.compose]: json(releaseCompose),
    [releaseFilesDefaultNames.setupWizard]: json(setupWizard),
    [releaseFilesDefaultNames.avatar]: inputs['avatar-urbit.png']
  };
  const inventory = {
    status: 'DESCRIPTORS_ONLY_IMAGE_UNBOUND',
    package: manifest.name,
    version: manifest.version,
    sdk_version: '0.3.55',
    expected_image: { repo_tag: image.imageTag, filename: getImageFileName(manifest.name, manifest.version, 'linux/amd64'), architecture: 'linux/amd64' },
    image_binding: null,
    inputs: Object.fromEntries(Object.entries(inputs).map(([name, bytes]) => [name, sha256(bytes)])),
    outputs: Object.fromEntries(Object.entries(outputs).map(([name, bytes]) => [`assets/${name}`, sha256(bytes)]))
  };
  // Exclusive claim: never reuse, replace or clean up an existing output.
  mkdirSync(outputDir, { mode: 0o700 });
  try {
    mkdirSync(join(outputDir, 'assets'), { mode: 0o700 });
    for (const [name, bytes] of Object.entries(outputs)) {
      const path = join(outputDir, 'assets', name);
      writeFileSync(path, bytes, { flag: 'wx', mode: 0o600 });
      assert.deepEqual(readPublicFile(path), bytes, 'Output readback failed');
    }
    const path = join(outputDir, 'inventory.json');
    writeFileSync(path, json(inventory), { flag: 'wx', mode: 0o600 });
    assert.deepEqual(readPublicFile(path), json(inventory), 'Inventory readback failed');
    return inventory;
  } catch (cause) {
    const error = new Error('Partial release descriptor output retained; do not reuse or treat it as complete', { cause });
    error.code = 'PREPARE_RELEASE_PARTIAL';
    error.outputDir = outputDir;
    throw error;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try {
    const args = process.argv.slice(2);
    assert.ok(args.length === 2 && args[0] === '--output', 'Usage: node scripts/prepare-release.mjs --output ABSOLUTE_NEW_DIRECTORY');
    console.log(JSON.stringify(await prepareRelease({ outputDir: args[1] }), null, 2));
  } catch (error) {
    console.error(`${error.code || 'PREPARE_RELEASE_REFUSED'}: ${error.message}`);
    process.exitCode = 1;
  }
}
