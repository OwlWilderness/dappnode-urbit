import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

// Optional explicit reuse of an already-installed SDK; no installation or build.
const sdkRoot = resolve(process.env.DAPPNODE_SDK_ROOT || 'node_modules/@dappnode/dappnodesdk');
assert.equal(JSON.parse(readFileSync(resolve(sdkRoot, 'package.json'), 'utf8')).version, '0.3.55');
const load = path => import(pathToFileURL(resolve(sdkRoot, path)).href);
export const { getPackagesToBuildProps } = await load('dist/commands/build/variants.js');
export const { getFileValidationTask } = await load('dist/tasks/buildAndUpload/getFileValidationTask.js');
const require = createRequire(resolve(sdkRoot, 'package.json'));
export const { load: parseYaml } = require('js-yaml');
const schemaRoot = dirname(require.resolve('@dappnode/schemas/package.json'));
export const { validateSetupWizardSchema, validateManifestSchema, validateDappnodeCompose } = await import(pathToFileURL(resolve(schemaRoot, 'dist/index.js')).href);
export const { readManifest } = await load('dist/files/manifest/readManifest.js');
export const { readCompose } = await load('dist/files/compose/readCompose.js');
export const { readSetupWizardIfExists } = await load('dist/files/setupWizard/readSetupWizardIfExists.js');
export const { getComposePackageImages } = await load('dist/files/compose/getComposePackageImages.js');
export const { getImageFileName } = await load('dist/utils/getImageFileName.js');
export const { releaseFilesDefaultNames } = await load('dist/params.js');

export function readPackage(rootDir = resolve('.')) {
  return getPackagesToBuildProps({ rootDir, variantsDirPath: resolve(rootDir, 'variants'), composeFileName: 'docker-compose.yml' });
}

// Fixed public descriptors only: unlike the general package reader, this never
// discovers optional notifications or alternative manifest/wizard filenames.
export function readReleaseDescriptors(rootDir) {
  return {
    manifest: readManifest([{ dir: rootDir, manifestFileName: 'dappnode_package.json' }]).manifest,
    compose: readCompose([{ dir: rootDir, composeFileName: 'docker-compose.yml' }]),
    setupWizard: readSetupWizardIfExists([{ dir: rootDir, setupWizardFileName: 'setup-wizard.yaml' }])
  };
}
