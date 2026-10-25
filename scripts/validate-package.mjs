import { readPackage, getFileValidationTask, validateSetupWizardSchema } from './sdk.mjs';

const packagesToBuildProps = readPackage();
await getFileValidationTask({ packagesToBuildProps }).task();
for (const pkg of packagesToBuildProps) {
  if (!pkg.setupWizard) throw new Error('SDK did not load setup-wizard.yaml');
  validateSetupWizardSchema(pkg.setupWizard);
}
console.log('PASS: pinned SDK manifest, Compose and wizard validation; no build/upload/runtime');
