/* Load alongside native-controller.js. Nothing runs on load; no fetch or mutation.
 * Supply reviewed browser File objects selected by the owner. This only prepares
 * arguments; the parent alone may explicitly invoke a fresh controller later.
 * Never transcribe an imageFileId or a nonce. An expired file stays expired.
 */
async function prepareNativeReceiptInstall({manifestFile,composeFile,stagedReceiptFile,artifactSha256,expectedArtifactSizeBytes}) {
  if (typeof artifactSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(artifactSha256) ||
      !Number.isSafeInteger(expectedArtifactSizeBytes) || expectedArtifactSizeBytes <= 0)
    throw Error('Independent reviewed artifact digest and byte count required');
  const [manifestText,compose,receiptText]=await Promise.all([
    manifestFile.text(),composeFile.text(),stagedReceiptFile.text()
  ]);
  const saved=JSON.parse(receiptText);
  if(!saved||!saved.receipt||typeof saved.receipt!=='object'||Array.isArray(saved.receipt))
    throw Error('Saved structured finish receipt required');
  return Object.freeze({manifest:JSON.parse(manifestText),compose,stagedReceipt:Object.freeze({...saved.receipt}),
    artifactSha256, expectedArtifactSizeBytes});
}
// Preparation only (no call executed here):
// const args = await prepareNativeReceiptInstall({manifestFile,composeFile,stagedReceiptFile,artifactSha256,expectedArtifactSizeBytes});
// Separately authorized parent action, with a NEW controller, not the old UNCERTAIN instance:
// await freshController.stopAndInstall(args);
