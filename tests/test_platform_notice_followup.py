"""File-only checks for the bounded five-package public source follow-up."""
import hashlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SELECTED = {
    'alpine-release': '3.24.2-r0',
    'alpine-baselayout': '3.7.2-r1',
    'alpine-baselayout-data': '3.7.2-r1',
    'alpine-keys': '2.6-r0',
    'ca-certificates-bundle': '20260909-r0',
}


def inventory():
    path = ROOT / 'THIRD_PARTY/platform/followup/inventory.json'
    if not path.is_file():
        raise AssertionError('scaffold RED: five-package reconciliation inventory is absent')
    return json.loads(path.read_text())


class PlatformNoticeFollowupTests(unittest.TestCase):
    def test_reconciles_exact_installed_package_set_without_silent_omissions(self):
        data = inventory()
        rows = data['packages']
        self.assertEqual(len(rows), len(SELECTED))
        self.assertEqual({row['name']: row['version'] for row in rows}, SELECTED)
        self.assertEqual(len({row['name'] for row in rows}), len(rows))
        baseline = json.loads((ROOT / 'THIRD_PARTY/platform/image-baseline/installed-notices/inventory.json').read_text())
        by_name = {row['name']: row for row in baseline['packages']}
        for row in rows:
            self.assertEqual(row['source_origin'], by_name[row['name']]['origin'])
            self.assertEqual(row['source_revision'], by_name[row['name']]['source_commit'])

    def test_evidence_is_content_pinned_and_every_recipe_is_reused(self):
        data = inventory()
        files = {row['path']: row for row in data['files']}
        self.assertEqual(len(files), len(data['files']))
        for name, row in files.items():
            path = ROOT / name
            self.assertFalse(path.is_symlink(), name)
            content = path.read_bytes()
            self.assertEqual(hashlib.sha256(content).hexdigest(), row['sha256'], name)
            self.assertEqual(len(content), row['bytes'], name)
        for row in data['packages']:
            self.assertIn(row['recipe_path'], files)
            self.assertEqual(files[row['recipe_path']]['kind'], 'reused_pinned_recipe')
            for name in row['evidence_paths']:
                self.assertIn(name, files, row['name'])

    def test_bounded_evidence_does_not_claim_build_or_distribution_clearance(self):
        data = inventory()
        for field in ['complete_notice_coverage', 'complete_corresponding_source_delivery',
                      'legal_clearance', 'written_offer_issued', 'final_notice_image_built',
                      'final_image_verified', 'archive_downloads_repeated']:
            self.assertIs(data[field], False, field)
        for row in data['packages']:
            self.assertIsInstance(row['remaining_gaps'], list)
            self.assertTrue(row['evidence_status'])

    def test_every_followup_file_is_bound_in_the_exact_notice_manifest(self):
        manifest = json.loads((ROOT / 'build/notice-files.json').read_text())
        for path in (ROOT / 'THIRD_PARTY/platform/followup').rglob('*'):
            self.assertFalse(path.is_symlink(), str(path))
            if path.is_file():
                name = str(path.relative_to(ROOT))
                self.assertTrue(name in manifest['files'], f'Follow-up input missing from notice manifest: {name}')
                self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), manifest['files'][name])


if __name__ == '__main__':
    unittest.main()
