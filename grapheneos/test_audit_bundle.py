import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile
from contextlib import redirect_stdout


MODULE = Path(__file__).with_name('audit-bundle.py')
SPEC = importlib.util.spec_from_file_location('mp01_audit_bundle', MODULE)
AUDIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDIT)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def write_json(path, value):
    path.write_text(json.dumps(value, sort_keys=True), encoding='utf-8')


class BundleFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.artifacts = {}
        self.profile = 'initial-installation'
        self.add('system_image', b'signed system image')
        with zipfile.ZipFile(self.root / 'signed.zip', 'w') as archive:
            archive.writestr('IMAGES/system.img', (self.root / 'system_image').read_bytes())
        self.artifacts['signed_target_files'] = 'signed.zip'
        self.add('unsigned_target_files', b'unsigned target-files')
        self.add('source_lock', b'{"locked":"inputs"}')
        self.add('prepared_manifest', b'<manifest/>')
        self.add('vendor_baseline', b'{"vendor":"MP01 test baseline"}')
        self.add_json('source_receipt', {
            'support_commit': 'a' * 40,
            'inputs_sha256': self.hash('source_lock'),
            'prepared_manifest_sha256': self.hash('prepared_manifest'),
            'source_graph': {'platform/build': {'revision': 'b' * 40}},
            'layer': {'keyboard': {'sha256': 'c' * 64}},
        })
        self.add_json('build_provenance', {
            'schema': 1, 'status': 'UNSIGNED_TARGET_FILES_REQUIRES_INDEPENDENT_AUDIT',
            'profile': 'development', 'variant': 'user', 'support_commit': 'a' * 40,
            'source_receipt_sha256': self.hash('source_receipt'),
            'target_files_sha256': self.hash('unsigned_target_files'),
            'device_inventory_sha256': 'e' * 64,
            'container_image_id': 'sha256:' + 'f' * 64,
            'dependencies_sha256': '1' * 64,
            'environment': {'MP01_VARIANT': 'user', 'BUILD_DATETIME': '1790035200'},
            'resources_start': {}, 'target_files': '/workspace/out/original.zip',
            'log_sha256': '2' * 64, 'resources_sha256': '3' * 64,
        })
        self.add_json('signing_policy', {'schema': 'mp01-signing-policy-v1', 'product': 'mp01',
                                         'project_certificates': ['4' * 64], 'packages': {}})
        self.signer = {
            'schema': 'mp01-signer-profile-v2', 'profile': self.profile,
            'status': 'INITIAL_SIGNER_POLICY_PASSED', 'flash_authorized': False,
            'target_files_sha256': self.hash('signed_target_files'),
            'system_image_sha256': self.hash('system_image'),
            'vendor_baseline_sha256': self.hash('vendor_baseline'),
            'policy_sha256': self.hash('signing_policy'), 'previous_report_sha256': None,
            'build': {'product': 'mp01', 'variant': 'user', 'timestamp': '1790035200', 'sdk': '37'},
            'identities': [], 'verifier_sha256': '5' * 64,
            'public_test_certificates_sha256': '6' * 64,
            'inventory_tool_sha256': '7' * 64,
        }
        self.add_json('signer_report', self.signer)
        self.avb = {
            'schema': 'mp01-avb-audit-v1', 'status': 'AVB_IMAGE_IDENTITY_PASSED',
            'flash_authorized': False, 'image_sha256': self.hash('system_image'),
            'project_avb_public_key_sha256': 'd' * 64,
            'avbtool_sha256': '8' * 64, 'footer_version': '1.0',
            'image_size': 4096, 'original_image_size': 2048,
            'algorithm': 'SHA256_RSA4096', 'hashtree_root_digest': '9' * 64,
        }
        self.add_json('avb_report', self.avb)

    def add(self, role, data):
        path = self.root / role
        path.write_bytes(data)
        self.artifacts[role] = role

    def add_json(self, role, data):
        self.add(role, json.dumps(data, sort_keys=True).encode())

    def hash(self, role):
        return sha((self.root / self.artifacts[role]).read_bytes())

    def manifest(self):
        value = {'schema': AUDIT.SCHEMA, 'profile': self.profile,
                 'artifacts': {role: {'path': path, 'sha256': self.hash(role)}
                               for role, path in self.artifacts.items()}}
        write_json(self.root / 'bundle-manifest.json', value)
        return self.hash_manifest()

    def hash_manifest(self):
        return sha((self.root / 'bundle-manifest.json').read_bytes())

    def audit(self):
        return AUDIT.audit(self.root, self.manifest())

    def test_valid_binding_never_authorizes_flash(self):
        report = self.audit()
        self.assertEqual(report['status'], 'BUNDLE_INTEGRITY_BOUND')
        self.assertFalse(report['flash_authorized'])
        self.assertEqual(report['artifact_sha256']['system_image'], self.hash('system_image'))

    def test_manifest_requires_independently_supplied_digest(self):
        self.manifest()
        with self.assertRaisesRegex(AUDIT.AuditError, 'independently authenticated'):
            AUDIT.audit(self.root, '0' * 64)

    def test_artifact_substitution_is_blocked(self):
        trusted = self.manifest()
        (self.root / 'system_image').write_bytes(b'different image')
        with self.assertRaisesRegex(AUDIT.AuditError, 'authenticated manifest SHA256'):
            AUDIT.audit(self.root, trusted)

    def test_path_traversal_and_symlinks_are_blocked(self):
        self.manifest()
        manifest = json.loads((self.root / 'bundle-manifest.json').read_text())
        manifest['artifacts']['vendor_baseline']['path'] = '../outside'
        write_json(self.root / 'bundle-manifest.json', manifest)
        with self.assertRaisesRegex(AUDIT.AuditError, 'Unsafe artifact path'):
            AUDIT.audit(self.root, self.hash_manifest())
        self.manifest()
        vendor = self.root / 'vendor_baseline'
        vendor.rename(self.root / 'vendor_real')
        vendor.symlink_to('vendor_real')
        with self.assertRaises(OSError):
            AUDIT.audit(self.root, self.hash_manifest())

    def test_duplicate_json_keys_and_unknown_manifest_fields_are_blocked(self):
        self.manifest()
        path = self.root / 'bundle-manifest.json'
        path.write_text(path.read_text().replace('"schema":', '"schema":"other","schema":', 1))
        with self.assertRaisesRegex(AUDIT.AuditError, 'Duplicate JSON key'):
            AUDIT.audit(self.root, self.hash_manifest())
        self.manifest()
        manifest = json.loads(path.read_text())
        manifest['flash_authorized'] = True
        write_json(path, manifest)
        with self.assertRaisesRegex(AUDIT.AuditError, 'missing or unexpected fields'):
            AUDIT.audit(self.root, self.hash_manifest())

    def test_embedded_system_image_must_match_standalone_image(self):
        with zipfile.ZipFile(self.root / 'signed.zip', 'w') as archive:
            archive.writestr('IMAGES/system.img', b'other signed image')
        with self.assertRaisesRegex(AUDIT.AuditError, 'Standalone system image differs'):
            self.audit()

    def test_signed_report_bindings_and_flash_flag_are_checked(self):
        self.signer['policy_sha256'] = 'f' * 64
        self.add_json('signer_report', self.signer)
        with self.assertRaisesRegex(AUDIT.AuditError, 'policy_sha256 differs'):
            self.audit()
        self.signer['policy_sha256'] = self.hash('signing_policy')
        self.signer['flash_authorized'] = True
        self.add_json('signer_report', self.signer)
        with self.assertRaisesRegex(AUDIT.AuditError, 'Signer report is not a passing'):
            self.audit()

    def test_avb_report_must_name_the_same_signed_system_image(self):
        self.avb['image_sha256'] = 'f' * 64
        self.add_json('avb_report', self.avb)
        with self.assertRaisesRegex(AUDIT.AuditError, 'AVB report does not bind'):
            self.audit()

    def test_cli_writes_a_private_non_authorizing_report(self):
        manifest_sha = self.manifest()
        output = self.root / 'binding-result.json'
        with redirect_stdout(io.StringIO()):
            result = AUDIT.main(['--bundle-root', str(self.root),
                                 '--manifest-sha256', manifest_sha,
                                 '--output', str(output)])
        self.assertEqual(result, 0)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertFalse(json.loads(output.read_text())['flash_authorized'])

    def test_build_provenance_must_bind_unsigned_archive_and_receipt(self):
        path = self.root / 'build_provenance'
        provenance = json.loads(path.read_text())
        provenance['target_files_sha256'] = 'f' * 64
        self.add_json('build_provenance', provenance)
        with self.assertRaisesRegex(AUDIT.AuditError, 'Build provenance does not bind'):
            self.audit()

    def test_upgrade_requires_previous_report_hash(self):
        self.profile = 'upgrade'
        self.add_json('previous_signer_report', self.signer)
        self.signer['profile'] = 'upgrade'
        self.signer['status'] = 'UPGRADE_SIGNER_POLICY_PASSED'
        self.signer['previous_report_sha256'] = self.hash('previous_signer_report')
        self.add_json('signer_report', self.signer)
        self.assertEqual(self.audit()['profile'], 'upgrade')
        self.signer['previous_report_sha256'] = 'f' * 64
        self.add_json('signer_report', self.signer)
        with self.assertRaisesRegex(AUDIT.AuditError, 'previous signer report'):
            self.audit()


if __name__ == '__main__':
    unittest.main()
