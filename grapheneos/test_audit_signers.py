import copy
import dataclasses
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
import zipfile

SPEC = importlib.util.spec_from_file_location('mp01_graphene_signers', Path(__file__).with_name('audit-signers.py'))
AUDIT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AUDIT
SPEC.loader.exec_module(AUDIT)

CERT = 'b' * 64
VENDOR = 'd' * 64


def fixture():
    identities = [
        AUDIT.SIGNERS.Identity('apk', 'android', 'SYSTEM/framework/framework-res.apk', 'apk', '17', CERT, '-', '-', '0'),
        AUDIT.SIGNERS.Identity('apex', 'com.android.runtime', 'SYSTEM/apex/runtime.apex', 'apex', '4', CERT, CERT, 'c' * 64, '0')]
    policy = {'schema': 'mp01-signing-policy-v1', 'product': 'mp01', 'project_certificates': [CERT], 'packages': {}}
    for identity in identities:
        policy['packages'][identity.kind + ':' + identity.package] = {
            'authority': 'project', 'file_sha256': None,
            **{k: getattr(identity, k) for k in ['signer_cert_sha256', 'container_cert_sha256', 'payload_pubkey_sha256']}}
    build = {'product': 'mp01', 'variant': 'user', 'timestamp': '200', 'sdk': '37'}
    previous = {'schema': 'mp01-signer-profile-v2', 'profile': 'initial-installation',
                'status': 'INITIAL_SIGNER_POLICY_PASSED', 'vendor_baseline_sha256': VENDOR,
                'build': {**build, 'timestamp': '100'},
                'identities': [dataclasses.asdict(i) for i in identities]}
    return identities, policy, build, previous


class SignerProfileTests(unittest.TestCase):
    def setUp(self):
        self.identities, self.policy, self.build, self.previous = fixture()

    def check(self, profile='initial-installation', **overrides):
        args = dict(profile=profile, actual=self.identities, build=self.build,
                    vendor_baseline_sha256=VENDOR, policy=self.policy)
        if profile == 'upgrade':
            args['previous'] = self.previous
        args.update(overrides)
        return AUDIT.check_profile(**args)

    def test_development_has_no_initial_or_upgrade_eligibility(self):
        self.build['variant'] = 'userdebug'
        self.assertEqual(self.check('development', policy=None), 'DEVELOPMENT_ONLY')
        with self.assertRaises(AUDIT.SIGNERS.GateError):
            self.check('upgrade')

    def test_initial_install_uses_project_policy_without_lineage_baseline(self):
        self.assertEqual(self.check(), 'INITIAL_SIGNER_POLICY_PASSED')
        with self.assertRaises(AUDIT.SIGNERS.GateError):
            self.check(policy=None)

    def test_policy_must_cover_every_package_exactly(self):
        del self.policy['packages']['apex:com.android.runtime']
        with self.assertRaises(AUDIT.SIGNERS.GateError):
            self.check()

    def test_public_test_certificates_cannot_be_trusted_as_release_keys(self):
        test_cert = next(iter(json.loads((AUDIT.HERE / 'public-test-certificates.json').read_text()).values()))
        self.policy['project_certificates'] = [test_cert]
        with self.assertRaisesRegex(AUDIT.SIGNERS.GateError, 'test certificates'):
            self.check()

    def test_platform_cannot_be_marked_as_upstream_presigned(self):
        self.policy['packages']['apk:android']['authority'] = 'upstream-presigned'
        self.policy['packages']['apk:android']['file_sha256'] = 'a' * 64
        with self.assertRaises(AUDIT.SIGNERS.GateError):
            self.check(file_hashes={self.identities[0].source_path: 'a' * 64})

    def test_presigned_apk_bytes_are_verified(self):
        identity = AUDIT.SIGNERS.Identity('apk', 'app.example', 'SYSTEM/app/example.apk', 'apk', '9', 'e' * 64, '-', '-', '0')
        self.identities.append(identity)
        self.policy['packages']['apk:app.example'] = {'authority': 'upstream-presigned', 'file_sha256': 'f' * 64,
            'signer_cert_sha256': 'e' * 64, 'container_cert_sha256': '-', 'payload_pubkey_sha256': '-'}
        self.assertEqual(self.check(file_hashes={identity.source_path: 'f' * 64}), 'INITIAL_SIGNER_POLICY_PASSED')
        with self.assertRaisesRegex(AUDIT.SIGNERS.GateError, 'bytes'):
            self.check(file_hashes={identity.source_path: 'a' * 64})

    def test_upgrade_accepts_same_signers_and_advancing_build(self):
        self.assertEqual(self.check('upgrade'), 'UPGRADE_SIGNER_POLICY_PASSED')

    def test_upgrade_rejects_development_baseline(self):
        self.previous['profile'] = 'development'
        with self.assertRaises(AUDIT.SIGNERS.GateError):
            self.check('upgrade')

    def test_upgrade_rejects_changed_signer_even_if_new_policy_accepts_it(self):
        self.previous['identities'][0]['signer_cert_sha256'] = 'a' * 64
        with self.assertRaisesRegex(AUDIT.SIGNERS.GateError, 'installed signer'):
            self.check('upgrade')

    def test_upgrade_rejects_package_downgrade(self):
        self.previous['identities'][0]['version_code'] = '18'
        with self.assertRaisesRegex(AUDIT.SIGNERS.GateError, 'downgrade'):
            self.check('upgrade')

    def test_upgrade_compares_combined_major_and_minor_version(self):
        self.previous['identities'][0]['version_code_major'] = '2'
        self.identities[0] = dataclasses.replace(
            self.identities[0], version_code='99', version_code_major='1'
        )
        with self.assertRaisesRegex(AUDIT.SIGNERS.GateError, 'downgrade'):
            self.check('upgrade')

        self.identities[0] = dataclasses.replace(
            self.identities[0], version_code='1', version_code_major='3'
        )
        self.assertEqual(self.check('upgrade'), 'UPGRADE_SIGNER_POLICY_PASSED')

    def test_upgrade_rejects_baseline_without_major_version_evidence(self):
        self.previous['schema'] = 'mp01-signer-profile-v1'
        with self.assertRaisesRegex(AUDIT.SIGNERS.GateError, 'v2 report'):
            self.check('upgrade')

        self.previous['schema'] = 'mp01-signer-profile-v2'
        del self.previous['identities'][0]['version_code_major']
        with self.assertRaisesRegex(AUDIT.SIGNERS.GateError, 'version information'):
            self.check('upgrade')

    def test_release_rejects_unknown_or_signed_major_version(self):
        self.identities[0] = dataclasses.replace(
            self.identities[0], version_code_major='-'
        )
        with self.assertRaisesRegex(AUDIT.SIGNERS.GateError, 'versionCodeMajor'):
            self.check()
        self.identities[0] = dataclasses.replace(
            self.identities[0], version_code_major=str(1 << 31)
        )
        with self.assertRaisesRegex(AUDIT.SIGNERS.GateError, 'sign bit'):
            self.check()

    def test_upgrade_rejects_conflicting_versions_in_duplicate_apks(self):
        duplicate = dataclasses.replace(
            self.identities[0],
            source_path='PRODUCT/framework/framework-res.apk',
            version_code='16',
        )
        self.identities.append(duplicate)
        with self.assertRaisesRegex(AUDIT.SIGNERS.GateError, 'conflicting APK versions'):
            self.check('upgrade')

        self.identities.pop()
        self.previous['identities'].append(dataclasses.asdict(duplicate))
        with self.assertRaisesRegex(AUDIT.SIGNERS.GateError, 'conflicting APK versions'):
            self.check('upgrade')

    def test_upgrade_rejects_conflicting_major_in_duplicate_apks(self):
        duplicate = dataclasses.replace(
            self.identities[0],
            source_path='PRODUCT/framework/framework-res.apk',
            version_code_major='1',
        )
        self.identities.append(duplicate)
        with self.assertRaisesRegex(AUDIT.SIGNERS.GateError, 'conflicting APK major versions'):
            self.check('upgrade')

    def test_upgrade_rejects_sdk_and_timestamp_downgrades(self):
        for field, value in [('timestamp', '100'), ('sdk', '36')]:
            with self.subTest(field=field), self.assertRaises(AUDIT.SIGNERS.GateError):
                self.check('upgrade', build={**self.build, field: value})

    def test_upgrade_rejects_vendor_changes_and_missing_baseline(self):
        with self.assertRaises(AUDIT.SIGNERS.GateError):
            self.check('upgrade', vendor_baseline_sha256='a' * 64)
        with self.assertRaises(AUDIT.SIGNERS.GateError):
            self.check('upgrade', previous=None)

    def test_trusted_policy_hash_mismatch_and_duplicate_keys_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'policy.json'
            path.write_text('{"key": 1, "key": 2}')
            for digest in ['a' * 64, AUDIT.SIGNERS.sha256_file(path)]:
                with self.subTest(digest=digest), self.assertRaises(AUDIT.SIGNERS.GateError):
                    AUDIT.pinned_json(path, digest)

    def test_archive_metadata_reads_image_and_properties(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'target.zip'
            with zipfile.ZipFile(path, 'w') as z:
                z.writestr('SYSTEM/build.prop', 'ro.product.system.device=mp01\nro.build.type=user\nro.build.date.utc=200\nro.build.version.sdk=37\n')
                z.writestr('IMAGES/system.img', b'image bytes')
                for identity in self.identities:
                    z.writestr(identity.source_path, b'fixture package')
            build, hashes = AUDIT.archive_metadata(path, self.identities)
            self.assertEqual(build, self.build)
            self.assertEqual(hashes['IMAGES/system.img'], AUDIT.hashlib.sha256(b'image bytes').hexdigest())


if __name__ == '__main__':
    unittest.main()
