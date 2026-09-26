import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location('mp01_graphene_avb', Path(__file__).with_name('audit-avb.py'))
AUDIT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AUDIT
SPEC.loader.exec_module(AUDIT)
SOURCE_AVB = Path(__file__).resolve().parents[2] / '.android-build/grapheneos-17/external/avb'


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class AvbMetadataTests(unittest.TestCase):
    GOOD = '''Footer version: 1.0
Image size: 262144 bytes
Original image size: 65536 bytes
Algorithm: SHA256_RSA2048
Flags: 0
Descriptors:
    Hashtree descriptor:
      Tree Size: 4096 bytes
      Hash Algorithm: sha256
      Partition Name: system
      Root Digest: 1111111111111111111111111111111111111111111111111111111111111111
      Flags: 0
'''

    def test_requires_footer_and_system_hashtree(self):
        self.assertEqual(AUDIT.parse_avb_info(self.GOOD)['algorithm'], 'SHA256_RSA2048')
        for altered in [self.GOOD.replace('Footer version:', 'No footer:'),
                        self.GOOD.replace('Hashtree descriptor:', 'Hash descriptor:'),
                        self.GOOD.replace('Partition Name: system', 'Partition Name: vendor'),
                        self.GOOD.replace('Flags: 0', 'Flags: 1', 1),
                        self.GOOD.replace('Root Digest: ' + '1' * 64, 'Root Digest: '),
                        self.GOOD.replace('Algorithm: SHA256_RSA2048', 'Algorithm: NONE')]:
            with self.subTest(altered=altered), self.assertRaises(AUDIT.SNAPSHOT.GateError):
                AUDIT.parse_avb_info(altered)


class AvbIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.avbtool = SOURCE_AVB / 'avbtool.py'
        if not cls.avbtool.is_file() or shutil.which('openssl') is None:
            raise unittest.SkipTest('Signed AVB fixtures need prepared source and openssl')
        cls.testkey = SOURCE_AVB / 'test/data/testkey_rsa2048.pem'

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='mp01-avb-fixture-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.key = self.root / 'throwaway-fixture.pem'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA',
                        '-pkeyopt', 'rsa_keygen_bits:2048', '-out', str(self.key)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.image = self.root / 'signed-system.img'
        self.key_sha = self.make_image(self.image, self.key)
        self.tool_sha = sha256(self.avbtool)

    def avb(self, *args):
        subprocess.run([sys.executable, str(self.avbtool), *map(str, args)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    def make_image(self, image, key, *extra):
        pubkey = image.with_suffix('.avbpubkey')
        self.avb('generate_test_image', '--image_size', '65536', '--output', image)
        self.avb('add_hashtree_footer', '--image', image, '--partition_size', '262144',
                 '--partition_name', 'system', '--hash_algorithm', 'sha256',
                 '--salt', '11' * 32, '--algorithm', 'SHA256_RSA2048',
                 '--key', key, '--do_not_generate_fec', *extra)
        self.avb('extract_public_key', '--key', key, '--output', pubkey)
        return sha256(pubkey)

    def audit(self, image=None, image_sha=None, key_sha=None, tool_sha=None):
        image = image or self.image
        return AUDIT.audit(image, image_sha or sha256(image), key_sha or self.key_sha,
                           self.avbtool, tool_sha or self.tool_sha)

    def test_signed_hashtree_and_project_key_are_verified_without_flash_authorization(self):
        report = self.audit()
        self.assertEqual(report['status'], 'AVB_IMAGE_IDENTITY_PASSED')
        self.assertFalse(report['flash_authorized'])
        self.assertEqual(report['image_sha256'], sha256(self.image))
        self.assertEqual(report['project_avb_public_key_sha256'], self.key_sha)
        output = self.root / 'avb-report.json'
        args = ['--image', str(self.image), '--image-sha256', sha256(self.image),
                '--expected-public-key-sha256', self.key_sha, '--avbtool', str(self.avbtool),
                '--avbtool-sha256', self.tool_sha, '--output', str(output)]
        self.assertEqual(AUDIT.main(args), 0)
        self.assertFalse(json.loads(output.read_text())['flash_authorized'])
        self.assertEqual(AUDIT.main(args), 2)

    def test_rejects_wrong_image_tool_and_project_key_hashes(self):
        for override in [{'image_sha': 'a' * 64}, {'tool_sha': 'b' * 64},
                         {'key_sha': 'c' * 64}]:
            with self.subTest(override=override), self.assertRaises(AUDIT.SNAPSHOT.GateError):
                self.audit(**override)

    def test_rejects_missing_footer_and_tampered_hashtree(self):
        raw = self.root / 'raw.img'
        raw.write_bytes(b'0' * 4096)
        with self.assertRaises(AUDIT.SNAPSHOT.GateError):
            self.audit(image=raw)
        with self.image.open('r+b') as image:
            image.seek(0)
            image.write(b'corrupt')
        with self.assertRaisesRegex(AUDIT.SNAPSHOT.GateError, 'verify_image failed'):
            self.audit()

    def test_rejects_disabled_hashtree_and_public_test_key(self):
        disabled = self.root / 'disabled.img'
        self.make_image(disabled, self.key, '--set_hashtree_disabled_flag')
        with self.assertRaisesRegex(AUDIT.SNAPSHOT.GateError, 'flags must be zero'):
            self.audit(image=disabled)
        if not self.testkey.is_file():
            self.skipTest('Upstream AVB test key is absent')
        public_image = self.root / 'public-test.img'
        public_sha = self.make_image(public_image, self.testkey)
        self.assertIn(public_sha, AUDIT.PUBLIC_TEST_AVB_KEYS)
        with self.assertRaisesRegex(AUDIT.SNAPSHOT.GateError, 'public AVB test key'):
            self.audit(image=public_image, key_sha=public_sha)
        with self.assertRaisesRegex(AUDIT.SNAPSHOT.GateError, 'uses a public AVB test key'):
            self.audit(image=public_image)


if __name__ == '__main__':
    unittest.main()
