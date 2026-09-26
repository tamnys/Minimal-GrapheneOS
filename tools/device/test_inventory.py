import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('mp01_inventory', Path(__file__).with_name('inventory.py'))
INVENTORY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = INVENTORY
SPEC.loader.exec_module(INVENTORY)


class DeviceInventoryTests(unittest.TestCase):
    def identity_result(self, model):
        return subprocess.CompletedProcess([], 0, (model + '\n').encode(), b'')

    def test_pixel_and_generic_mediatek_identity_rejected_before_capture(self):
        for model in ['Pixel 8a', 'AOSP on ARM64', 'MT6789', '']:
            with self.subTest(model=model), tempfile.TemporaryDirectory() as tmp, \
                 mock.patch.object(INVENTORY, 'run', return_value=self.identity_result(model)) as run:
                output = Path(tmp) / 'capture'
                with self.assertRaises(INVENTORY.InventoryError):
                    INVENTORY.collect(Path('/adb'), 'selected-serial', output)
                self.assertFalse(output.exists())
                self.assertTrue(all(c.args[2][:2] == ['shell', 'getprop'] for c in run.call_args_list))

    def test_model_match_does_not_allow_missing_vendor_identity(self):
        results = [self.identity_result(''), self.identity_result('MP01'), self.identity_result('Minimal')]
        with mock.patch.object(INVENTORY, 'run', side_effect=results):
            with self.assertRaises(INVENTORY.InventoryError):
                INVENTORY.identify(Path('/adb'), 'serial')

    def test_valid_identity_is_accepted(self):
        results = [self.identity_result('MP01'), self.identity_result('MP01'), self.identity_result('Minimal')]
        with mock.patch.object(INVENTORY, 'run', side_effect=results):
            self.assertEqual(INVENTORY.identify(Path('/adb'), 'serial')['ro.product.vendor.model'], 'MP01')

    def test_serial_is_never_remote_shell_text(self):
        with mock.patch.object(INVENTORY.subprocess, 'run') as run:
            INVENTORY.run('/adb', 'specific-serial', ['shell', 'getprop', 'ro.product.model'])
            self.assertEqual(run.call_args.args[0], ['/adb', '-s', 'specific-serial', 'shell', 'getprop', 'ro.product.model'])
        with self.assertRaises(INVENTORY.InventoryError):
            INVENTORY.identify('/adb', 'serial; reboot')

    def test_successful_capture_keeps_evidence_private_and_needs_review(self):
        def read_only_result(adb, serial, arguments):
            if arguments[:2] == ['shell', 'getprop']:
                value = 'MP01' if arguments[2] == 'ro.product.vendor.model' else 'observed'
                return subprocess.CompletedProcess([], 0, (value + '\n').encode(), b'')
            return subprocess.CompletedProcess([], 0, b'observed\n', b'')

        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(INVENTORY, 'run', side_effect=read_only_result) as run:
            output = Path(tmp) / 'capture'
            report_path = INVENTORY.collect(Path('/adb'), 'selected-serial', output)
            report = json.loads(report_path.read_text())
            self.assertEqual(report['schema'], 'mp01-device-inventory-v1')
            self.assertEqual(report['status'], 'CAPTURED_REQUIRES_REVIEW')
            self.assertEqual(report['identity']['ro.product.vendor.model'], 'MP01')
            self.assertEqual([target['carrier'] for target in report['cellular_test_targets']],
                             ['AT&T', 'T-Mobile'])
            self.assertEqual(os.stat(output).st_mode & 0o777, 0o700)
            self.assertTrue(all(os.stat(path).st_mode & 0o777 == 0o600
                                for path in output.iterdir()))
            self.assertTrue(all(call.args[2][0] in {'shell', 'exec-out'}
                                for call in run.call_args_list))


if __name__ == '__main__':
    unittest.main()
