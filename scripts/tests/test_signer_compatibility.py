import gzip
import hashlib
import io
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock
import warnings
import zipfile

from scripts import signer_compatibility as gate


APK_CERT = "1" * 64
APEX_CERT = "2" * 64
OTHER_CERT = "3" * 64
PUBKEY_SHA = "4" * 64
ARCHIVE_SHA = "5" * 64
IMAGE_SHA = "6" * 64


def identity(
    kind="apk",
    package="com.example.app",
    source_path="SYSTEM/app/Example/Example.apk",
    format_name="apk",
    version="1",
    major="0",
    signer=APK_CERT,
    container="-",
    payload="-",
):
    return gate.Identity(
        kind,
        package,
        source_path,
        format_name,
        version,
        signer,
        container,
        payload,
        major,
    )


def manifest(identities, apk_coverage="complete", apex_coverage="complete"):
    return gate.Manifest(
        {
            "apk_coverage": apk_coverage,
            "apex_coverage": apex_coverage,
            "baseline_archive_sha256": ARCHIVE_SHA,
            "baseline_image_sha256": IMAGE_SHA,
            "baseline_apk_inventory_sha256": "7" * 64,
            "baseline_apex_inventory_sha256": "8" * 64,
        },
        tuple(sorted(identities, key=lambda item: item.row_key)),
    )


def signer_output(certificate):
    return (
        "Verifies\n"
        "Number of signers: 1\n"
        f"Signer #1 certificate SHA-256 digest: {certificate}\n"
    )


class ManifestTest(unittest.TestCase):
    def test_round_trip_is_deterministic(self):
        original = manifest(
            [
                identity(),
                identity(
                    kind="apex",
                    package="com.android.example",
                    source_path="SYSTEM/apex/com.android.example.capex",
                    format_name="capex",
                    signer=APEX_CERT,
                    container=APEX_CERT,
                    payload=PUBKEY_SHA,
                ),
            ],
            apk_coverage="partial",
        )
        serialized = gate.serialize_manifest(original)
        self.assertEqual(gate.serialize_manifest(gate.parse_manifest_bytes(serialized)), serialized)
        self.assertIn(b"version_code_major\n", serialized)

    def test_legacy_manifest_remains_readable_without_inventing_major(self):
        current = gate.serialize_manifest(manifest([identity(version="42", major="2")]))
        legacy = current.replace(
            gate.FORMAT_MARKER.encode(), gate.LEGACY_FORMAT_MARKER.encode(), 1
        ).replace(
            "\t".join(gate.COLUMNS).encode(),
            "\t".join(gate.LEGACY_COLUMNS).encode(),
            1,
        ).replace(b"\t2\n", b"\n", 1)
        parsed = gate.parse_manifest_bytes(legacy)
        self.assertEqual(parsed.identities[0].version_code, "42")
        self.assertEqual(parsed.identities[0].version_code_major, "-")

    def test_v2_manifest_rejects_invalid_major(self):
        valid = gate.serialize_manifest(manifest([identity()]))
        with self.assertRaisesRegex(gate.GateError, "major version code"):
            gate.parse_manifest_bytes(valid.replace(b"\t0\n", b"\tunknown\n", 1))

    def test_rejects_duplicate_and_unsorted_identity_rows(self):
        row = "\t".join(identity().values())
        raw = (
            gate.FORMAT_MARKER
            + "\n# apex_coverage=complete"
            + "\n# apk_coverage=complete"
            + f"\n# baseline_archive_sha256={ARCHIVE_SHA}"
            + f"\n# baseline_apex_inventory_sha256={'8' * 64}"
            + f"\n# baseline_apk_inventory_sha256={'7' * 64}"
            + f"\n# baseline_image_sha256={IMAGE_SHA}"
            + "\n"
            + "\t".join(gate.COLUMNS)
            + "\n"
            + row
            + "\n"
            + row
            + "\n"
        ).encode()
        with self.assertRaisesRegex(gate.GateError, "duplicate identity"):
            gate.parse_manifest_bytes(raw)

    def test_allows_same_apk_package_at_two_paths_with_one_signer(self):
        first = identity()
        second = identity(source_path="PRODUCT/overlay/ExampleOverlay.apk")
        original = manifest([first, second])
        parsed = gate.parse_manifest_bytes(gate.serialize_manifest(original))
        self.assertEqual(len(parsed.identities), 2)

    def test_rejects_same_apk_package_with_conflicting_signers(self):
        first = identity()
        second = identity(
            source_path="PRODUCT/overlay/ExampleOverlay.apk", signer=OTHER_CERT
        )
        with self.assertRaisesRegex(gate.GateError, "conflicting APK signers"):
            gate.parse_manifest_bytes(gate.serialize_manifest(manifest([first, second])))

    def test_rejects_same_apk_package_with_conflicting_versions(self):
        first = identity(version="18")
        second = identity(
            source_path="PRODUCT/overlay/ExampleOverlay.apk", version="17"
        )
        with self.assertRaisesRegex(gate.GateError, "conflicting APK versions"):
            gate.serialize_manifest(manifest([first, second]))

    def test_rejects_same_apk_package_with_conflicting_major_versions(self):
        first = identity(version="42", major="2")
        second = identity(
            source_path="PRODUCT/overlay/ExampleOverlay.apk", version="42", major="1"
        )
        with self.assertRaisesRegex(gate.GateError, "conflicting APK major versions"):
            gate.serialize_manifest(manifest([first, second]))

    def test_expected_manifest_hash_is_independent_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "expected.tsv"
            path.write_bytes(gate.serialize_manifest(manifest([identity()])))
            with self.assertRaisesRegex(gate.GateError, "SHA256 mismatch"):
                gate.load_expected_manifest(path, "0" * 64)


class ComparisonTest(unittest.TestCase):
    def setUp(self):
        self.apk = identity()
        self.apex = identity(
            kind="apex",
            package="com.android.example",
            source_path="SYSTEM/apex/com.android.example.apex",
            format_name="apex",
            signer=APEX_CERT,
            container=APEX_CERT,
            payload=PUBKEY_SHA,
        )

    def test_exact_complete_match_passes(self):
        expected = manifest([self.apk, self.apex])
        actual = manifest([self.apex, self.apk])
        self.assertEqual(gate.compare_manifests(expected, actual, "release-candidate"), ())

    def test_partial_manifest_blocks_release_candidate(self):
        expected = manifest([self.apk, self.apex], apk_coverage="partial")
        actual = manifest([self.apk, self.apex])
        issues = gate.compare_manifests(expected, actual, "release-candidate")
        self.assertIn("expected_coverage_partial", {issue.code for issue in issues})
        self.assertTrue(all(issue.severity == "incompatibility" for issue in issues))

    def test_partial_manifest_is_explicit_warning_in_test_key_audit(self):
        new_apk = identity(package="com.example.new", source_path="SYSTEM/app/New/New.apk")
        expected = manifest([self.apk, self.apex], apk_coverage="partial")
        actual = manifest([self.apk, self.apex, new_apk])
        issues = gate.compare_manifests(expected, actual, "test-key-audit")
        self.assertEqual(
            {issue.code for issue in issues},
            {"expected_coverage_partial", "unconstrained_candidate_package"},
        )
        self.assertTrue(all(issue.severity == "warning" for issue in issues))

    def test_cert_and_payload_mismatches_are_incompatible(self):
        changed = gate.Identity(
            **{
                **dict(zip(gate.COLUMNS, self.apex.values())),
                "signer_cert_sha256": OTHER_CERT,
                "container_cert_sha256": OTHER_CERT,
                "payload_pubkey_sha256": "7" * 64,
            }
        )
        issues = gate.compare_manifests(
            manifest([self.apex]), manifest([changed]), "test-key-audit"
        )
        self.assertEqual(
            {issue.code for issue in issues},
            {
                "signer_cert_sha256_mismatch",
                "container_cert_sha256_mismatch",
                "payload_pubkey_sha256_mismatch",
            },
        )
        self.assertTrue(all(issue.severity == "incompatibility" for issue in issues))

    def test_missing_and_unexpected_complete_packages_are_incompatible(self):
        replacement = identity(package="com.example.replacement")
        issues = gate.compare_manifests(
            manifest([self.apk]), manifest([replacement]), "release-candidate"
        )
        self.assertEqual(
            {issue.code for issue in issues},
            {"missing_candidate_package", "unexpected_candidate_package"},
        )

    def test_evidence_is_sorted_and_test_key_is_never_flashable(self):
        expected = manifest([self.apk])
        actual = manifest([self.apk])
        evidence = gate.render_evidence(
            "test-key-audit",
            "8" * 64,
            "9" * 64,
            expected,
            "a" * 64,
            actual,
            (),
            ("b" * 64, "c" * 64),
        ).decode()
        self.assertIn("comparison_status=COMPATIBLE_SIGNER_IDENTITIES\n", evidence)
        self.assertIn("flash_disposition=NOT_FOR_IN_PLACE_FLASH\n", evidence)
        self.assertIn("apksigner_execution=direct_java_jar\n", evidence)
        self.assertIn(f"apksigner_java_sha256={'b' * 64}\n", evidence)
        self.assertIn(f"apksigner_jar_sha256={'c' * 64}\n", evidence)


class ArchiveTest(unittest.TestCase):
    def setUp(self):
        self.tools = gate.Tools(
            Path("/tools/apksigner"),
            Path("/tools/aapt2"),
            Path("/tools/deapexer"),
            Path("/tools/avbtool"),
        )

    def write_capex(self, root, wrapper_pubkey=b"public-key", inner_pubkey=None):
        if inner_pubkey is None:
            inner_pubkey = wrapper_pubkey
        inner_bytes = io.BytesIO()
        with zipfile.ZipFile(inner_bytes, "w") as inner:
            inner.writestr("AndroidManifest.xml", b"manifest")
            inner.writestr("apex_manifest.pb", b"manifest-pb")
            inner.writestr("apex_pubkey", inner_pubkey)
            inner.writestr("apex_payload.img", b"signed-payload")
        capex = root / "example.capex"
        with zipfile.ZipFile(capex, "w") as wrapper:
            wrapper.writestr("AndroidManifest.xml", b"wrapper-manifest")
            wrapper.writestr("apex_manifest.pb", b"wrapper-manifest-pb")
            wrapper.writestr("apex_pubkey", wrapper_pubkey)
            wrapper.writestr("original_apex", inner_bytes.getvalue())
        return capex

    def command_mock(self, pubkey=b"public-key", inner_certificate=APEX_CERT):
        def command(arguments, label, **kwargs):
            if "--print-type" in arguments:
                return "COMPRESSED\n"
            if "decompress" in arguments:
                source = Path(arguments[arguments.index("--input") + 1])
                destination = Path(arguments[arguments.index("--output") + 1])
                with zipfile.ZipFile(source) as archive:
                    payload = archive.read("original_apex")
                self.assertEqual(kwargs["output_file_limit"], len(payload))
                self.assertEqual(kwargs["temporary_directory"], destination.parent)
                destination.write_bytes(payload)
                return ""
            if arguments[0].endswith("apksigner"):
                certificate = (
                    inner_certificate if "installable APEX" in label else APEX_CERT
                )
                return signer_output(certificate)
            if arguments[0].endswith("aapt2"):
                if "xmltree" in arguments:
                    return (
                        "    E: manifest (line=2)\n"
                        "      A: http://schemas.android.com/apk/res/android:versionCode(0x0101021b)=42\n"
                        '      A: package="com.android.example" (Raw: "com.android.example")\n'
                    )
                return "package: name='com.android.example' versionCode='42'\n"
            if "verify_image" in arguments:
                return "Verifying image using embedded public key\n"
            if "info_image" in arguments:
                output = Path(arguments[arguments.index("--output_pubkey") + 1])
                output.write_bytes(pubkey)
                return "Footer version: 1.0\n"
            self.fail(f"unexpected command: {arguments}")

        return command

    def test_capex_validates_wrapper_inner_and_payload_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capex = self.write_capex(root)
            work = root / "work"
            work.mkdir()
            with mock.patch.object(gate, "run_command", self.command_mock()):
                found = gate.inspect_apex(
                    capex, "SYSTEM/apex/com.android.example.capex", self.tools, work
                )
        self.assertEqual(found.package, "com.android.example")
        self.assertEqual(found.signer_cert_sha256, APEX_CERT)
        self.assertEqual(found.container_cert_sha256, APEX_CERT)
        self.assertEqual(
            found.payload_pubkey_sha256, hashlib.sha256(b"public-key").hexdigest()
        )

    def test_capex_rejects_wrapper_and_inner_certificate_mismatch(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capex = self.write_capex(root)
            work = root / "work"
            work.mkdir()
            command = self.command_mock(inner_certificate=OTHER_CERT)
            with mock.patch.object(gate, "run_command", command):
                with self.assertRaisesRegex(gate.GateError, "container signers differ"):
                    gate.inspect_apex(
                        capex, "SYSTEM/apex/com.android.example.capex", self.tools, work
                    )

    def test_capex_rejects_payload_key_not_bound_by_avb(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capex = self.write_capex(root)
            work = root / "work"
            work.mkdir()
            with mock.patch.object(
                gate, "run_command", self.command_mock(pubkey=b"different-key")
            ):
                with self.assertRaisesRegex(gate.GateError, "payload signing key"):
                    gate.inspect_apex(
                        capex, "SYSTEM/apex/com.android.example.capex", self.tools, work
                    )

    def test_oversized_original_apex_is_rejected_before_decompression(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capex = root / "oversized.capex"
            with zipfile.ZipFile(capex, "w", compression=zipfile.ZIP_DEFLATED) as wrapper:
                wrapper.writestr("original_apex", b"x" * 4096)
            self.assertLess(capex.stat().st_size, 1024)
            work = root / "work"
            work.mkdir()

            def command(arguments, _label, **_kwargs):
                if "--print-type" in arguments:
                    return "COMPRESSED\n"
                self.fail("a tool ran after oversized original_apex metadata")

            with mock.patch.object(gate, "MAX_APEX_SIZE", 1024), mock.patch.object(
                gate, "run_command", side_effect=command
            ):
                with self.assertRaisesRegex(gate.GateError, "original_apex.*metadata"):
                    gate.inspect_apex(capex, "SYSTEM/apex/oversized.capex", self.tools, work)

    def test_deapexer_output_must_match_declared_inner_size(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            capex = self.write_capex(root)
            work = root / "work"
            work.mkdir()
            normal = self.command_mock()

            def command(arguments, label, **kwargs):
                if "decompress" in arguments:
                    output = Path(arguments[arguments.index("--output") + 1])
                    output.write_bytes(b"x" * (kwargs["output_file_limit"] + 1))
                    return ""
                return normal(arguments, label, **kwargs)

            with mock.patch.object(gate, "run_command", side_effect=command):
                with self.assertRaisesRegex(gate.GateError, "invalid APEX size"):
                    gate.inspect_apex(capex, "SYSTEM/apex/example.capex", self.tools, work)

    def test_duplicate_target_files_member_fails_before_tooling(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "target-files.zip"
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                with zipfile.ZipFile(archive_path, "w") as archive:
                    archive.writestr("SYSTEM/app/A/A.apk", b"one")
                    archive.writestr("SYSTEM/app/A/A.apk", b"two")
            with self.assertRaisesRegex(gate.GateError, "duplicate signable"):
                gate.inventory_target_files(archive_path, self.tools)

    def test_unsafe_signable_target_files_path_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "target-files.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("SYSTEM/../escape.apk", b"not-an-apk")
            with self.assertRaisesRegex(gate.GateError, "is unsafe"):
                gate.inventory_target_files(archive_path, self.tools)

    def fake_apk_identity(self, path, source_path, tools, archive_format="apk"):
        package_suffix = hashlib.sha256(source_path.encode("ascii")).hexdigest()[:12]
        return identity(
            package=f"com.example.p{package_suffix}",
            source_path=source_path,
            format_name=archive_format,
        )

    def test_signables_at_data_and_root_paths_are_not_ignored(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "target-files.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("DATA/app/Data.apk", b"data-apk")
                archive.writestr("Root.apk", b"root-apk")
            with mock.patch.object(
                gate, "inspect_apk", side_effect=self.fake_apk_identity
            ):
                found = gate.inventory_target_files(archive_path, self.tools)
        self.assertEqual(
            {item.source_path for item in found}, {"DATA/app/Data.apk", "Root.apk"}
        )

    def test_each_extracted_package_is_removed_before_the_next(self):
        earlier_path = None

        def inspect(path, source_path, tools, archive_format="apk"):
            nonlocal earlier_path
            if earlier_path is not None:
                self.assertFalse(earlier_path.exists())
            earlier_path = path
            return self.fake_apk_identity(path, source_path, tools, archive_format)

        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "target-files.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("SYSTEM/app/First.apk", b"first")
                archive.writestr("SYSTEM/app/Second.apk", b"second")
            with mock.patch.object(gate, "inspect_apk", side_effect=inspect):
                self.assertEqual(len(gate.inventory_target_files(archive_path, self.tools)), 2)
            self.assertFalse(earlier_path.exists())

    def test_gzip_apk_is_bounded_decompressed_and_inventoried(self):
        inspected = []

        def inspect(path, source_path, tools, archive_format="apk"):
            inspected.append((path.read_bytes(), source_path, archive_format))
            return self.fake_apk_identity(path, source_path, tools, archive_format)

        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "target-files.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("DATA/app/Packed.apk.gz", gzip.compress(b"apk-payload"))
            with mock.patch.object(gate, "inspect_apk", side_effect=inspect):
                found = gate.inventory_target_files(archive_path, self.tools)
        self.assertEqual(
            inspected, [(b"apk-payload", "DATA/app/Packed.apk.gz", "apk.gz")]
        )
        self.assertEqual(found[0].format, "apk.gz")

    def test_gzip_apk_decompression_limit_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            compressed = root / "app.apk.gz"
            output = root / "app.apk"
            compressed.write_bytes(gzip.compress(b"too-large"))
            with mock.patch.object(gate, "MAX_APK_SIZE", 4):
                with self.assertRaisesRegex(gate.GateError, "exceeds size limit"):
                    gate._decompress_gzip_apk(compressed, output, "app.apk.gz")
            self.assertFalse(output.exists())

    def test_unsupported_compressed_apex_is_not_silently_ignored(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "target-files.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("DATA/apex/Module.apex.gz", gzip.compress(b"apex"))
            with self.assertRaisesRegex(gate.GateError, "unsupported gzip"):
                gate.inventory_target_files(archive_path, self.tools)

    def test_non_ascii_and_control_paths_fail_before_tooling(self):
        hostile_paths = (
            "DATA/app/nonascii-\N{LATIN SMALL LETTER E WITH ACUTE}.apk",
            "DATA/app/tab\tinject.apk",
        )
        for hostile_path in hostile_paths:
            with self.subTest(
                path=hostile_path
            ), tempfile.TemporaryDirectory() as temporary:
                archive_path = Path(temporary) / "target-files.zip"
                with zipfile.ZipFile(archive_path, "w") as archive:
                    archive.writestr(hostile_path, b"not-inspected")
                with self.assertRaises(gate.GateError):
                    gate.inventory_target_files(archive_path, self.tools)

    def test_target_derived_identity_is_validated_before_serialization(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "target-files.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("DATA/app/Valid.apk", b"apk")
            poisoned = identity(source_path="DATA/app/Valid.apk\tinjected")
            with mock.patch.object(gate, "inspect_apk", return_value=poisoned):
                with self.assertRaisesRegex(gate.GateError, "control character"):
                    gate.inventory_target_files(archive_path, self.tools)

    def test_signable_entry_count_limit_fails_before_tooling(self):
        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "target-files.zip"
            with zipfile.ZipFile(archive_path, "w") as archive:
                archive.writestr("DATA/app/One.apk", b"one")
                archive.writestr("DATA/app/Two.apk", b"two")
            with mock.patch.object(gate, "MAX_SIGNABLE_ENTRY_COUNT", 1):
                with self.assertRaisesRegex(gate.GateError, "too many signable"):
                    gate.inventory_target_files(archive_path, self.tools)

    def test_empty_version_code_is_normalized_for_provenance(self):
        with mock.patch.object(
            gate,
            "run_command",
            return_value="package: name='android.ext.shared' versionCode=''\n",
        ):
            package, version = gate.package_badging(
                self.tools.aapt2, Path("example.apk"), "example badging"
            )
        self.assertEqual(package, "android.ext.shared")
        self.assertEqual(version, "-")


class PackageVersionTest(unittest.TestCase):
    AAPT2 = Path("/tools/aapt2")
    APK = Path("example.apk")

    def xmltree(self, code="42", major=None, extra=""):
        lines = [
            "    E: manifest (line=2)",
            f"      A: http://schemas.android.com/apk/res/android:versionCode(0x0101021b)={code}",
            '      A: package="com.example.app" (Raw: "com.example.app")',
        ]
        if major is not None:
            lines.append(
                "      A: http://schemas.android.com/apk/res/android:versionCodeMajor(0x01010576)="
                + major
            )
        if extra:
            lines.append(extra)
        return "\n".join(lines) + "\n"

    def version(self, xmltree, badging="package: name='com.example.app' versionCode='42'\n"):
        def command(arguments, _label):
            return xmltree if "xmltree" in arguments else badging

        with mock.patch.object(gate, "run_command", side_effect=command):
            return gate.package_version(self.AAPT2, self.APK, "example APK")

    def test_reads_major_from_compiled_manifest_when_badging_omits_it(self):
        self.assertEqual(self.version(self.xmltree(major="2")), ("com.example.app", "42", "2"))
        self.assertEqual(self.version(self.xmltree()), ("com.example.app", "42", "0"))

    def test_handles_signed_and_hex_32_bit_manifest_values(self):
        badging = "package: name='com.example.app' versionCode='-1'\n"
        self.assertEqual(
            self.version(self.xmltree(code="0xffffffff", major="0x00000002"), badging),
            ("com.example.app", "4294967295", "2"),
        )
        self.assertEqual(
            self.version(self.xmltree(major='2 (Raw: "2")')),
            ("com.example.app", "42", "2"),
        )

    def test_empty_badging_code_does_not_override_manifest_code(self):
        badging = "package: name='com.example.app' versionCode=''\n"
        self.assertEqual(
            self.version(self.xmltree(code="0"), badging),
            ("com.example.app", "0", "0"),
        )

    def test_rejects_mismatch_duplicate_and_unresolved_manifest_values(self):
        with self.assertRaisesRegex(gate.GateError, "badging and manifest"):
            self.version(self.xmltree(code="43"))
        with self.assertRaisesRegex(gate.GateError, "duplicate manifest attributes"):
            self.version(self.xmltree(major="2", extra=(
                "      A: http://schemas.android.com/apk/res/android:versionCodeMajor(0x01010576)=3"
            )))
        with self.assertRaisesRegex(gate.GateError, "malformed compiled manifest"):
            self.version(self.xmltree(major="?0x00000002"))
        with self.assertRaisesRegex(gate.GateError, "unresolved or ambiguous"):
            self.version(self.xmltree(extra=(
                "      A: http://schemas.android.com/apk/res/android:versionCodeMajor=2"
            )))
        with self.assertRaisesRegex(gate.GateError, "malformed compiled manifest"):
            self.version(self.xmltree(major="2 trailing-junk"))

    def test_nested_major_does_not_override_root(self):
        nested = (
            "        E: application (line=3)\n"
            "          A: http://schemas.android.com/apk/res/android:versionCodeMajor(0x01010576)=9"
        )
        self.assertEqual(
            self.version(self.xmltree(extra=nested)),
            ("com.example.app", "42", "0"),
        )


class ToolResolutionTest(unittest.TestCase):
    def executable(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
        path.chmod(0o755)
        return path

    def test_sdk_apksigner_override_with_build_otatools(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            host = root / "host"
            sdk_apksigner = self.executable(root / "sdk" / "apksigner")
            aapt2 = self.executable(host / "bin" / "aapt2")
            deapexer = self.executable(host / "bin" / "deapexer")
            avbtool = self.executable(host / "bin" / "avbtool")
            tools = gate.resolve_tools(host, apksigner_override=sdk_apksigner)
        self.assertEqual(tools.apksigner, sdk_apksigner.resolve())
        self.assertEqual(tools.aapt2, aapt2.resolve())
        self.assertEqual(tools.deapexer, deapexer.resolve())
        self.assertEqual(tools.avbtool, avbtool.resolve())

    def test_direct_apksigner_uses_pinned_java_and_retained_jar(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            host = root / "host"
            java = self.executable(root / "jdk" / "bin" / "java")
            jar = root / "retained" / "apksigner.jar"
            jar.parent.mkdir(parents=True)
            jar.write_bytes(b"retained apksigner jar")
            java_home = root / "java-home"
            java_tmpdir = root / "java-tmp"
            java_home.mkdir()
            java_tmpdir.mkdir()
            self.executable(host / "bin" / "aapt2")
            self.executable(host / "bin" / "deapexer")
            self.executable(host / "bin" / "avbtool")
            java_sha256 = hashlib.sha256(java.read_bytes()).hexdigest()
            jar_sha256 = hashlib.sha256(jar.read_bytes()).hexdigest()
            tools = gate.resolve_tools(
                host,
                apksigner_java_override=java,
                apksigner_jar_override=jar,
                apksigner_java_home=java_home,
                apksigner_java_tmpdir=java_tmpdir,
                apksigner_java_sha256=java_sha256,
                apksigner_jar_sha256=jar_sha256,
            )
            archive = root / "example.apk"
            archive.write_bytes(b"apk")
            with mock.patch.object(
                gate, "run_command", return_value=signer_output(APK_CERT)
            ) as run:
                certificate = gate.signer_sha256(tools, archive, "direct signer")
            self.assertEqual(APK_CERT, certificate)
            self.assertEqual(
                [
                    str(java.resolve()),
                    f"-Duser.home={java_home.resolve()}",
                    f"-Djava.io.tmpdir={java_tmpdir.resolve()}",
                    "-jar",
                    str(jar.resolve()),
                    "verify",
                    "--verbose",
                    "--print-certs",
                    str(archive),
                ],
                run.call_args.args[0],
            )

            jar.write_bytes(b"replaced after resolution")
            with self.assertRaisesRegex(gate.GateError, "changed before execution"):
                gate.signer_sha256(tools, archive, "replaced signer")

    def test_direct_apksigner_requires_complete_matching_inputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(gate.GateError, "requires Java"):
                gate.resolve_tools(
                    root,
                    apksigner_java_override=root / "java",
                )

    def test_invalid_explicit_tool_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with self.assertRaisesRegex(gate.GateError, "explicit apksigner"):
                gate.resolve_tools(root, apksigner_override=root / "missing")

    def test_outputs_cannot_replace_inputs_or_each_other(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "target.zip"
            expected = root / "expected.tsv"
            with self.assertRaisesRegex(gate.GateError, "must not replace"):
                gate.validate_output_paths(target, expected, target, None)
            output = root / "output.txt"
            with self.assertRaisesRegex(gate.GateError, "different paths"):
                gate.validate_output_paths(target, expected, output, output)

    def test_subprocess_timeout_is_a_documented_gate_error(self):
        with mock.patch.object(gate, "SUBPROCESS_TIMEOUT_SECONDS", 0.05):
            with self.assertRaisesRegex(gate.GateError, "timed out"):
                gate.run_command(
                    [sys.executable, "-c", "import time; time.sleep(5)"], "test tool"
                )

    def test_subprocess_scrubs_java_injection_environment(self):
        injected = {
            "_JAVA_OPTIONS": "-javaagent:/tmp/agent.jar",
            "JAVA_TOOL_OPTIONS": "-Xbootclasspath/a:/tmp/classes",
            "JDK_JAVA_OPTIONS": "-Duser.home=/tmp/ambient",
            "CLASSPATH": "/tmp/ambient.jar",
        }
        command = [
            sys.executable,
            "-c",
            "import os; print('|'.join(os.environ.get(k, 'missing') for k in "
            "('_JAVA_OPTIONS', 'JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', 'CLASSPATH')))",
        ]
        with mock.patch.dict(os.environ, injected):
            self.assertEqual("missing|missing|missing|missing\n", gate.run_command(command, "test tool"))

    def test_subprocess_output_limit_terminates_the_tool(self):
        with tempfile.TemporaryDirectory() as temporary:
            pid_file = Path(temporary) / "tool.pid"
            command = [
                sys.executable,
                "-c",
                "import os, sys, time; from pathlib import Path; "
                f"Path({str(pid_file)!r}).write_text(str(os.getpid())); "
                "sys.stderr.buffer.write(b'x' * 4096); sys.stderr.flush(); "
                "time.sleep(5)",
            ]
            with mock.patch.object(gate, "MAX_COMMAND_OUTPUT_BYTES", 1024):
                with self.assertRaisesRegex(gate.GateError, "output exceeds 1024 byte limit"):
                    gate.run_command(command, "noisy tool")
                self.assertEqual(
                    len(
                        gate.run_command(
                            [sys.executable, "-c", "print('x' * 1023)"], "quiet tool"
                        )
                    ),
                    1024,
                )
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pid_file.read_text()), 0)

    def test_subprocess_file_limit_blocks_oversized_decompression_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "oversized.apex"
            command = [
                sys.executable,
                "-c",
                f"from pathlib import Path; Path({str(output)!r}).write_bytes(b'x' * 4096)",
            ]
            with self.assertRaisesRegex(gate.GateError, "failed"):
                gate.run_command(
                    command,
                    "bounded deapexer",
                    output_file_limit=1024,
                    temporary_directory=root,
                )
            self.assertLessEqual(output.stat().st_size, 1024)


class SnapshotTest(unittest.TestCase):
    def test_snapshot_hash_and_bytes_survive_source_replacement(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "target-files.zip"
            destination = root / "private-snapshot.zip"
            original = b"original immutable target-files bytes"
            source.write_bytes(original)
            with gate.target_files_snapshot(source, destination) as snapshot:
                replacement = root / "replacement.zip"
                replacement.write_bytes(b"replacement bytes")
                os.replace(replacement, source)
                self.assertEqual(snapshot.path.read_bytes(), original)
                self.assertEqual(snapshot.sha256, hashlib.sha256(original).hexdigest())
                self.assertEqual(snapshot.size, len(original))
                self.assertEqual(snapshot.path.stat().st_mode & 0o222, 0)
            self.assertTrue(destination.exists())

    def test_snapshot_refuses_symlink_source_and_cleans_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real_source = root / "real.zip"
            real_source.write_bytes(b"target-files")
            source = root / "target-files.zip"
            source.symlink_to(real_source)
            destination = root / "snapshot.zip"
            with self.assertRaises(gate.GateError):
                gate.create_target_files_snapshot(source, destination)
            self.assertFalse(destination.exists())


class MainExitTest(unittest.TestCase):
    def invoke(self, mode):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected = manifest([identity()])
            expected_bytes = gate.serialize_manifest(expected)
            expected_path = root / "expected.tsv"
            expected_path.write_bytes(expected_bytes)
            target_path = root / "target-files.zip"
            target_path.write_bytes(b"target-files")
            evidence_path = root / "evidence.txt"
            tools = gate.Tools(
                Path("/tools/apksigner"),
                Path("/tools/aapt2"),
                Path("/tools/deapexer"),
                Path("/tools/avbtool"),
            )
            arguments = [
                "--target-files",
                str(target_path),
                "--expected-manifest",
                str(expected_path),
                "--expected-manifest-sha256",
                hashlib.sha256(expected_bytes).hexdigest(),
                "--otatools-dir",
                str(root / "host"),
                "--mode",
                mode,
                "--evidence-out",
                str(evidence_path),
            ]
            with mock.patch.object(gate, "resolve_tools", return_value=tools), mock.patch.object(
                gate, "inventory_target_files", return_value=expected.identities
            ):
                status = gate.main(arguments)
            evidence = evidence_path.read_text(encoding="ascii")
        return status, evidence

    def test_matching_test_key_audit_can_never_return_success(self):
        status, evidence = self.invoke("test-key-audit")
        self.assertEqual(status, 3)
        self.assertIn("comparison_status=COMPATIBLE_SIGNER_IDENTITIES\n", evidence)
        self.assertIn("flash_disposition=NOT_FOR_IN_PLACE_FLASH\n", evidence)

    def test_only_matching_release_candidate_returns_success(self):
        status, evidence = self.invoke("release-candidate")
        self.assertEqual(status, 0)
        self.assertIn(
            "flash_disposition=SIGNER_GATE_PASSED_HARDWARE_TEST_STILL_REQUIRED\n",
            evidence,
        )

    def test_invalid_target_identity_returns_two_and_cleans_outputs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected = manifest([identity()])
            expected_bytes = gate.serialize_manifest(expected)
            expected_path = root / "expected.tsv"
            expected_path.write_bytes(expected_bytes)
            target_path = root / "target-files.zip"
            target_path.write_bytes(b"target-files")
            evidence_path = root / "evidence.txt"
            actual_path = root / "actual.tsv"
            snapshot_path = root / "snapshot.zip"
            poisoned = identity(source_path="DATA/app/Bad.apk\tinjected")
            tools = gate.Tools(
                Path("/tools/apksigner"),
                Path("/tools/aapt2"),
                Path("/tools/deapexer"),
                Path("/tools/avbtool"),
            )
            arguments = [
                "--target-files",
                str(target_path),
                "--expected-manifest",
                str(expected_path),
                "--expected-manifest-sha256",
                hashlib.sha256(expected_bytes).hexdigest(),
                "--otatools-dir",
                str(root / "host"),
                "--mode",
                "test-key-audit",
                "--actual-manifest-out",
                str(actual_path),
                "--evidence-out",
                str(evidence_path),
                "--snapshot-out",
                str(snapshot_path),
            ]
            with mock.patch.object(gate, "resolve_tools", return_value=tools), mock.patch.object(
                gate, "inventory_target_files", return_value=(poisoned,)
            ), mock.patch.object(gate.sys, "stderr", io.StringIO()):
                status = gate.main(arguments)
            self.assertEqual(status, 2)
            self.assertFalse(evidence_path.exists())
            self.assertFalse(actual_path.exists())
            self.assertFalse(snapshot_path.exists())



if __name__ == "__main__":
    unittest.main()
