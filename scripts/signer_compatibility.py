#!/usr/bin/env python3
"""Inventory and compare public APK/APEX signing identities in target-files."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import dataclasses
import gzip
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import resource
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
import zipfile


FORMAT_MARKER = "# mp01-public-signer-manifest-v2"
LEGACY_FORMAT_MARKER = "# mp01-public-signer-manifest-v1"
LEGACY_COLUMNS = (
    "kind",
    "package",
    "source_path",
    "format",
    "version_code",
    "signer_cert_sha256",
    "container_cert_sha256",
    "payload_pubkey_sha256",
)
COLUMNS = (*LEGACY_COLUMNS, "version_code_major")
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
PACKAGE = re.compile(r"^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+$|^android$")
SIGNABLE_FORMATS = ("apk.gz", "capex", "apex", "apk")
MAX_TARGET_FILES_SIZE = 64 * 1024 * 1024 * 1024
MAX_TARGET_ENTRY_COUNT = 100000
MAX_SIGNABLE_ENTRY_COUNT = 4096
MAX_SIGNABLE_TOTAL_SIZE = 32 * 1024 * 1024 * 1024
MAX_DECOMPRESSED_APK_TOTAL_SIZE = 16 * 1024 * 1024 * 1024
MAX_APK_SIZE = 1024 * 1024 * 1024
MAX_APEX_SIZE = 4 * 1024 * 1024 * 1024
MAX_SMALL_APEX_MEMBER_SIZE = 16 * 1024 * 1024
MAX_COMMAND_OUTPUT_BYTES = 4 * 1024 * 1024
SUBPROCESS_TIMEOUT_SECONDS = 300


class GateError(RuntimeError):
    """A malformed input, invalid artifact, or unavailable tool."""


@dataclasses.dataclass(frozen=True, order=True)
class Identity:
    kind: str
    package: str
    source_path: str
    format: str
    version_code: str
    signer_cert_sha256: str
    container_cert_sha256: str
    payload_pubkey_sha256: str
    version_code_major: str

    @property
    def package_key(self) -> tuple[str, str]:
        return (self.kind, self.package)

    @property
    def row_key(self) -> tuple[str, str, str]:
        return (self.kind, self.package, self.source_path)

    def values(self) -> tuple[str, ...]:
        return tuple(getattr(self, column) for column in COLUMNS)


@dataclasses.dataclass(frozen=True)
class Manifest:
    metadata: dict[str, str]
    identities: tuple[Identity, ...]


@dataclasses.dataclass(frozen=True, order=True)
class Issue:
    severity: str
    kind: str
    package: str
    code: str
    expected: str = "-"
    actual: str = "-"


@dataclasses.dataclass(frozen=True)
class Tools:
    apksigner: Path
    aapt2: Path
    deapexer: Path
    avbtool: Path
    apksigner_jar: Path | None = None
    apksigner_sha256: str | None = None
    apksigner_jar_sha256: str | None = None
    apksigner_java_home: Path | None = None
    apksigner_java_tmpdir: Path | None = None


@dataclasses.dataclass(frozen=True)
class ArchiveSnapshot:
    path: Path
    sha256: str
    size: int


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise GateError(f"cannot calculate SHA256 for {path}") from exc
    return digest.hexdigest()


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _publish_new_temporary(temporary: Path, destination: Path) -> None:
    linked = False
    try:
        os.link(temporary, destination)
        linked = True
        temporary.unlink()
        _fsync_directory(destination.parent)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        if linked:
            destination.unlink(missing_ok=True)
        raise GateError(
            f"cannot publish output path without replacement: {destination}"
        ) from exc


def create_target_files_snapshot(source: Path, destination: Path) -> ArchiveSnapshot:
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        output_descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", dir=destination.parent
        )
    except OSError as exc:
        raise GateError(f"cannot prepare target-files snapshot: {destination}") from exc

    temporary = Path(temporary_name)
    source_descriptor = -1
    try:
        open_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        open_flags |= getattr(os, "O_NOFOLLOW", 0)
        source_descriptor = os.open(source, open_flags)
        before = os.fstat(source_descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise GateError(f"target-files input is not a regular file: {source}")
        if before.st_size <= 0 or before.st_size > MAX_TARGET_FILES_SIZE:
            raise GateError(
                f"target-files size is outside the supported range: {before.st_size}"
            )

        digest = hashlib.sha256()
        copied = 0
        with os.fdopen(source_descriptor, "rb") as input_file, os.fdopen(
            output_descriptor, "wb"
        ) as output_file:
            source_descriptor = -1
            output_descriptor = -1
            for chunk in iter(lambda: input_file.read(1024 * 1024), b""):
                copied += len(chunk)
                if copied > MAX_TARGET_FILES_SIZE:
                    raise GateError("target-files grew beyond the snapshot size limit")
                digest.update(chunk)
                output_file.write(chunk)
            after = os.fstat(input_file.fileno())
            output_file.flush()
            os.fsync(output_file.fileno())

        stable_fields = (
            "st_dev",
            "st_ino",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
        )
        if copied != before.st_size or any(
            getattr(before, field) != getattr(after, field) for field in stable_fields
        ):
            raise GateError("target-files changed while its private snapshot was created")
        os.chmod(temporary, 0o444)
        _publish_new_temporary(temporary, destination)
        return ArchiveSnapshot(destination, digest.hexdigest(), copied)
    except GateError:
        temporary.unlink(missing_ok=True)
        raise
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise GateError(f"cannot create target-files snapshot from {source}") from exc
    finally:
        if source_descriptor >= 0:
            os.close(source_descriptor)
        if output_descriptor >= 0:
            os.close(output_descriptor)


@contextmanager
def target_files_snapshot(source: Path, persistent_destination: Path | None):
    if persistent_destination is None:
        with tempfile.TemporaryDirectory(
            prefix="mp01-target-files-snapshot-"
        ) as temporary:
            snapshot = create_target_files_snapshot(
                source, Path(temporary) / "target-files.zip"
            )
            yield snapshot
        return

    snapshot = create_target_files_snapshot(source, persistent_destination)
    try:
        yield snapshot
    except BaseException:
        try:
            snapshot.path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _validate_sha256(value: str, label: str) -> None:
    if not HEX_SHA256.fullmatch(value):
        raise GateError(f"{label} must be a lowercase SHA256 digest")


def _validate_ascii_text(value: str, label: str) -> None:
    try:
        value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise GateError(f"{label} must contain ASCII only") from exc
    has_control = any(
        ord(character) < 0x20 or ord(character) == 0x7F for character in value
    )
    if not value or has_control:
        raise GateError(f"{label} contains an empty value or control character")


def _validate_source_path(value: str, label: str) -> None:
    _validate_ascii_text(value, label)
    if len(value) > 4096:
        raise GateError(f"{label} is too long")
    components = value.split("/")
    source = PurePosixPath(value)
    if (
        value.startswith("/")
        or "\\" in value
        or any(component in {"", ".", ".."} for component in components)
        or ".." in source.parts
    ):
        raise GateError(f"{label} is unsafe: {value!r}")


def _validate_identity(identity: Identity, location: str) -> None:
    for column, value in zip(COLUMNS, identity.values()):
        _validate_ascii_text(value, f"{location} {column}")
    if identity.kind not in {"apk", "apex"}:
        raise GateError(f"{location}: unsupported kind {identity.kind!r}")
    if not PACKAGE.fullmatch(identity.package):
        raise GateError(f"{location}: invalid package name {identity.package!r}")
    _validate_source_path(identity.source_path, f"{location} source_path")
    if identity.version_code != "-" and not identity.version_code.isdigit():
        raise GateError(f"{location}: invalid version code {identity.version_code!r}")
    if identity.version_code.isdigit() and (
        len(identity.version_code) > 10 or int(identity.version_code) > 0xFFFFFFFF
    ):
        raise GateError(f"{location}: version code exceeds 32 bits")
    if identity.version_code_major != "-" and not identity.version_code_major.isdigit():
        raise GateError(f"{location}: invalid major version code {identity.version_code_major!r}")
    if identity.version_code_major.isdigit() and (
        len(identity.version_code_major) > 10
        or int(identity.version_code_major) > 0xFFFFFFFF
    ):
        raise GateError(f"{location}: major version code exceeds 32 bits")
    _validate_sha256(identity.signer_cert_sha256, f"{location} signer certificate")
    if identity.kind == "apk":
        if identity.format not in {"apk", "apk.gz"}:
            raise GateError(f"{location}: APK format must be 'apk' or 'apk.gz'")
        if identity.container_cert_sha256 != "-" or identity.payload_pubkey_sha256 != "-":
            raise GateError(f"{location}: APK rows must not contain APEX identities")
    else:
        if identity.format not in {"apex", "capex"}:
            raise GateError(f"{location}: APEX format must be 'apex' or 'capex'")
        _validate_sha256(
            identity.container_cert_sha256, f"{location} APEX container certificate"
        )
        _validate_sha256(
            identity.payload_pubkey_sha256, f"{location} APEX payload public key"
        )


def parse_manifest_bytes(raw: bytes) -> Manifest:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as exc:
        raise GateError("signer manifest must be ASCII") from exc
    if "\r" in text:
        raise GateError("signer manifest must use LF line endings")
    lines = text.splitlines()
    if not lines or lines[0] not in {FORMAT_MARKER, LEGACY_FORMAT_MARKER}:
        raise GateError(f"signer manifest must begin with {FORMAT_MARKER!r} or {LEGACY_FORMAT_MARKER!r}")
    legacy = lines[0] == LEGACY_FORMAT_MARKER

    metadata: dict[str, str] = {}
    cursor = 1
    while cursor < len(lines) and lines[cursor].startswith("# "):
        entry = lines[cursor][2:]
        if "=" not in entry:
            raise GateError(f"manifest line {cursor + 1}: malformed metadata")
        key, value = entry.split("=", 1)
        if not re.fullmatch(r"[a-z][a-z0-9_]*", key) or not value:
            raise GateError(f"manifest line {cursor + 1}: malformed metadata")
        if key in metadata:
            raise GateError(f"manifest line {cursor + 1}: duplicate metadata key {key!r}")
        metadata[key] = value
        cursor += 1

    required_metadata = {
        "apk_coverage",
        "apex_coverage",
        "baseline_archive_sha256",
        "baseline_image_sha256",
        "baseline_apk_inventory_sha256",
        "baseline_apex_inventory_sha256",
    }
    if set(metadata) != required_metadata:
        missing = sorted(required_metadata - set(metadata))
        extra = sorted(set(metadata) - required_metadata)
        raise GateError(f"signer manifest metadata mismatch; missing={missing}, extra={extra}")
    for kind in ("apk", "apex"):
        if metadata[f"{kind}_coverage"] not in {"partial", "complete"}:
            raise GateError(f"{kind}_coverage must be 'partial' or 'complete'")
    _validate_sha256(metadata["baseline_archive_sha256"], "baseline archive SHA256")
    _validate_sha256(metadata["baseline_image_sha256"], "baseline image SHA256")
    _validate_sha256(
        metadata["baseline_apk_inventory_sha256"], "baseline APK inventory SHA256"
    )
    _validate_sha256(
        metadata["baseline_apex_inventory_sha256"], "baseline APEX inventory SHA256"
    )

    columns = LEGACY_COLUMNS if legacy else COLUMNS
    if cursor >= len(lines) or tuple(lines[cursor].split("\t")) != columns:
        raise GateError("signer manifest has an unexpected TSV header")
    cursor += 1

    identities: list[Identity] = []
    row_keys: set[tuple[str, str, str]] = set()
    previous_row_key: tuple[str, str, str] | None = None
    for index in range(cursor, len(lines)):
        line = lines[index]
        if not line:
            raise GateError(f"manifest line {index + 1}: blank lines are not allowed")
        values = line.split("\t")
        if len(values) != len(columns):
            raise GateError(f"manifest line {index + 1}: expected {len(columns)} TSV fields")
        identity = Identity(*values, "-") if legacy else Identity(*values)
        _validate_identity(identity, f"manifest line {index + 1}")
        if identity.row_key in row_keys:
            raise GateError(
                f"manifest line {index + 1}: duplicate identity {identity.row_key}"
            )
        if previous_row_key is not None and identity.row_key <= previous_row_key:
            raise GateError(
                "signer manifest identity rows must be sorted by kind, package, and path"
            )
        previous_row_key = identity.row_key
        row_keys.add(identity.row_key)
        identities.append(identity)
    if not identities:
        raise GateError("signer manifest contains no identities")
    _collapse_package_identities(tuple(identities), "expected signer manifest")
    return Manifest(metadata, tuple(identities))


def load_expected_manifest(path: Path, expected_sha256: str) -> tuple[Manifest, str]:
    _validate_sha256(expected_sha256, "expected signer manifest SHA256")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise GateError(f"cannot read expected signer manifest: {path}") from exc
    actual_sha256 = sha256_bytes(raw)
    if actual_sha256 != expected_sha256:
        raise GateError(
            "expected signer manifest SHA256 mismatch: "
            f"expected {expected_sha256}, actual {actual_sha256}"
        )
    return parse_manifest_bytes(raw), actual_sha256


def serialize_manifest(manifest: Manifest) -> bytes:
    for key, value in manifest.metadata.items():
        _validate_ascii_text(key, "manifest metadata key")
        _validate_ascii_text(value, f"manifest metadata {key}")
    for index, identity in enumerate(
        sorted(manifest.identities, key=lambda item: item.row_key), start=1
    ):
        _validate_identity(identity, f"serialized identity {index}")
    _collapse_package_identities(manifest.identities, "serialized manifest")
    lines = [FORMAT_MARKER]
    for key in sorted(manifest.metadata):
        lines.append(f"# {key}={manifest.metadata[key]}")
    lines.append("\t".join(COLUMNS))
    for identity in sorted(manifest.identities, key=lambda item: item.row_key):
        lines.append("\t".join(identity.values()))
    return ("\n".join(lines) + "\n").encode("ascii")


def resolve_tools(
    otatools_dir: Path,
    apksigner_override: Path | None = None,
    aapt2_override: Path | None = None,
    apksigner_java_override: Path | None = None,
    apksigner_jar_override: Path | None = None,
    apksigner_java_home: Path | None = None,
    apksigner_java_tmpdir: Path | None = None,
    apksigner_java_sha256: str | None = None,
    apksigner_jar_sha256: str | None = None,
) -> Tools:
    def explicit(path: Path | None, name: str) -> Path | None:
        if path is None:
            return None
        if not path.is_file() or not os.access(path, os.X_OK):
            raise GateError(f"explicit {name} is unavailable or not executable: {path}")
        return path.resolve()

    def resolve(name: str, override: Path | None = None) -> Path:
        selected = explicit(override, name)
        if selected is not None:
            return selected
        candidates = (otatools_dir / "bin" / name, otatools_dir / name)
        for candidate in candidates:
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate.resolve()
        raise GateError(f"required otatools executable is unavailable: {name}")

    direct_values = (
        apksigner_java_override,
        apksigner_jar_override,
        apksigner_java_home,
        apksigner_java_tmpdir,
        apksigner_java_sha256,
        apksigner_jar_sha256,
    )
    if any(value is not None for value in direct_values):
        if not all(value is not None for value in direct_values):
            raise GateError(
                "direct apksigner requires Java, JAR, home, temp, and both SHA256 values"
            )
        if apksigner_override is not None:
            raise GateError("direct apksigner inputs cannot be combined with a launcher")
        assert apksigner_java_override is not None
        assert apksigner_jar_override is not None
        assert apksigner_java_home is not None
        assert apksigner_java_tmpdir is not None
        assert apksigner_java_sha256 is not None
        assert apksigner_jar_sha256 is not None
        _validate_sha256(apksigner_java_sha256, "apksigner Java")
        _validate_sha256(apksigner_jar_sha256, "apksigner JAR")
        apksigner = explicit(apksigner_java_override, "apksigner Java")
        if apksigner is None:
            raise GateError("direct apksigner Java is required")
        if not apksigner_jar_override.is_file() or not os.access(
            apksigner_jar_override, os.R_OK
        ):
            raise GateError(
                f"explicit apksigner JAR is unavailable: {apksigner_jar_override}"
            )
        apksigner_jar = apksigner_jar_override.resolve()
        if sha256_file(apksigner) != apksigner_java_sha256:
            raise GateError("apksigner Java SHA256 mismatch")
        if sha256_file(apksigner_jar) != apksigner_jar_sha256:
            raise GateError("apksigner JAR SHA256 mismatch")
        if not apksigner_java_home.is_dir() or not apksigner_java_tmpdir.is_dir():
            raise GateError("direct apksigner Java home and temp paths must be directories")
        resolved_java_home = apksigner_java_home.resolve()
        resolved_java_tmpdir = apksigner_java_tmpdir.resolve()
        return Tools(
            apksigner,
            resolve("aapt2", aapt2_override),
            resolve("deapexer"),
            resolve("avbtool"),
            apksigner_jar,
            apksigner_java_sha256,
            apksigner_jar_sha256,
            resolved_java_home,
            resolved_java_tmpdir,
        )

    return Tools(
        resolve("apksigner", apksigner_override),
        resolve("aapt2", aapt2_override),
        resolve("deapexer"),
        resolve("avbtool"),
    )


def run_command(
    arguments: list[str],
    label: str,
    *,
    output_file_limit: int | None = None,
    temporary_directory: Path | None = None,
) -> str:
    environment = os.environ.copy()
    for variable in ("_JAVA_OPTIONS", "JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH"):
        environment.pop(variable, None)
    environment.update({"LC_ALL": "C", "LANG": "C", "TZ": "UTC"})
    if output_file_limit is not None and not 0 < output_file_limit <= MAX_APEX_SIZE:
        raise GateError(f"{label} has an invalid output file limit")
    if temporary_directory is not None:
        if not temporary_directory.is_dir():
            raise GateError(f"{label} has an unavailable temporary directory")
        environment["TMPDIR"] = str(temporary_directory)

    def limit_output_file() -> None:
        assert output_file_limit is not None
        resource.setrlimit(resource.RLIMIT_FSIZE, (output_file_limit, output_file_limit))

    try:
        process = subprocess.Popen(
            arguments,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=environment,
            cwd=temporary_directory,
            preexec_fn=limit_output_file if output_file_limit is not None else None,
            start_new_session=True,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise GateError(f"could not execute {label}") from exc

    assert process.stdout is not None
    output = bytearray()
    deadline = time.monotonic() + SUBPROCESS_TIMEOUT_SECONDS
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(arguments, SUBPROCESS_TIMEOUT_SECONDS)
                events = selector.select(remaining)
                for key, _ in events:
                    chunk = os.read(
                        key.fd,
                        min(64 * 1024, MAX_COMMAND_OUTPUT_BYTES + 1 - len(output)),
                    )
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    output.extend(chunk)
                    if len(output) > MAX_COMMAND_OUTPUT_BYTES:
                        raise GateError(
                            f"{label} output exceeds {MAX_COMMAND_OUTPUT_BYTES} byte limit"
                        )
        remaining = max(0, deadline - time.monotonic())
        returncode = process.wait(timeout=remaining)
    except subprocess.TimeoutExpired as exc:
        raise GateError(
            f"{label} timed out after {SUBPROCESS_TIMEOUT_SECONDS} seconds"
        ) from exc
    except OSError as exc:
        raise GateError(f"could not read {label} output") from exc
    finally:
        if process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
        process.stdout.close()

    decoded = output.decode("utf-8", errors="replace")
    if returncode != 0:
        detail = decoded.strip().replace("\n", " | ")
        raise GateError(f"{label} failed (exit {returncode}): {detail}")
    return decoded


def signer_sha256(tools: Tools, archive: Path, label: str) -> str:
    command = [str(tools.apksigner)]
    if tools.apksigner_jar is not None:
        if (
            tools.apksigner_sha256 is None
            or tools.apksigner_jar_sha256 is None
            or tools.apksigner_java_home is None
            or tools.apksigner_java_tmpdir is None
        ):
            raise GateError("direct apksigner is missing its pinned hashes")
        if sha256_file(tools.apksigner) != tools.apksigner_sha256:
            raise GateError("apksigner Java changed before execution")
        if sha256_file(tools.apksigner_jar) != tools.apksigner_jar_sha256:
            raise GateError("apksigner JAR changed before execution")
        command.extend(
            (
                f"-Duser.home={tools.apksigner_java_home}",
                f"-Djava.io.tmpdir={tools.apksigner_java_tmpdir}",
                "-jar",
                str(tools.apksigner_jar),
            )
        )
    command.extend(("verify", "--verbose", "--print-certs", str(archive)))
    output = run_command(
        command, label
    )
    counts = re.findall(r"^Number of signers: (\d+)$", output, flags=re.MULTILINE)
    fingerprints = re.findall(
        r"^Signer #(\d+) certificate SHA-256 digest: ([0-9A-Fa-f:]+)$",
        output,
        flags=re.MULTILINE,
    )
    if counts != ["1"] or len(fingerprints) != 1 or fingerprints[0][0] != "1":
        raise GateError(f"{label} must report exactly one current signer")
    fingerprint = fingerprints[0][1].replace(":", "").lower()
    _validate_sha256(fingerprint, f"{label} signer certificate")
    return fingerprint


def package_badging(aapt2: Path, archive: Path, label: str) -> tuple[str, str]:
    output = run_command([str(aapt2), "dump", "badging", str(archive)], label)
    package_lines = re.findall(r"^package: (.+)$", output, flags=re.MULTILINE)
    if len(package_lines) != 1:
        raise GateError(f"{label} has missing or ambiguous package badging")
    attributes: dict[str, str] = {}
    for key, value in re.findall(
        r"(?:^| )([A-Za-z][A-Za-z0-9]*)='([^']*)'", package_lines[0]
    ):
        if key in attributes:
            raise GateError(f"{label} has duplicate {key} in package badging")
        attributes[key] = value
    package = attributes.get("name", "")
    version_code = attributes.get("versionCode")
    if (
        not PACKAGE.fullmatch(package)
        or version_code is None
    ):
        raise GateError(f"{label} has missing or invalid package version badging")
    return package, _version_uint32(
        version_code, f"{label} versionCode", allow_unsigned_decimal=True
    ) if version_code else "-"


def _version_uint32(
    numeric: str, label: str, allow_unsigned_decimal: bool = False
) -> str:
    if numeric.startswith("0x"):
        digits = numeric[2:]
        if not digits or len(digits) > 8 or not re.fullmatch(r"[0-9a-fA-F]+", digits):
            raise GateError(f"{label} is not a 32-bit unsigned integer")
        return str(int(digits, 16))
    if not re.fullmatch(r"-?[0-9]{1,10}", numeric):
        raise GateError(f"{label} is not a 32-bit integer")
    value = int(numeric)
    upper_bound = 1 << 32 if allow_unsigned_decimal and value >= 0 else 1 << 31
    if not -(1 << 31) <= value < upper_bound:
        raise GateError(f"{label} is not a 32-bit integer")
    return str(value & 0xFFFFFFFF)


def _xmltree_uint32(value: str, label: str) -> str:
    match = re.fullmatch(
        r'(0x[0-9a-fA-F]+|-?[0-9]+)(?: \(Raw: "[^"]*"\))?', value
    )
    if match is None:
        raise GateError(f"{label} has malformed compiled manifest value")
    return _version_uint32(match.group(1), label)


def package_manifest_version(aapt2: Path, archive: Path, label: str) -> tuple[str, str, str]:
    output = run_command(
        [str(aapt2), "dump", "xmltree", "--file", "AndroidManifest.xml", str(archive)],
        label,
    )
    lines = output.splitlines()
    roots = [
        (index, len(match.group(1)))
        for index, line in enumerate(lines)
        if (match := re.fullmatch(r"( *)E: manifest(?: \(.*\))?", line))
    ]
    if len(roots) != 1:
        raise GateError(f"{label} has missing or ambiguous manifest root")
    root_index, root_indent = roots[0]
    attributes: dict[str, str] = {}
    for line in lines[root_index + 1 :]:
        if re.match(r" *E: ", line):
            break
        prefix = " " * (root_indent + 2) + "A: "
        if not line.startswith(prefix):
            continue
        name, separator, value = line[len(prefix) :].partition("=")
        if not separator or name in attributes:
            raise GateError(f"{label} has malformed or duplicate manifest attributes")
        attributes[name] = value

    package_value = attributes.get("package", "")
    package_match = re.match(r'^"([^"]+)"', package_value)
    package = package_match.group(1) if package_match else ""
    if not PACKAGE.fullmatch(package):
        raise GateError(f"{label} has invalid manifest package")
    code_key = "http://schemas.android.com/apk/res/android:versionCode(0x0101021b)"
    major_key = "http://schemas.android.com/apk/res/android:versionCodeMajor(0x01010576)"
    for name in attributes:
        if ("versionCodeMajor" in name and name != major_key) or (
            "versionCode" in name and "versionCodeMajor" not in name and name != code_key
        ):
            raise GateError(f"{label} has an unresolved or ambiguous version attribute")
    code = (
        _xmltree_uint32(attributes[code_key], f"{label} versionCode")
        if code_key in attributes else "-"
    )
    major = (
        _xmltree_uint32(attributes[major_key], f"{label} versionCodeMajor")
        if major_key in attributes else "0"
    )
    return package, code, major


def package_version(aapt2: Path, archive: Path, label: str) -> tuple[str, str, str]:
    package, code = package_badging(aapt2, archive, label)
    xml_package, xml_code, major = package_manifest_version(aapt2, archive, label)
    if package != xml_package or (code != "-" and code != xml_code):
        raise GateError(f"{label} badging and manifest package versions differ")
    return package, xml_code, major


def _safe_zip_info(
    archive: zipfile.ZipFile,
    member: str,
    label: str,
    maximum_size: int | None = None,
) -> zipfile.ZipInfo:
    if maximum_size is None:
        maximum_size = MAX_APEX_SIZE
    matches = [item for item in archive.infolist() if item.filename == member]
    if len(matches) != 1:
        raise GateError(f"{label} must contain exactly one {member!r}")
    info = matches[0]
    if info.is_dir() or info.file_size > maximum_size:
        raise GateError(f"{label} has invalid {member!r} metadata")
    return info


def _extract_zip_info(
    archive: zipfile.ZipFile, info: zipfile.ZipInfo, destination: Path, label: str
) -> None:
    try:
        extracted_size = 0
        with archive.open(info, "r") as source, destination.open("wb") as output:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                extracted_size += len(chunk)
                if extracted_size > info.file_size or extracted_size > MAX_APEX_SIZE:
                    raise GateError(f"{info.filename!r} exceeds its extraction size limit")
                output.write(chunk)
    except GateError:
        raise
    except (OSError, zipfile.BadZipFile, RuntimeError, EOFError) as exc:
        raise GateError(f"could not extract {info.filename!r} from {label}") from exc
    if extracted_size != info.file_size:
        raise GateError(f"short extraction of {info.filename!r} from {label}")


def _hash_zip_info_bounded(
    archive: zipfile.ZipFile, info: zipfile.ZipInfo, label: str
) -> str:
    digest = hashlib.sha256()
    size = 0
    try:
        with archive.open(info, "r") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                size += len(chunk)
                if size > info.file_size or size > MAX_APEX_SIZE:
                    raise GateError(f"{label} exceeds its declared size")
                digest.update(chunk)
    except GateError:
        raise
    except (OSError, zipfile.BadZipFile, RuntimeError, EOFError) as exc:
        raise GateError(f"cannot validate {label}") from exc
    if size != info.file_size:
        raise GateError(f"{label} is shorter than its declared size")
    return digest.hexdigest()


def _read_zip_member(archive: Path, member: str, label: str) -> bytes:
    try:
        with zipfile.ZipFile(archive) as source:
            info = _safe_zip_info(
                source, member, label, maximum_size=MAX_SMALL_APEX_MEMBER_SIZE
            )
            return source.read(info)
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise GateError(f"cannot read ZIP member {member!r} from {label}") from exc


def inspect_apk(
    path: Path, source_path: str, tools: Tools, archive_format: str = "apk"
) -> Identity:
    package, version, major = package_version(tools.aapt2, path, f"APK for {source_path}")
    certificate = signer_sha256(tools, path, f"APK signature for {source_path}")
    return Identity(
        "apk", package, source_path, archive_format, version, certificate, "-", "-", major
    )


def inspect_apex(path: Path, source_path: str, tools: Tools, work_dir: Path) -> Identity:
    extension = PurePosixPath(source_path).suffix.lower()
    expected_type = {".apex": "UNCOMPRESSED", ".capex": "COMPRESSED"}[extension]
    type_output = run_command(
        [str(tools.deapexer), "info", str(path), "--print-type"],
        f"APEX type verification for {source_path}",
    )
    types = [
        line.strip()
        for line in type_output.splitlines()
        if line.strip() in {"COMPRESSED", "UNCOMPRESSED"}
    ]
    if types != [expected_type]:
        raise GateError(f"{source_path} extension and deapexer type disagree")

    try:
        wrapper_size = path.stat().st_size
    except OSError as exc:
        raise GateError(f"cannot inspect APEX wrapper size for {source_path}") from exc
    if not 0 < wrapper_size <= MAX_APEX_SIZE:
        raise GateError(f"APEX wrapper size is invalid for {source_path}")
    expected_inner_size = wrapper_size
    original_sha256: str | None = None
    if expected_type == "COMPRESSED":
        try:
            with zipfile.ZipFile(path) as wrapper_zip:
                original_info = _safe_zip_info(
                    wrapper_zip, "original_apex", f"compressed APEX {source_path}"
                )
                if original_info.file_size <= 0:
                    raise GateError(f"compressed APEX {source_path} has an empty original_apex")
                expected_inner_size = original_info.file_size
                original_sha256 = _hash_zip_info_bounded(
                    wrapper_zip, original_info, f"original_apex in {source_path}"
                )
        except GateError:
            raise
        except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
            raise GateError(f"cannot validate compressed APEX {source_path}") from exc

    wrapper_certificate = signer_sha256(
        tools, path, f"APEX wrapper signature for {source_path}"
    )
    wrapper_package, wrapper_version, wrapper_major = package_version(
        tools.aapt2, path, f"APEX wrapper for {source_path}"
    )
    wrapper_pubkey = _read_zip_member(path, "apex_pubkey", f"APEX wrapper {source_path}")
    if not wrapper_pubkey:
        raise GateError(f"APEX wrapper {source_path} has an empty apex_pubkey")

    inner_path = work_dir / "installable.apex"
    run_command(
        [
            str(tools.deapexer),
            "decompress",
            "--input",
            str(path),
            "--output",
            str(inner_path),
            "--copy-if-uncompressed",
        ],
        f"APEX decompression for {source_path}",
        output_file_limit=expected_inner_size,
        temporary_directory=work_dir,
    )
    try:
        inner_stat = inner_path.lstat()
    except OSError as exc:
        raise GateError(f"deapexer did not produce an installable APEX for {source_path}") from exc
    if not stat.S_ISREG(inner_stat.st_mode) or inner_stat.st_size != expected_inner_size:
        raise GateError(f"deapexer produced an invalid APEX size for {source_path}")
    if original_sha256 is not None and original_sha256 != sha256_file(inner_path):
        raise GateError(f"deapexer output does not match original_apex in {source_path}")

    container_certificate = signer_sha256(
        tools, inner_path, f"installable APEX signature for {source_path}"
    )
    if wrapper_certificate != container_certificate:
        raise GateError(f"APEX wrapper and installable container signers differ for {source_path}")
    package, version, major = package_version(
        tools.aapt2, inner_path, f"installable APEX for {source_path}"
    )
    if (package, version, major) != (wrapper_package, wrapper_version, wrapper_major):
        raise GateError(f"APEX wrapper and installable manifest differ for {source_path}")

    inner_pubkey = _read_zip_member(inner_path, "apex_pubkey", f"installable APEX {source_path}")
    if inner_pubkey != wrapper_pubkey:
        raise GateError(f"APEX wrapper and installable apex_pubkey differ for {source_path}")

    payload_path = work_dir / "apex_payload.img"
    try:
        with zipfile.ZipFile(inner_path) as inner_zip:
            payload_info = _safe_zip_info(
                inner_zip, "apex_payload.img", f"installable APEX {source_path}"
            )
            _extract_zip_info(
                inner_zip, payload_info, payload_path, f"installable APEX {source_path}"
            )
    except (OSError, zipfile.BadZipFile, RuntimeError) as exc:
        raise GateError(f"cannot extract APEX payload for {source_path}") from exc

    run_command(
        [str(tools.avbtool), "verify_image", "--image", str(payload_path)],
        f"APEX payload AVB verification for {source_path}",
    )
    avb_pubkey_path = work_dir / "payload.avbpubkey"
    run_command(
        [
            str(tools.avbtool),
            "info_image",
            "--image",
            str(payload_path),
            "--output_pubkey",
            str(avb_pubkey_path),
        ],
        f"APEX payload public-key extraction for {source_path}",
    )
    try:
        avb_pubkey = avb_pubkey_path.read_bytes()
    except OSError as exc:
        raise GateError(f"avbtool did not emit the payload public key for {source_path}") from exc
    if avb_pubkey != inner_pubkey:
        raise GateError(f"APEX payload signing key does not match apex_pubkey for {source_path}")

    return Identity(
        "apex",
        package,
        source_path,
        extension[1:],
        version,
        wrapper_certificate,
        container_certificate,
        sha256_bytes(inner_pubkey),
        major,
    )


def _signable_format(name: str) -> str | None:
    candidate = name[:-1] if name.endswith("/") else name
    lowered = candidate.lower()
    for archive_format in SIGNABLE_FORMATS:
        if lowered.endswith(f".{archive_format}"):
            return archive_format
    if lowered.endswith((".apex.gz", ".capex.gz")):
        raise GateError(f"unsupported gzip-compressed signable entry: {name!r}")
    return None


def _decompress_gzip_apk(source: Path, destination: Path, label: str) -> int:
    extracted = 0
    try:
        with gzip.open(source, "rb") as input_file, destination.open("wb") as output_file:
            while True:
                chunk = input_file.read(1024 * 1024)
                if not chunk:
                    break
                extracted += len(chunk)
                if extracted > MAX_APK_SIZE:
                    raise GateError(f"gzip-compressed APK exceeds size limit: {label}")
                output_file.write(chunk)
    except GateError:
        destination.unlink(missing_ok=True)
        raise
    except (OSError, EOFError, gzip.BadGzipFile) as exc:
        destination.unlink(missing_ok=True)
        raise GateError(f"cannot decompress gzip APK: {label}") from exc
    if extracted == 0:
        destination.unlink(missing_ok=True)
        raise GateError(f"gzip-compressed APK is empty: {label}")
    return extracted


def inventory_target_files(target_files: Path, tools: Tools) -> tuple[Identity, ...]:
    try:
        archive = zipfile.ZipFile(target_files)
    except (OSError, zipfile.BadZipFile) as exc:
        raise GateError(f"cannot open target-files archive: {target_files}") from exc
    with archive:
        all_entries = archive.infolist()
        if len(all_entries) > MAX_TARGET_ENTRY_COUNT:
            raise GateError(
                f"target-files contains too many entries: {len(all_entries)}"
            )
        selected: list[tuple[zipfile.ZipInfo, str]] = []
        seen_names: set[str] = set()
        total_signable_size = 0
        for info in all_entries:
            archive_format = _signable_format(info.filename)
            if archive_format is None:
                continue
            if info.orig_filename != info.filename:
                raise GateError(
                    f"signable target-files path contains a NUL byte: {info.orig_filename!r}"
                )
            _validate_source_path(info.filename, "signable target-files path")
            if info.filename in seen_names:
                raise GateError(f"duplicate signable target-files entry: {info.filename}")
            seen_names.add(info.filename)
            maximum_size = (
                MAX_APEX_SIZE
                if archive_format in {"apex", "capex"}
                else MAX_APK_SIZE
            )
            if info.is_dir() or info.file_size <= 0 or info.file_size > maximum_size:
                raise GateError(f"invalid signable target-files entry: {info.filename}")
            total_signable_size += info.file_size
            if total_signable_size > MAX_SIGNABLE_TOTAL_SIZE:
                raise GateError("target-files signable entries exceed aggregate size limit")
            selected.append((info, archive_format))
            if len(selected) > MAX_SIGNABLE_ENTRY_COUNT:
                raise GateError("target-files contains too many signable entries")
        selected.sort(key=lambda item: item[0].filename)
        if not selected:
            raise GateError("target-files contains no APK or APEX entries")

        identities: list[Identity] = []
        total_apk_payload_size = 0
        with tempfile.TemporaryDirectory(prefix="mp01-signer-inventory-") as temporary:
            root = Path(temporary)
            for index, (info, archive_format) in enumerate(selected):
                with tempfile.TemporaryDirectory(
                    prefix=f"entry-{index:05d}-", dir=root
                ) as entry_temporary:
                    entry_root = Path(entry_temporary)
                    suffix = ".apk.gz" if archive_format == "apk.gz" else f".{archive_format}"
                    extracted = entry_root / f"artifact{suffix}"
                    _extract_zip_info(archive, info, extracted, "target-files")
                    if archive_format in {"apk", "apk.gz"}:
                        inspect_path = extracted
                        if archive_format == "apk.gz":
                            inspect_path = entry_root / "artifact.apk"
                            apk_payload_size = _decompress_gzip_apk(
                                extracted, inspect_path, info.filename
                            )
                        else:
                            apk_payload_size = info.file_size
                        total_apk_payload_size += apk_payload_size
                        if total_apk_payload_size > MAX_DECOMPRESSED_APK_TOTAL_SIZE:
                            raise GateError(
                                "target-files APK payloads exceed aggregate size limit"
                            )
                        identity = inspect_apk(
                            inspect_path, info.filename, tools, archive_format
                        )
                    else:
                        apex_work = entry_root / "apex-work"
                        apex_work.mkdir()
                        identity = inspect_apex(extracted, info.filename, tools, apex_work)
                    _validate_identity(
                        identity, f"target-derived identity for {info.filename}"
                    )
                    identities.append(identity)
    result = tuple(sorted(identities, key=lambda item: item.row_key))
    _collapse_package_identities(result, "candidate target-files")
    return result


def _signer_values(identity: Identity) -> tuple[str, ...]:
    values = [identity.signer_cert_sha256]
    if identity.kind == "apex":
        values.extend((identity.container_cert_sha256, identity.payload_pubkey_sha256))
    return tuple(values)


def _collapse_package_identities(
    identities: tuple[Identity, ...], label: str
) -> dict[tuple[str, str], Identity]:
    collapsed: dict[tuple[str, str], Identity] = {}
    for identity in identities:
        previous = collapsed.get(identity.package_key)
        if previous is None:
            collapsed[identity.package_key] = identity
            continue
        if identity.kind == "apex":
            raise GateError(f"{label} has multiple APEX files for package {identity.package}")
        if _signer_values(previous) != _signer_values(identity):
            raise GateError(
                f"{label} has conflicting APK signers for package {identity.package}"
            )
        if previous.version_code != identity.version_code:
            raise GateError(
                f"{label} has conflicting APK versions for package {identity.package}"
            )
        if previous.version_code_major != identity.version_code_major:
            raise GateError(
                f"{label} has conflicting APK major versions for package {identity.package}"
            )
    return collapsed


def compare_manifests(expected: Manifest, actual: Manifest, mode: str) -> tuple[Issue, ...]:
    issues: list[Issue] = []
    expected_by_key = _collapse_package_identities(
        expected.identities, "expected signer manifest"
    )
    actual_by_key = _collapse_package_identities(actual.identities, "candidate manifest")

    for kind in ("apk", "apex"):
        coverage = expected.metadata[f"{kind}_coverage"]
        if coverage != "complete":
            severity = "incompatibility" if mode == "release-candidate" else "warning"
            issues.append(Issue(severity, kind, "*", "expected_coverage_partial"))

    for key, wanted in sorted(expected_by_key.items()):
        found = actual_by_key.get(key)
        if found is None:
            issues.append(Issue("incompatibility", key[0], key[1], "missing_candidate_package"))
            continue
        fields = ["signer_cert_sha256"]
        if key[0] == "apex":
            fields.extend(["container_cert_sha256", "payload_pubkey_sha256"])
        for field in fields:
            wanted_value = getattr(wanted, field)
            found_value = getattr(found, field)
            if wanted_value != found_value:
                issues.append(
                    Issue(
                        "incompatibility",
                        key[0],
                        key[1],
                        f"{field}_mismatch",
                        wanted_value,
                        found_value,
                    )
                )

    for key in sorted(set(actual_by_key) - set(expected_by_key)):
        coverage = expected.metadata[f"{key[0]}_coverage"]
        if coverage == "complete":
            issues.append(Issue("incompatibility", key[0], key[1], "unexpected_candidate_package"))
        else:
            issues.append(Issue("warning", key[0], key[1], "unconstrained_candidate_package"))
    return tuple(sorted(issues))


def render_evidence(
    mode: str,
    target_files_sha256: str,
    expected_sha256: str,
    expected: Manifest,
    actual_manifest_sha256: str,
    actual: Manifest,
    issues: tuple[Issue, ...],
    apksigner_evidence: tuple[str, str] | None = None,
) -> bytes:
    incompatibilities = [issue for issue in issues if issue.severity == "incompatibility"]
    warnings = [issue for issue in issues if issue.severity == "warning"]
    status = "INCOMPATIBLE" if incompatibilities else "COMPATIBLE_SIGNER_IDENTITIES"
    disposition = (
        "NOT_FOR_IN_PLACE_FLASH"
        if mode == "test-key-audit"
        else (
            "BLOCKED"
            if incompatibilities
            else "SIGNER_GATE_PASSED_HARDWARE_TEST_STILL_REQUIRED"
        )
    )
    apk_count = sum(identity.kind == "apk" for identity in actual.identities)
    apex_count = sum(identity.kind == "apex" for identity in actual.identities)
    lines = [
        "format=mp01-signer-compatibility-evidence-v1",
        f"mode={mode}",
        f"comparison_status={status}",
        f"flash_disposition={disposition}",
        f"target_files_sha256={target_files_sha256}",
        f"expected_manifest_sha256={expected_sha256}",
        f"expected_baseline_archive_sha256={expected.metadata['baseline_archive_sha256']}",
        f"expected_baseline_image_sha256={expected.metadata['baseline_image_sha256']}",
        "expected_baseline_apk_inventory_sha256="
        f"{expected.metadata['baseline_apk_inventory_sha256']}",
        "expected_baseline_apex_inventory_sha256="
        f"{expected.metadata['baseline_apex_inventory_sha256']}",
        f"expected_apk_coverage={expected.metadata['apk_coverage']}",
        f"expected_apex_coverage={expected.metadata['apex_coverage']}",
        f"actual_manifest_sha256={actual_manifest_sha256}",
        f"actual_apk_count={apk_count}",
        f"actual_apex_count={apex_count}",
        f"incompatibility_count={len(incompatibilities)}",
        f"warning_count={len(warnings)}",
    ]
    if apksigner_evidence is not None:
        java_sha256, jar_sha256 = apksigner_evidence
        _validate_sha256(java_sha256, "evidence apksigner Java")
        _validate_sha256(jar_sha256, "evidence apksigner JAR")
        lines.extend(
            (
                "apksigner_execution=direct_java_jar",
                f"apksigner_java_sha256={java_sha256}",
                f"apksigner_jar_sha256={jar_sha256}",
            )
        )
    for index, issue in enumerate(issues, start=1):
        value = "\t".join(
            (
                issue.severity,
                issue.kind,
                issue.package,
                issue.code,
                issue.expected,
                issue.actual,
            )
        )
        lines.append(f"issue.{index:04d}={value}")
    return ("\n".join(lines) + "\n").encode("ascii")


def atomic_write(path: Path, content: bytes) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", dir=path.parent
        )
    except OSError as exc:
        raise GateError(f"cannot prepare output path: {path}") from exc
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary, 0o644)
        _publish_new_temporary(temporary, path)
    except GateError:
        temporary.unlink(missing_ok=True)
        raise
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise GateError(f"cannot write output path: {path}") from exc


def validate_output_paths(
    target_files: Path,
    expected_manifest: Path,
    actual_manifest_out: Path | None,
    evidence_out: Path | None,
    snapshot_out: Path | None = None,
) -> None:
    try:
        inputs = {target_files.resolve(), expected_manifest.resolve()}
        requested_outputs = tuple(
            path
            for path in (actual_manifest_out, evidence_out, snapshot_out)
            if path is not None
        )
        outputs = [path.resolve() for path in requested_outputs]
    except (OSError, RuntimeError) as exc:
        raise GateError("cannot resolve signer-gate input or output paths") from exc
    if len(outputs) != len(set(outputs)):
        raise GateError("signer-gate outputs must use different paths")
    if inputs.intersection(outputs):
        raise GateError("output paths must not replace target-files or expected manifest inputs")
    existing = [str(path) for path in requested_outputs if path.exists()]
    if existing:
        raise GateError(f"refusing to replace existing signer-gate outputs: {existing}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-files", type=Path, required=True)
    parser.add_argument("--expected-manifest", type=Path, required=True)
    parser.add_argument("--expected-manifest-sha256", required=True)
    parser.add_argument("--otatools-dir", type=Path, required=True)
    parser.add_argument(
        "--apksigner",
        type=Path,
        help="explicit SDK apksigner when it is not installed in otatools",
    )
    parser.add_argument(
        "--apksigner-java",
        type=Path,
        help="Java executable for direct invocation of a retained apksigner JAR",
    )
    parser.add_argument("--apksigner-java-home", type=Path)
    parser.add_argument("--apksigner-java-tmpdir", type=Path)
    parser.add_argument("--apksigner-java-sha256")
    parser.add_argument(
        "--apksigner-jar",
        type=Path,
        help="retained apksigner JAR to invoke directly",
    )
    parser.add_argument("--apksigner-jar-sha256")
    parser.add_argument(
        "--aapt2",
        type=Path,
        help="explicit aapt2 override; defaults to the otatools copy",
    )
    parser.add_argument(
        "--mode", choices=("test-key-audit", "release-candidate"), required=True
    )
    parser.add_argument("--actual-manifest-out", type=Path)
    parser.add_argument("--evidence-out", type=Path)
    parser.add_argument(
        "--snapshot-out",
        type=Path,
        help="retain the exact private target-files snapshot that was inventoried",
    )
    return parser.parse_args(argv)


def _remove_failed_outputs(paths: list[Path]) -> None:
    for path in paths:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass


def main(argv: list[str] | None = None) -> int:
    arguments = parse_args(sys.argv[1:] if argv is None else argv)
    created_outputs: list[Path] = []
    try:
        validate_output_paths(
            arguments.target_files,
            arguments.expected_manifest,
            arguments.actual_manifest_out,
            arguments.evidence_out,
            arguments.snapshot_out,
        )
        expected, expected_sha256 = load_expected_manifest(
            arguments.expected_manifest, arguments.expected_manifest_sha256.lower()
        )
        tools = resolve_tools(
            arguments.otatools_dir,
            arguments.apksigner,
            arguments.aapt2,
            arguments.apksigner_java,
            arguments.apksigner_jar,
            arguments.apksigner_java_home,
            arguments.apksigner_java_tmpdir,
            arguments.apksigner_java_sha256,
            arguments.apksigner_jar_sha256,
        )
        with target_files_snapshot(
            arguments.target_files, arguments.snapshot_out
        ) as snapshot:
            identities = inventory_target_files(snapshot.path, tools)
            actual = Manifest(
                {
                    "apex_coverage": "complete",
                    "apk_coverage": "complete",
                    "baseline_archive_sha256": expected.metadata[
                        "baseline_archive_sha256"
                    ],
                    "baseline_image_sha256": expected.metadata["baseline_image_sha256"],
                    "baseline_apk_inventory_sha256": expected.metadata[
                        "baseline_apk_inventory_sha256"
                    ],
                    "baseline_apex_inventory_sha256": expected.metadata[
                        "baseline_apex_inventory_sha256"
                    ],
                },
                identities,
            )
            actual_bytes = serialize_manifest(actual)
            actual_sha256 = sha256_bytes(actual_bytes)
            issues = compare_manifests(expected, actual, arguments.mode)
            evidence = render_evidence(
                arguments.mode,
                snapshot.sha256,
                expected_sha256,
                expected,
                actual_sha256,
                actual,
                issues,
                (
                    tools.apksigner_sha256,
                    tools.apksigner_jar_sha256,
                )
                if tools.apksigner_jar is not None
                and tools.apksigner_sha256 is not None
                and tools.apksigner_jar_sha256 is not None
                else None,
            )
            if arguments.actual_manifest_out:
                atomic_write(arguments.actual_manifest_out, actual_bytes)
                created_outputs.append(arguments.actual_manifest_out)
            if arguments.evidence_out:
                atomic_write(arguments.evidence_out, evidence)
                created_outputs.append(arguments.evidence_out)
            else:
                sys.stdout.buffer.write(evidence)
            if arguments.mode == "test-key-audit":
                return 3
            incompatible = any(
                issue.severity == "incompatibility" for issue in issues
            )
            return 1 if incompatible else 0
    except GateError as exc:
        _remove_failed_outputs(created_outputs)
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        _remove_failed_outputs(created_outputs)
        print(
            f"ERROR: unexpected signer verifier failure ({type(exc).__name__}): {exc}",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
