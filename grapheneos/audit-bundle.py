#!/usr/bin/env python3
"""Bind a candidate's release evidence to authenticated bytes; never approve a flash."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import zipfile


SCHEMA = 'mp01-bundle-binding-v1'
SIGNER_FIELDS = frozenset({
    'schema', 'profile', 'status', 'flash_authorized', 'target_files_sha256',
    'system_image_sha256', 'build', 'vendor_baseline_sha256', 'policy_sha256',
    'previous_report_sha256', 'identities', 'verifier_sha256',
    'public_test_certificates_sha256', 'inventory_tool_sha256',
})
AVB_FIELDS = frozenset({
    'schema', 'status', 'flash_authorized', 'image_sha256',
    'project_avb_public_key_sha256', 'avbtool_sha256', 'footer_version',
    'image_size', 'original_image_size', 'algorithm', 'hashtree_root_digest',
})
PROVENANCE_FIELDS = frozenset({
    'schema', 'status', 'profile', 'support_commit', 'variant',
    'source_receipt_sha256', 'device_inventory_sha256', 'container_image_id',
    'dependencies_sha256', 'environment', 'resources_start', 'target_files',
    'target_files_sha256', 'log_sha256', 'resources_sha256',
})
BASE_ARTIFACTS = frozenset({
    'signed_target_files', 'unsigned_target_files', 'system_image',
    'signer_report', 'avb_report', 'source_receipt', 'source_lock',
    'prepared_manifest', 'build_provenance', 'signing_policy',
    'vendor_baseline',
})
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_ZIP_MEMBERS = 100_000
MAX_SYSTEM_IMAGE_BYTES = 64 * 1024 ** 3
SHA256 = re.compile(r'[0-9a-f]{64}\Z')
GIT_SHA1 = re.compile(r'[0-9a-f]{40}\Z')


class AuditError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise AuditError(message)


def digest(value, label):
    require(isinstance(value, str) and SHA256.fullmatch(value),
            f'{label} must be a lowercase SHA256 digest')
    return value


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, f'Duplicate JSON key: {key}')
        result[key] = value
    return result


def parse_json(raw, label):
    require(len(raw) <= MAX_JSON_BYTES, f'{label} is too large')
    try:
        return json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object,
                          parse_constant=lambda value: require(False, f'{label}: invalid {value}'))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise AuditError(f'{label} is not valid UTF-8 JSON: {exc}') from exc


def safe_parts(name):
    require(isinstance(name, str) and name and len(name) <= 4096,
            'Artifact path must be a nonempty relative string')
    require(not name.startswith('/') and '\\' not in name and '\x00' not in name,
            f'Unsafe artifact path: {name!r}')
    parts = name.split('/')
    require(all(part not in {'', '.', '..'} for part in parts),
            f'Unsafe artifact path: {name!r}')
    return parts


def read_file(root_fd, name, *, keep=False):
    """Read a regular file beneath an already-open root, refusing symlink traversal."""
    parts = safe_parts(name)
    directory = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                              os.O_CLOEXEC, dir_fd=directory)
            os.close(directory)
            directory = next_fd
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW |
                     os.O_CLOEXEC, dir_fd=directory)
    finally:
        os.close(directory)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode), f'Artifact is not a regular file: {name}')
        content = bytearray() if keep else None
        checksum = hashlib.sha256()
        while block := stream.read(4 * 1024 * 1024):
            checksum.update(block)
            if content is not None:
                require(len(content) + len(block) <= MAX_JSON_BYTES,
                        f'JSON artifact is too large: {name}')
                content.extend(block)
        after = os.fstat(stream.fileno())
        require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                f'Artifact changed while reading: {name}')
        return checksum.hexdigest(), bytes(content) if content is not None else None


def system_member_digest(root_fd, name):
    """Hash the system image embedded in signed target-files without extraction."""
    parts = safe_parts(name)
    directory = os.dup(root_fd)
    try:
        for part in parts[:-1]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW |
                              os.O_CLOEXEC, dir_fd=directory)
            os.close(directory)
            directory = next_fd
        fd = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW |
                     os.O_CLOEXEC, dir_fd=directory)
    finally:
        os.close(directory)
    with os.fdopen(fd, 'rb') as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode), 'Signed target-files is not a regular file')
        with zipfile.ZipFile(stream) as archive:
            members = archive.infolist()
            require(len(members) <= MAX_ZIP_MEMBERS, 'Too many target-files members')
            names = [member.filename for member in members]
            require(len(names) == len(set(names)), 'Duplicate target-files member')
            matches = [member for member in members if member.filename == 'IMAGES/system.img']
            require(len(matches) == 1, 'Signed target-files needs exactly one system image')
            member = matches[0]
            require(not member.is_dir() and 0 < member.file_size <= MAX_SYSTEM_IMAGE_BYTES,
                    'Invalid embedded system image size')
            checksum = hashlib.sha256()
            read_bytes = 0
            with archive.open(member) as image:
                while block := image.read(4 * 1024 * 1024):
                    checksum.update(block)
                    read_bytes += len(block)
                    require(read_bytes <= MAX_SYSTEM_IMAGE_BYTES,
                            'Embedded system image exceeds the size limit')
            require(read_bytes == member.file_size, 'Embedded system image is incomplete')
        after = os.fstat(stream.fileno())
        require((before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                'Signed target-files changed during ZIP inspection')
        return checksum.hexdigest()


def require_fields(value, fields, label):
    require(isinstance(value, dict) and set(value) == set(fields),
            f'{label} has missing or unexpected fields')


def audit(root, trusted_manifest_sha256):
    digest(trusted_manifest_sha256, 'Authenticated manifest SHA256')
    require(root.is_dir() and not root.is_symlink(), 'Bundle root must be an ordinary directory')
    root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        actual_manifest_sha256, manifest_raw = read_file(root_fd, 'bundle-manifest.json', keep=True)
        require(actual_manifest_sha256 == trusted_manifest_sha256,
                'Bundle manifest differs from independently authenticated SHA256')
        manifest = parse_json(manifest_raw, 'bundle manifest')
        require_fields(manifest, {'schema', 'profile', 'artifacts'}, 'Bundle manifest')
        require(manifest['schema'] == SCHEMA, 'Unexpected bundle manifest schema')
        profile = manifest['profile']
        require(profile in {'initial-installation', 'upgrade'}, 'Unsupported release profile')
        required = BASE_ARTIFACTS | ({'previous_signer_report'} if profile == 'upgrade' else set())
        artifacts = manifest['artifacts']
        require(isinstance(artifacts, dict) and set(artifacts) == required,
                'Bundle artifact set is incomplete or unexpected')
        paths = set()
        hashes = {}
        documents = {}
        json_keys = {'signer_report', 'avb_report', 'source_receipt',
                     'build_provenance', 'signing_policy', 'previous_signer_report'}
        for key in sorted(required):
            entry = artifacts[key]
            require_fields(entry, {'path', 'sha256'}, f'{key} entry')
            parts = safe_parts(entry['path'])
            require(entry['path'] != 'bundle-manifest.json', 'Artifact cannot be the manifest')
            require(tuple(parts) not in paths, 'Two artifact roles reference one path')
            paths.add(tuple(parts))
            expected = digest(entry['sha256'], f'{key} SHA256')
            actual, raw = read_file(root_fd, entry['path'], keep=key in json_keys)
            require(actual == expected, f'{key} differs from authenticated manifest SHA256')
            hashes[key] = actual
            if raw is not None:
                documents[key] = parse_json(raw, key)
        signed_system = system_member_digest(root_fd, artifacts['signed_target_files']['path'])
        require(signed_system == hashes['system_image'],
                'Standalone system image differs from signed target-files IMAGES/system.img')
        signed_again, _ = read_file(root_fd, artifacts['signed_target_files']['path'])
        require(signed_again == hashes['signed_target_files'],
                'Signed target-files changed between hashing and ZIP inspection')
    finally:
        os.close(root_fd)

    signer = documents['signer_report']
    avb = documents['avb_report']
    receipt = documents['source_receipt']
    provenance = documents['build_provenance']
    policy = documents['signing_policy']
    require_fields(signer, SIGNER_FIELDS, 'Signer report')
    require_fields(avb, AVB_FIELDS, 'AVB report')
    require_fields(receipt, {'support_commit', 'inputs_sha256',
                             'prepared_manifest_sha256', 'source_graph', 'layer'},
                   'Source receipt')
    require_fields(provenance, PROVENANCE_FIELDS, 'Build provenance')
    require_fields(policy, {'schema', 'product', 'project_certificates', 'packages'},
                   'Signing policy')
    require(isinstance(signer, dict) and signer.get('schema') == 'mp01-signer-profile-v2'
            and signer.get('profile') == profile
            and signer.get('status') == ('INITIAL_SIGNER_POLICY_PASSED' if profile == 'initial-installation'
                                         else 'UPGRADE_SIGNER_POLICY_PASSED')
            and signer.get('flash_authorized') is False,
            'Signer report is not a passing release-profile gate')
    for field, key in [('target_files_sha256', 'signed_target_files'),
                       ('system_image_sha256', 'system_image'),
                       ('vendor_baseline_sha256', 'vendor_baseline'),
                       ('policy_sha256', 'signing_policy')]:
        require(signer.get(field) == hashes[key], f'Signer report {field} differs from bundle')
    require(isinstance(signer.get('build'), dict) and signer['build'].get('product') == 'mp01'
            and signer['build'].get('variant') == 'user',
            'Signer report is not for an MP01 user build')
    require_fields(signer['build'], {'product', 'variant', 'timestamp', 'sdk'},
                   'Signer report build identity')
    require(isinstance(avb, dict) and avb.get('schema') == 'mp01-avb-audit-v1'
            and avb.get('status') == 'AVB_IMAGE_IDENTITY_PASSED'
            and avb.get('flash_authorized') is False
            and avb.get('image_sha256') == hashes['system_image'],
            'AVB report does not bind the signed system image')
    digest(avb.get('project_avb_public_key_sha256'), 'AVB project public key')
    require(isinstance(policy, dict) and policy.get('schema') == 'mp01-signing-policy-v1'
            and policy.get('product') == 'mp01', 'Unexpected signing policy')
    require(isinstance(receipt, dict) and GIT_SHA1.fullmatch(str(receipt.get('support_commit', '')))
            and receipt.get('inputs_sha256') == hashes['source_lock']
            and receipt.get('prepared_manifest_sha256') == hashes['prepared_manifest']
            and isinstance(receipt.get('source_graph'), dict) and receipt['source_graph']
            and isinstance(receipt.get('layer'), dict) and receipt['layer'],
            'Source receipt does not bind a complete source lock')
    require(isinstance(provenance, dict) and provenance.get('schema') == 1
            and provenance.get('status') == 'UNSIGNED_TARGET_FILES_REQUIRES_INDEPENDENT_AUDIT'
            and provenance.get('profile') == 'development'
            and provenance.get('variant') == 'user'
            and provenance.get('support_commit') == receipt['support_commit']
            and provenance.get('source_receipt_sha256') == hashes['source_receipt']
            and provenance.get('target_files_sha256') == hashes['unsigned_target_files'],
            'Build provenance does not bind the source and unsigned target-files')
    environment = provenance.get('environment')
    require(isinstance(environment, dict) and environment.get('MP01_VARIANT') == 'user'
            and str(environment.get('BUILD_DATETIME')) == signer['build'].get('timestamp'),
            'Build timestamp or variant differs between provenance and signed target-files')
    if profile == 'upgrade':
        require(signer.get('previous_report_sha256') == hashes['previous_signer_report'],
                'Upgrade report does not bind the previous signer report')
        previous = documents['previous_signer_report']
        require_fields(previous, SIGNER_FIELDS, 'Previous signer report')
        require(isinstance(previous, dict) and previous.get('schema') == 'mp01-signer-profile-v2'
                and previous.get('profile') in {'initial-installation', 'upgrade'}
                and previous.get('status') in {'INITIAL_SIGNER_POLICY_PASSED',
                                                'UPGRADE_SIGNER_POLICY_PASSED'}
                and previous.get('flash_authorized') is False,
                'Previous signer report is not a release-profile baseline')
    else:
        require(signer.get('previous_report_sha256') is None,
                'Initial installation cannot carry a previous report')
    return {'schema': SCHEMA, 'status': 'BUNDLE_INTEGRITY_BOUND',
            'profile': profile, 'flash_authorized': False,
            'manifest_sha256': actual_manifest_sha256,
            'artifact_sha256': hashes,
            'system_image_in_signed_target_files_sha256': signed_system,
            'limitations': ['No full filesystem, AVB chain, framework or vendor compatibility audit',
                            'No device identity, recovery, partition or installation approval']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle-root', type=Path, required=True)
    parser.add_argument('--manifest-sha256', required=True,
                        help='authenticated out of band; never calculate it from this candidate bundle')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        require(not args.output.exists(), 'Use a new report output path')
        report = audit(args.bundle_root, args.manifest_sha256)
        payload = (json.dumps(report, indent=2, sort_keys=True) + '\n').encode()
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        print('BUNDLE_INTEGRITY_BOUND; flash authorization and whole-artifact audit remain required')
        return 0
    except (AuditError, OSError, ValueError, TypeError, KeyError, zipfile.BadZipFile,
            zipfile.LargeZipFile) as exc:
        print(f'BLOCKED: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
