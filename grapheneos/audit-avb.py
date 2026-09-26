#!/usr/bin/env python3
"""Verify one signed MP01 system image's AVB identity; never authorize flashing."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('mp01_avb_snapshot', HERE.parent / 'scripts/signer_compatibility.py')
SNAPSHOT = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = SNAPSHOT
spec.loader.exec_module(SNAPSHOT)

# SHA256 of the AVB public-key blobs extracted from upstream's bundled test
# private keys. The inherited GSI board configuration selects the first two.
PUBLIC_TEST_AVB_KEYS = {
    '22de3994532196f61c039e90260d78a93a4c57362c7e789be928036e80b77c8c',  # RSA2048
    '2bed47451bc698e9e82d92a6668bd03ab6cf8dd1a144341cb7f426f20b2879cf',  # RSA2048_2
    '7728e30f50bfa5cea165f473175a08803f6a8346642b5aa10913e9d9e6defef6',  # RSA4096
    'e15e2365469ce672a91d02cc8d9c2f29b787481e574d3b56ac774153d7ced614',  # RSA8192
}


def require(ok, message):
    if not ok:
        raise SNAPSHOT.GateError(message)


def one_match(pattern, value, label):
    matches = re.findall(pattern, value, flags=re.MULTILINE)
    require(len(matches) == 1, f'Expected exactly one {label} in AVB metadata')
    return matches[0]


def parse_avb_info(info):
    footer = one_match(r'^Footer version:\s*([0-9]+\.[0-9]+)\s*$', info, 'footer')
    image_size = int(one_match(r'^Image size:\s*([0-9]+) bytes\s*$', info, 'image size'))
    original_size = int(one_match(r'^Original image size:\s*([0-9]+) bytes\s*$', info, 'original image size'))
    algorithm = one_match(r'^Algorithm:\s*(\S+)\s*$', info, 'signature algorithm')
    require(re.fullmatch(r'SHA(?:256|512)_RSA(?:2048|4096|8192)', algorithm),
            'AVB image must use a signed RSA algorithm')
    require(image_size > original_size > 0, 'Invalid AVB footer image sizes')
    flags = re.findall(r'^\s*Flags:\s*([0-9]+)\s*$', info, flags=re.MULTILINE)
    require(len(flags) == 2 and all(flag == '0' for flag in flags),
            'AVB verification/hashtree flags must be zero')
    descriptors = re.findall(r'^    ([A-Za-z ]+) descriptor:\s*$', info, flags=re.MULTILINE)
    require(descriptors == ['Hashtree'], 'Expected exactly one system hashtree descriptor')
    require(one_match(r'^      Partition Name:\s*(\S+)\s*$', info, 'partition name') == 'system',
            'AVB hashtree is not for the system partition')
    require(one_match(r'^      Hash Algorithm:\s*(\S+)\s*$', info, 'hashtree algorithm') == 'sha256',
            'AVB hashtree must use SHA256')
    tree_size = int(one_match(r'^      Tree Size:\s*([0-9]+) bytes\s*$', info, 'hashtree size'))
    require(tree_size > 0, 'AVB hashtree is empty')
    root_digest = one_match(r'^      Root Digest:\s*([0-9a-f]{64})\s*$', info, 'hashtree root digest')
    return {'footer_version': footer, 'image_size': image_size,
            'original_image_size': original_size, 'algorithm': algorithm,
            'hashtree_root_digest': root_digest}


def run_tool(tool, *args):
    command = [sys.executable, str(tool), *map(str, args)]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, encoding='utf-8', errors='strict', check=False)
    require(result.returncode == 0,
            f'avbtool {args[0]} failed: {result.stderr.strip()[:1000]}')
    return result.stdout


def audit(image, image_sha256, expected_public_key_sha256, avbtool, avbtool_sha256):
    for label, digest in [('image', image_sha256), ('expected project AVB public key', expected_public_key_sha256),
                          ('avbtool', avbtool_sha256)]:
        SNAPSHOT._validate_sha256(digest, label)
    require(expected_public_key_sha256 not in PUBLIC_TEST_AVB_KEYS,
            'A public AVB test key cannot be the project release key')
    with tempfile.TemporaryDirectory(prefix='mp01-avb-audit-') as directory:
        temporary = Path(directory)
        image_copy = SNAPSHOT.create_target_files_snapshot(image, temporary / 'system.img')
        tool_copy = SNAPSHOT.create_target_files_snapshot(avbtool, temporary / 'avbtool.py')
        require(tool_copy.size < 1024 * 1024, 'AVB verifier is unexpectedly large')
        require(tool_copy.sha256 == avbtool_sha256, 'Pinned avbtool SHA256 mismatch')
        require(image_copy.sha256 == image_sha256, 'Signed system image SHA256 mismatch')
        pubkey = temporary / 'system.avbpubkey'
        info = run_tool(tool_copy.path, 'info_image', '--image', image_copy.path,
                        '--output_pubkey', pubkey)
        metadata = parse_avb_info(info)
        require(pubkey.is_file() and 0 < pubkey.stat().st_size <= 16 * 1024,
                'AVB image has no supported embedded public key')
        actual_key_sha256 = hashlib.sha256(pubkey.read_bytes()).hexdigest()
        require(actual_key_sha256 not in PUBLIC_TEST_AVB_KEYS,
                'Signed system image uses a public AVB test key')
        require(actual_key_sha256 == expected_public_key_sha256,
                'Signed system image AVB public key does not match project key')
        verification = run_tool(tool_copy.path, 'verify_image', '--image', image_copy.path)
        require(len(re.findall(r'^system: Successfully verified sha256 hashtree of ',
                               verification, flags=re.MULTILINE)) == 1,
                'AVB verification did not confirm the system hashtree')
        require(SNAPSHOT.sha256_file(image_copy.path) == image_sha256,
                'Signed system image changed during AVB verification')
        require(SNAPSHOT.sha256_file(tool_copy.path) == avbtool_sha256,
                'AVB verifier changed during execution')
        return {'schema': 'mp01-avb-audit-v1', 'status': 'AVB_IMAGE_IDENTITY_PASSED',
                'flash_authorized': False, 'image_sha256': image_sha256,
                'project_avb_public_key_sha256': actual_key_sha256,
                'avbtool_sha256': avbtool_sha256, **metadata}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--image-sha256', required=True)
    parser.add_argument('--expected-public-key-sha256', required=True)
    parser.add_argument('--avbtool', type=Path, required=True)
    parser.add_argument('--avbtool-sha256', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        require(not args.output.exists(), 'Use a new AVB report output path')
        report = audit(args.image, args.image_sha256, args.expected_public_key_sha256,
                       args.avbtool, args.avbtool_sha256)
        SNAPSHOT.atomic_write(args.output, (json.dumps(report, indent=2, sort_keys=True) + '\n').encode())
        print('AVB_IMAGE_IDENTITY_PASSED; full artifact audit, device validation and installation approval remain required')
        return 0
    except (SNAPSHOT.GateError, OSError, ValueError, UnicodeError, subprocess.SubprocessError) as exc:
        print(f'BLOCKED: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
