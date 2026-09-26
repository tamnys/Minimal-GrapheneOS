#!/usr/bin/env python3
"""Independent signer gate profiles. Passing this gate never authorizes flashing."""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import zipfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('mp01_signer_verifier', HERE.parent / 'scripts/signer_compatibility.py')
SIGNERS = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = SIGNERS
spec.loader.exec_module(SIGNERS)
PROFILES = ('development', 'initial-installation', 'upgrade')


def require(ok, message):
    if not ok:
        raise SIGNERS.GateError(message)


def pinned_json(path, digest):
    require(path is not None and digest is not None, 'A trusted document and its independently authenticated SHA256 are required')
    SIGNERS._validate_sha256(digest, 'trusted document SHA256')
    raw = path.read_bytes()
    require(hashlib.sha256(raw).hexdigest() == digest, 'Trusted document hash mismatch')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, 'Duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)


def package_map(identities):
    result = SIGNERS._collapse_package_identities(tuple(identities), 'release signer inventory')
    require(any(k[0] == 'apk' for k in result) and any(k[0] == 'apex' for k in result),
            'Release inventory needs both APK and APEX coverage')
    for identity in identities:
        SIGNERS._validate_identity(identity, 'release identity')
        long_version_code(identity)
    return {kind + ':' + package: identity for (kind, package), identity in result.items()}


def long_version_code(identity):
    require(identity.version_code.isdigit() and identity.version_code_major.isdigit(),
            'Both versionCode and versionCodeMajor are required for every package')
    require(int(identity.version_code_major) < (1 << 31),
            'versionCodeMajor sign bit must be clear for release ordering')
    return (int(identity.version_code_major) << 32) | int(identity.version_code)


def check_profile(profile, actual, build, vendor_baseline_sha256, policy=None, previous=None, file_hashes=None):
    require(profile in PROFILES, 'Unknown artifact profile')
    require(actual, 'Empty signer inventory')
    require(build.get('product') == 'mp01', 'Target-files is not the MP01 product')
    SIGNERS._validate_sha256(vendor_baseline_sha256, 'vendor baseline SHA256')
    packages = package_map(actual)
    if profile == 'development':
        require(previous is None, 'Development artifacts cannot establish upgrade continuity')
        return 'DEVELOPMENT_ONLY'
    require(build.get('variant') == 'user', 'Production candidates require the user build variant')
    require(policy is not None and policy.get('schema') == 'mp01-signing-policy-v1'
            and policy.get('product') == 'mp01', 'Expected project public signing policy')
    require(set(policy) == {'schema', 'product', 'project_certificates', 'packages'}, 'Unexpected signing policy fields')
    test_certs = set(json.loads((HERE / 'public-test-certificates.json').read_text()).values())
    project_certs = set(policy['project_certificates'])
    require(project_certs and not project_certs & test_certs, 'Project signing policy contains public test certificates')
    for cert in project_certs:
        SIGNERS._validate_sha256(cert, 'project certificate')
    require(set(policy['packages']) == set(packages), 'Signing policy must cover exactly every APK/APEX package')
    for key, actual_identity in packages.items():
        wanted = policy['packages'][key]
        require(set(wanted) == {'authority', 'signer_cert_sha256', 'container_cert_sha256', 'payload_pubkey_sha256', 'file_sha256'}, 'Unexpected package policy fields')
        require(wanted['authority'] in {'project', 'upstream-presigned'}, 'Unknown signing authority')
        for field in ['signer_cert_sha256', 'container_cert_sha256', 'payload_pubkey_sha256']:
            require(wanted[field] == getattr(actual_identity, field), f'{key}: {field} changed')
        certs = {actual_identity.signer_cert_sha256}
        if actual_identity.kind == 'apex':
            certs.add(actual_identity.container_cert_sha256)
        require(not certs & test_certs, f'{key}: public test certificate')
        if wanted['authority'] == 'project':
            require(certs <= project_certs, f'{key}: not signed by project release keys')
            require(wanted['file_sha256'] is None, 'Project-signed APK bytes change when signing')
        else:
            require(file_hashes is not None, 'Presigned packages need exact byte verification')
            SIGNERS._validate_sha256(wanted['file_sha256'], 'upstream-presigned archive SHA256')
            # Check every copy of this package, not only the first inventory row.
            for identity in actual:
                if identity.package_key == actual_identity.package_key:
                    require(file_hashes.get(identity.source_path) == wanted['file_sha256'],
                            f'{key}: upstream-presigned bytes were changed')
    # The platform identity may never be mislabeled as an upstream app.
    require('apk:android' in packages and policy['packages']['apk:android']['authority'] == 'project',
            'Android platform must use the project signing identity')
    if profile == 'initial-installation':
        require(previous is None, 'Initial installation must not carry an upgrade baseline')
        return 'INITIAL_SIGNER_POLICY_PASSED'
    require(previous is not None and previous.get('schema') == 'mp01-signer-profile-v2',
            'Upgrade requires a trusted previous MP01 v2 report with versionCodeMajor')
    require(previous.get('profile') in {'initial-installation', 'upgrade'}
            and previous.get('status') in {'INITIAL_SIGNER_POLICY_PASSED', 'UPGRADE_SIGNER_POLICY_PASSED'},
            'A development or failed report cannot become an upgrade baseline')
    require(previous['vendor_baseline_sha256'] == vendor_baseline_sha256, 'Vendor baseline changed; this USB path updates only system')
    require(previous['build']['product'] == 'mp01' and previous['build']['variant'] == 'user', 'Unexpected previous product')
    require(int(build['timestamp']) > int(previous['build']['timestamp']), 'Upgrade timestamp must advance')
    require(int(build['sdk']) >= int(previous['build']['sdk']), 'Android downgrade is forbidden')
    previous_rows = previous.get('identities')
    require(isinstance(previous_rows, list) and previous_rows and all(
        isinstance(row, dict) and set(row) == set(SIGNERS.COLUMNS) for row in previous_rows
    ), 'Previous report lacks complete package version information')
    old = package_map([SIGNERS.Identity(**row) for row in previous_rows])
    for key, identity in old.items():
        require(key in packages, f'Installed package removed: {key}; explicit migration review required')
        require(SIGNERS._signer_values(identity) == SIGNERS._signer_values(packages[key]),
                f'Upgrade changes installed signer: {key}')
        require(long_version_code(packages[key]) >= long_version_code(identity), f'Package downgrade: {key}')
    return 'UPGRADE_SIGNER_POLICY_PASSED'


def archive_metadata(path, identities):
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        require(len(names) == len(set(names)), 'Duplicate target-files ZIP member')
        require('SYSTEM/build.prop' in names and 'IMAGES/system.img' in names, 'Missing system properties/image')
        props_info = archive.getinfo('SYSTEM/build.prop')
        require(props_info.file_size < 1024 * 1024, 'Oversized build properties')
        props = {}
        for line in archive.read(props_info).decode().splitlines():
            if line and not line.startswith('#') and '=' in line:
                key, value = line.split('=', 1)
                require(key not in props, f'Duplicate system property: {key}')
                props[key] = value
        build = {'product': props.get('ro.product.system.device', props.get('ro.product.device')),
                 'variant': props.get('ro.build.type', props.get('ro.system.build.type')),
                 'timestamp': props.get('ro.build.date.utc', props.get('ro.system.build.date.utc')),
                 'sdk': props.get('ro.build.version.sdk', props.get('ro.system.build.version.sdk'))}
        require(str(build['timestamp']).isdigit() and str(build['sdk']).isdigit(), 'Missing build timestamp/SDK')
        hashes = {}
        for name in ['IMAGES/system.img', *[i.source_path for i in identities]]:
            info = archive.getinfo(name)
            require(0 < info.file_size <= SIGNERS.MAX_TARGET_FILES_SIZE, 'Invalid archive member size')
            with archive.open(info) as f:
                h = hashlib.sha256()
                for block in iter(lambda: f.read(4 * 1024 * 1024), b''):
                    h.update(block)
                hashes[name] = h.hexdigest()
        return build, hashes


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--profile', choices=PROFILES, required=True)
    p.add_argument('--target-files', type=Path, required=True)
    p.add_argument('--vendor-baseline-sha256', required=True)
    p.add_argument('--policy', type=Path)
    p.add_argument('--policy-sha256')
    p.add_argument('--previous-report', type=Path)
    p.add_argument('--previous-report-sha256')
    p.add_argument('--otatools-dir', type=Path, required=True)
    p.add_argument('--apksigner-java', type=Path, required=True)
    p.add_argument('--apksigner-jar', type=Path, required=True)
    p.add_argument('--apksigner-java-home', type=Path, required=True)
    p.add_argument('--apksigner-java-tmpdir', type=Path, required=True)
    p.add_argument('--apksigner-java-sha256', required=True)
    p.add_argument('--apksigner-jar-sha256', required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args(argv)
    try:
        require(not args.output.exists(), 'Use a new report output path')
        policy = pinned_json(args.policy, args.policy_sha256) if args.profile != 'development' else None
        require((args.previous_report is not None) == (args.profile == 'upgrade'), 'Only upgrades take a previous release report')
        previous = pinned_json(args.previous_report, args.previous_report_sha256) if args.previous_report else None
        tools = SIGNERS.resolve_tools(args.otatools_dir,
            apksigner_java_override=args.apksigner_java, apksigner_jar_override=args.apksigner_jar,
            apksigner_java_home=args.apksigner_java_home, apksigner_java_tmpdir=args.apksigner_java_tmpdir,
            apksigner_java_sha256=args.apksigner_java_sha256, apksigner_jar_sha256=args.apksigner_jar_sha256)
        with SIGNERS.target_files_snapshot(args.target_files, None) as snapshot:
            identities = SIGNERS.inventory_target_files(snapshot.path, tools)
            build, hashes = archive_metadata(snapshot.path, identities)
            status = check_profile(args.profile, identities, build, args.vendor_baseline_sha256,
                                   policy, previous, hashes)
            report = {'schema': 'mp01-signer-profile-v2', 'profile': args.profile, 'status': status,
                      'flash_authorized': False, 'target_files_sha256': snapshot.sha256,
                      'system_image_sha256': hashes['IMAGES/system.img'], 'build': build,
                      'vendor_baseline_sha256': args.vendor_baseline_sha256,
                      'policy_sha256': args.policy_sha256, 'previous_report_sha256': args.previous_report_sha256,
                      'identities': [dataclasses.asdict(i) for i in identities],
                      'verifier_sha256': SIGNERS.sha256_file(Path(__file__)),
                      'public_test_certificates_sha256': SIGNERS.sha256_file(HERE / 'public-test-certificates.json'),
                      'inventory_tool_sha256': SIGNERS.sha256_file(HERE.parent / 'scripts/signer_compatibility.py')}
            SIGNERS.atomic_write(args.output, (json.dumps(report, indent=2, sort_keys=True) + '\n').encode())
        print(status + '; full artifact audit, device validation and installation approval remain required')
        return 0
    except (SIGNERS.GateError, OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile) as exc:
        print(f'BLOCKED: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
