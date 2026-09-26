#!/usr/bin/env python3
"""Pinned MP01 source preparation and unsigned builds; no signing or flashing."""
from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
WORKSPACE = REPO.parent
SOURCE = WORKSPACE / '.android-build/grapheneos-17'
STATE = WORKSPACE / '.android-build/grapheneos-17-state'
GIB = 1024 ** 3
SHA1 = re.compile(r'[0-9a-f]{40}')


class BuildError(ValueError):
    pass


class BlobMismatch(BuildError):
    pass


def require(ok, message):
    if not ok:
        raise BuildError(message)


def sha256(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(4 * 1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def write_json(path, value):
    with path.open('x') as f:
        json.dump(value, f, indent=2, sort_keys=True)
        f.write('\n')
        f.flush()
        os.fsync(f.fileno())


def safe_relative(value):
    p = PurePosixPath(value)
    require(bool(value) and value not in {'.', '..'} and not p.is_absolute() and p.as_posix() == value
            and '..' not in p.parts and '.' not in p.parts,
            f'Unsafe relative path: {value!r}')
    return value


def checked_directory(path):
    require(path.is_absolute(), 'Workspace paths must be absolute')
    for part in (path, *path.parents):
        require(not part.is_symlink(), f'Symlink workspace component: {part}')
        require(not part.exists() or part.is_dir(), f'Not a directory: {part}')
    path.mkdir(parents=True, exist_ok=True)
    return path


def command(args, cwd=REPO, **kwargs):
    argv = [str(a) for a in args]
    if argv and argv[0] in {'git', 'repo'}:
        environment = dict(kwargs.pop('env', os.environ))
        for key in list(environment):
            if key.startswith('GIT_'):
                environment.pop(key)
        environment['GIT_NO_REPLACE_OBJECTS'] = '1'
        environment['GIT_TERMINAL_PROMPT'] = '0'
        if argv[0] == 'repo':
            environment['PYTHONDONTWRITEBYTECODE'] = '1'
        else:
            environment['GIT_ATTR_NOSYSTEM'] = '1'
            argv.insert(1, '--no-replace-objects')
        kwargs['env'] = environment
    return subprocess.check_output(argv, cwd=cwd, **kwargs)


def _git_records(raw, label, oid_field):
    records = {}
    for item in raw.split(b'\0'):
        if not item:
            continue
        metadata, separator, name = item.partition(b'\t')
        fields = metadata.split()
        require(separator and len(fields) == 3 and len(fields[oid_field]) == 40
                and SHA1.fullmatch(fields[oid_field].decode('ascii')),
                f'Malformed {label} entry')
        relative = safe_relative(os.fsdecode(name))
        require(relative not in records, f'Duplicate {label} entry: {relative}')
        records[relative] = tuple(fields)
    return records


def _stable_file_fields(before, after):
    return all(getattr(before, field) == getattr(after, field) for field in
               ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def _verify_worktree_blob(path, relative, mode, expected_oid, checked_directories=None,
                          *, allow_crlf=False):
    source = path / relative
    if checked_directories is None:
        checked_directories = {}
    try:
        directory = path
        for part in PurePosixPath(relative).parts[:-1]:
            directory = directory / part
            if directory not in checked_directories:
                parent_stat = directory.lstat()
                require(stat.S_ISDIR(parent_stat.st_mode),
                        f'Source parent is not an ordinary directory: {directory}')
                checked_directories[directory] = parent_stat
        if mode == b'160000':
            require(source.is_dir() and not source.is_symlink()
                    and not any(source.iterdir()),
                    f'Gitlink must remain an empty directory: {source}')
            return
        if mode == b'120000':
            before = source.lstat()
            require(stat.S_ISLNK(before.st_mode), f'Layer source type changed: {source}')
            target = os.fsencode(os.readlink(source))
            digest = hashlib.sha1(f'blob {len(target)}\0'.encode() + target).hexdigest()
            after = source.lstat()
            require(_stable_file_fields(before, after), f'Source changed during verification: {source}')
        else:
            descriptor = os.open(source, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0))
            try:
                with os.fdopen(descriptor, 'rb') as stream:
                    descriptor = -1
                    before = os.fstat(stream.fileno())
                    require(stat.S_ISREG(before.st_mode), f'Source file type changed: {source}')
                    require(bool(before.st_mode & 0o111) == (mode == b'100755'),
                            f'Source executable mode changed: {source}')
                    hasher = hashlib.sha1(f'blob {before.st_size}\0'.encode())
                    size = 0
                    cr_count = lf_count = crlf_count = 0
                    previous_cr = False
                    for block in iter(lambda: stream.read(4 * 1024 * 1024), b''):
                        size += len(block)
                        hasher.update(block)
                        if allow_crlf:
                            cr_count += block.count(b'\r')
                            lf_count += block.count(b'\n')
                            crlf_count += block.count(b'\r\n')
                            crlf_count += int(previous_cr and block.startswith(b'\n'))
                            previous_cr = block.endswith(b'\r')
                    digest = hasher.hexdigest()
                    if allow_crlf and digest != expected_oid.decode('ascii'):
                        require(crlf_count > 0 and cr_count == lf_count == crlf_count,
                                f'Invalid CRLF checkout conversion: {source}')
                        stream.seek(0)
                        normalized = hashlib.sha1(
                            f'blob {before.st_size - crlf_count}\0'.encode())
                        carry = b''
                        for block in iter(lambda: stream.read(4 * 1024 * 1024), b''):
                            data = carry + block
                            carry = b'\r' if data.endswith(b'\r') else b''
                            if carry:
                                data = data[:-1]
                            normalized.update(data.replace(b'\r\n', b'\n'))
                        require(not carry, f'Invalid CRLF checkout conversion: {source}')
                        digest = normalized.hexdigest()
                    after = os.fstat(stream.fileno())
                current = source.lstat()
                require(size == before.st_size and _stable_file_fields(before, after)
                        and _stable_file_fields(before, current),
                        f'Source changed during verification: {source}')
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
        if digest != expected_oid.decode('ascii'):
            raise BlobMismatch(f'Source bytes differ from committed blob: {source}')
    except OSError as exc:
        raise BuildError(f'Cannot verify committed source file: {source}') from exc


def _committed_crlf_attribute(path, relative):
    marker = path / '.git'
    gitdir = marker.resolve(strict=True) if marker.is_symlink() else marker
    local_info = gitdir / 'info'
    require(local_info.is_dir() and not local_info.is_symlink(),
            f'Git attribute metadata is not an ordinary directory: {local_info}')
    local_attributes = local_info / 'attributes'
    require(not local_attributes.exists() and not local_attributes.is_symlink(),
            f'Local Git attributes may override committed attributes: {local_attributes}')
    raw = command(['git', '-c', 'core.attributesFile=/dev/null', 'check-attr',
                   '--cached', '--all', '-z', '--', relative], path)
    fields = raw.split(b'\0')
    require(fields[-1] == b'', f'Malformed Git attributes: {relative}')
    fields.pop()
    require(len(fields) % 3 == 0, f'Malformed Git attributes: {relative}')
    attrs = {}
    for name, attribute, value in zip(fields[0::3], fields[1::3], fields[2::3]):
        require(name == os.fsencode(relative) and attribute not in attrs and attribute,
                f'Malformed Git attributes: {relative}')
        attrs[attribute] = value
    return (attrs.get(b'eol') == b'crlf'
            and attrs.get(b'text') in {None, b'auto', b'set'}
            and not any(attribute in attrs for attribute in
                        (b'filter', b'working-tree-encoding', b'ident')))


def _verify_git_metadata_location(path):
    marker = path / '.git'
    if path == REPO or path == SOURCE / '.repo/repo':
        require(marker.is_dir() and not marker.is_symlink(),
                f'Unexpected Git metadata location: {marker}')
        return
    if path == SOURCE / '.repo/manifests':
        expected = SOURCE / '.repo/manifests.git'
        target = '../manifests.git'
    elif path.is_relative_to(SOURCE) and path != SOURCE:
        relative = path.relative_to(SOURCE)
        expected = SOURCE / '.repo/projects' / (relative.as_posix() + '.git')
        target = os.path.relpath(expected, path)
    else:
        require(marker.is_dir() and not marker.is_symlink(),
                f'Unexpected Git metadata location: {marker}')
        return
    try:
        require(marker.is_symlink() and os.readlink(marker) == target,
                f'Git metadata redirect changed: {marker}')
        directory = expected
        while directory != SOURCE:
            require(stat.S_ISDIR(directory.lstat().st_mode),
                    f'Git metadata directory is not ordinary: {directory}')
            directory = directory.parent
    except OSError as exc:
        raise BuildError(f'Cannot verify Git metadata redirect: {marker}') from exc


def clean_head(path):
    # Git status can skip changed files marked assume-unchanged/skip-worktree.
    # Ignored files can also affect the repo tool and Android build execution.
    path = Path(path)
    try:
        require(stat.S_ISDIR(path.lstat().st_mode), f'Source checkout is not a directory: {path}')
    except OSError as exc:
        raise BuildError(f'Cannot inspect source checkout: {path}') from exc
    _verify_git_metadata_location(path)
    require(not command(['git', 'status', '--porcelain', '--untracked-files=all',
                         '--ignored=matching'], path),
            f'Commit or preserve uncommitted source before building: {path}')
    require(not command(['git', 'for-each-ref', '--format=%(refname)', 'refs/replace'], path),
            f'Git replace refs are forbidden in source checkout: {path}')
    head_before = command(['git', 'rev-parse', 'HEAD'], path).decode().strip()
    require(SHA1.fullmatch(head_before), f'Invalid source HEAD: {path}')
    tree = _git_records(command(['git', 'ls-tree', '-rz', '--full-tree', head_before], path),
                        'HEAD tree', 2)
    index = _git_records(command(['git', 'ls-files', '--stage', '-z'], path), 'index', 1)
    require(all(len(fields) == 3 and fields[2] == b'0' for fields in index.values()),
            f'Unmerged index entry: {path}')
    require({name: (fields[0], fields[1]) for name, fields in index.items()} ==
            {name: (fields[0], fields[2]) for name, fields in tree.items()},
            f'Index differs from committed HEAD: {path}')
    flags = command(['git', 'ls-files', '-v', '-z'], path).split(b'\0')
    flagged = {}
    for item in flags:
        if not item:
            continue
        tag, separator, name = item.partition(b' ')
        require(separator, f'Malformed index flag entry: {path}')
        relative = safe_relative(os.fsdecode(name))
        require(relative not in flagged, f'Duplicate index flag entry: {relative}')
        flagged[relative] = tag
    require(set(flagged) == set(tree) and all(tag == b'H' for tag in flagged.values()),
            f'Suppressed or unexpected index state: {path}')
    checked_directories = {}
    crlf_fallbacks = 0
    for relative, (mode, kind, oid) in tree.items():
        require((mode in {b'100644', b'100755', b'120000'} and kind == b'blob')
                or (mode == b'160000' and kind == b'commit'),
                f'Unsupported committed source type: {path / relative}')
        try:
            _verify_worktree_blob(path, relative, mode, oid, checked_directories)
        except BlobMismatch:
            require(mode in {b'100644', b'100755'}
                    and _committed_crlf_attribute(path, relative),
                    f'Source bytes differ from committed blob: {path / relative}')
            _verify_worktree_blob(path, relative, mode, oid, checked_directories,
                                  allow_crlf=True)
            crlf_fallbacks += 1
    for directory, before in checked_directories.items():
        try:
            after = directory.lstat()
        except OSError as exc:
            raise BuildError(f'Source directory disappeared during verification: {directory}') from exc
        require(stat.S_ISDIR(after.st_mode) and _stable_file_fields(before, after),
                f'Source directory changed during verification: {directory}')
    if crlf_fallbacks:
        require(_git_records(command(['git', 'ls-files', '--stage', '-z'], path),
                             'index', 1) == index,
                f'Index changed during CRLF verification: {path}')
    require(command(['git', 'rev-parse', 'HEAD'], path).decode().strip() == head_before,
            f'Source HEAD changed during verification: {path}')
    return head_before


def clean_source_head(path):
    return clean_head(path)


def source_graph(raw):
    """Compare effective URLs, commits and copy/link instructions, not XML layout."""
    root = ET.fromstring(raw)
    require(root.tag == 'manifest', 'Expected repo manifest')
    require(all(n.tag in {'project', 'remote', 'default', 'superproject', 'contactinfo'}
                for n in root), 'Unresolved/unsupported source manifest directive')
    remotes = {r.get('name'): r.attrib for r in root.findall('remote')}
    require(len(remotes) == len(root.findall('remote')), 'Duplicate manifest remote')
    defaults = root.findall('default')
    require(len(defaults) <= 1, 'Duplicate manifest default')
    default = defaults[0].attrib if defaults else {}
    records = {}
    for p in root.findall('project'):
        name = safe_relative(p.get('name', ''))
        path = safe_relative(p.get('path', name))
        require(path not in records, f'Duplicate project: {path}')
        remote = remotes.get(p.get('remote', default.get('remote')))
        require(remote is not None, f'Unknown remote: {path}')
        fetch = remote.get('fetch', '').rstrip('/')
        require(fetch.startswith('https://') and '@' not in fetch and '?' not in fetch
                and '#' not in fetch, f'Non-public HTTPS source: {path}')
        revision = p.get('revision', remote.get('revision', default.get('revision', '')))
        require(SHA1.fullmatch(revision), f'Moving source revision: {path}')
        links = []
        for link in p:
            require(link.tag in {'copyfile', 'linkfile'}, f'Unsupported project child: {path}')
            require(set(link.attrib) == {'src', 'dest'}, 'Unexpected link/copy attributes')
            # repo permits src="." for linking a complete project directory.
            src = link.get('src')
            if src != '.':
                safe_relative(src)
            links.append((link.tag, src, safe_relative(link.get('dest'))))
        records[path] = {'url': fetch + '/' + name, 'revision': revision,
                         'links': sorted(links)}
    require(records, 'Empty source graph')
    return records


def inputs():
    value = json.loads((HERE / 'inputs.json').read_text())
    require(sha256(HERE / 'upstream-manifest.xml') == value['manifest_sha256'],
            'Pinned upstream manifest changed')
    require(sha256(HERE / 'upstream-allowed-signers') == value['upstream_allowed_signers_sha256'],
            'Pinned upstream public verification material changed')
    require(value['inkos_release_url'] ==
            'https://github.com/gezimos/inkOS/releases/download/v0.1/app.inkos_v0.1-Signed.apk'
            and value['inkos_source_url'] ==
            'https://github.com/gezimos/inkOS/tree/a578fef2a42ebdccb6cec29449f13b5d6381f332'
            and value['inkos_source_size'] == 4036711
            and value['inkos_sha256'] ==
            '64a3cd323ba484640cb0ba6d6d4ad1855048f0460ad852ef1f610439fa6445f8',
            'Invalid pinned upstream inkOS release')
    source_graph((HERE / 'upstream-manifest.xml').read_bytes())
    return value


def inkos_cache_path():
    return STATE / 'prebuilts/inkos_v0.1.apk'


def pinned_inkos_apk(cfg):
    """Return the offline cache entry only after checking the release byte pin."""
    apk = inkos_cache_path()
    require(apk.is_file() and not apk.is_symlink(),
            'Pinned inkOS APK is absent; run fetch-prebuilts before offline prepare')
    require(apk.stat().st_size == cfg['inkos_source_size'] and
            sha256(apk) == cfg['inkos_sha256'],
            'Cached inkOS APK differs from pinned upstream release; preserve and remove it explicitly')
    return apk


def fetch_prebuilts(cfg):
    """Fetch the official signed APK once; preparation and builds stay offline."""
    apk = inkos_cache_path()
    checked_directory(apk.parent)
    if apk.exists() or apk.is_symlink():
        pinned_inkos_apk(cfg)
        print('Verified cached inkOS APK:', apk)
        return
    temporary = None
    try:
        with urllib.request.urlopen(cfg['inkos_release_url'], timeout=60) as response:
            require(urlsplit(response.url).scheme == 'https',
                    'inkOS release redirect left HTTPS')
            with tempfile.NamedTemporaryFile(prefix='.inkos-', dir=apk.parent,
                                             delete=False) as stream:
                temporary = Path(stream.name)
                digest = hashlib.sha256()
                size = 0
                while block := response.read(1024 * 1024):
                    size += len(block)
                    require(size <= cfg['inkos_source_size'], 'inkOS download exceeds pinned size')
                    digest.update(block)
                    stream.write(block)
                stream.flush()
                os.fsync(stream.fileno())
        require(size == cfg['inkos_source_size'] and digest.hexdigest() == cfg['inkos_sha256'],
                'Downloaded inkOS APK differs from pinned upstream release')
        require(not apk.exists() and not apk.is_symlink(),
                'inkOS cache appeared during download; preserve and inspect it')
        os.replace(temporary, apk)
        temporary = None
        print('Verified upstream inkOS APK:', apk)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def memory_bytes():
    mem = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
    total = int(mem['MemTotal'].split()[0]) * 1024
    available = int(mem['MemAvailable'].split()[0]) * 1024
    # Account for a container cgroup limit as well as the guest's ballooned RAM.
    paths = [Path('/sys/fs/cgroup')]
    for row in Path('/proc/self/cgroup').read_text().splitlines():
        if row.startswith('0::'):
            path = Path('/sys/fs/cgroup') / row[3:].lstrip('/')
            paths += [path, *path.parents]
    for path in paths:
        limit = path / 'memory.max'
        used = path / 'memory.current'
        if limit.is_file():
            raw = limit.read_text().strip()
            if raw != 'max':
                total = min(total, int(raw))
                if used.is_file():
                    available = min(available, max(0, int(raw) - int(used.read_text())))
    return total, available


def sync_source_allocated_bytes(cfg):
    """Credit only an initialized, pinned checkout on the workspace filesystem."""
    for part in (SOURCE, *SOURCE.parents):
        require(not part.is_symlink(), f'Symlink source component: {part}')
        require(not part.exists() or part.is_dir(), f'Not a source directory: {part}')
    if not SOURCE.exists():
        return 0
    if os.stat(SOURCE).st_dev != os.stat(WORKSPACE).st_dev:
        return 0
    metadata = SOURCE / '.repo'
    if not metadata.exists():
        return 0
    require(metadata.is_dir() and not metadata.is_symlink(), 'Invalid repo metadata directory')
    manifest = metadata / 'manifests'
    repo_tool = metadata / 'repo'
    if not manifest.is_dir() or not repo_tool.is_dir() or not (manifest / 'default.xml').is_file():
        return 0  # An interrupted repo init has not established a trusted source checkout.
    require(not manifest.is_symlink() and not repo_tool.is_symlink(), 'Symlink repo checkout')
    require(command(['git', 'rev-parse', 'HEAD'], manifest).decode().strip() == cfg['manifest_commit'],
            'Existing source manifest commit differs from the pin')
    require(command(['git', 'rev-parse', 'HEAD'], repo_tool).decode().strip() == cfg['repo_commit'],
            'Existing repo tool commit differs from the pin')
    require(sha256(manifest / 'default.xml') == cfg['manifest_sha256'],
            'Existing source manifest differs from the pin')
    # GNU du reports allocated filesystem blocks and does not follow symlinks.
    # Excluding out prevents a prior build from being credited as downloaded source.
    raw = command(['du', '-sx', '--block-size=1', '--exclude=out', '--', SOURCE])
    return int(raw.split(None, 1)[0])


def synced_build_budget_bytes(cfg):
    return (cfg['output_growth_budget_gib'] + cfg['packaging_budget_gib']
            + cfg['cache_budget_gib'] + cfg['reserve_gib']) * GIB


def resource_report(cfg, phase):
    total, available = memory_bytes()
    free = shutil.disk_usage(WORKSPACE).free
    budget_bytes = cfg['reserve_gib'] * GIB if phase == 'prepare' else synced_build_budget_bytes(cfg)
    source_credit = 0
    if phase == 'sync':
        source_budget = cfg['source_growth_budget_gib'] * GIB
        source_credit = min(sync_source_allocated_bytes(cfg), source_budget)
        budget_bytes += source_budget - source_credit
    problems = []
    if phase == 'build' and total < cfg['minimum_ram_gib'] * GIB:
        problems.append('At least 32 GiB RAM must be allocated to the guest/container now; swap and maximum balloon limits do not count')
    if phase == 'build' and available < (cfg['minimum_ram_gib'] - 4) * GIB:
        problems.append('At least 28 GiB RAM must be currently available')
    if free < budget_bytes:
        problems.append(f'Need at least {budget_bytes / GIB:.2f} GiB free for {phase}, '
                        'including packaging/cache and a 50 GiB reserve')
    marker = Path('/opt/mp01/builder')
    if not marker.is_file() or marker.read_text().strip() != 'mp01-debian12-v1':
        problems.append('Run through grapheneos/container.sh in the pinned Debian 12 image')
    if not os.environ.get('MP01_BUILDER_IMAGE_ID'):
        problems.append('Missing exact built container image identity')
    return {'phase': phase, 'ram_bytes': total, 'available_ram_bytes': available,
            'free_bytes': free, 'required_free_bytes': budget_bytes,
            'source_sync_credit_bytes': source_credit,
            'maximum_jobs': cfg['maximum_jobs'], 'problems': problems}


def patches(cfg):
    rows = json.loads((HERE / 'patches/series.json').read_text())
    require(isinstance(rows, list), 'Patch series must be a list')
    graph = source_graph((HERE / 'upstream-manifest.xml').read_bytes())
    for row in rows:
        require(set(row) == {'project', 'file', 'sha256', 'base_revision', 'result_revision', 'reason'},
                'Each compatibility patch needs exact before/after commits, hash and rationale')
        path = safe_relative(row['project'])
        file = HERE / 'patches' / safe_relative(row['file'])
        require(path in graph and graph[path]['revision'] == row['base_revision'], 'Patch base is not the locked source')
        require(SHA1.fullmatch(row['result_revision']), 'Patch result must be a full commit')
        require(sha256(file) == row['sha256'] and row['reason'].strip(), 'Patch digest/rationale missing')
        graph[path]['revision'] = row['result_revision']
    return rows, graph


def verify_upstream_checkout(cfg):
    """Verify the already downloaded release tag and tools without fetching."""
    for part in (SOURCE, *SOURCE.parents):
        require(not part.is_symlink(), f'Symlink source component: {part}')
    metadata = SOURCE / '.repo'
    require(metadata.is_dir() and not metadata.is_symlink(), 'Missing or symlinked repo metadata')
    require(clean_head(SOURCE / '.repo/repo') == cfg['repo_commit'], 'repo tool changed')
    require(clean_head(SOURCE / '.repo/manifests') == cfg['manifest_commit'], 'Upstream manifest repository changed')
    require(sha256(SOURCE / '.repo/manifests/default.xml') == cfg['manifest_sha256'],
            'Upstream manifest file changed')
    require(not (SOURCE / '.repo/local_manifests').exists(), 'Unexpected local manifests')
    tag = 'refs/tags/' + cfg['grapheneos_release']
    manifest = SOURCE / '.repo/manifests'
    require(command(['git', 'rev-parse', tag], manifest).decode().strip()
            == cfg['manifest_tag_object'], 'Wrong upstream signed tag object')
    require(command(['git', 'rev-parse', tag + '^{}'], manifest).decode().strip()
            == cfg['manifest_commit'], 'Signed tag does not identify pinned manifest commit')
    command(['git', '-c', 'gpg.ssh.allowedSignersFile=' + str(HERE / 'upstream-allowed-signers'),
             'verify-tag', tag], manifest)


def verify_source(expected, cfg=None):
    cfg = cfg or inputs()
    verify_upstream_checkout(cfg)
    raw = command(['repo', 'manifest', '-r'], SOURCE)
    actual = source_graph(raw)
    require(actual == expected, 'Live source graph differs from pinned URLs/revisions/link instructions')
    for path, record in expected.items():
        require(clean_source_head(SOURCE / path) == record['revision'], f'Source changed: {path}')
    return raw


def verify_source_layout(graph, *, allow_build_output=False):
    """Reject root entries outside pinned inputs and, after a build, its output."""
    tree = {}
    paths = {'.repo', 'device/mp01', 'vendor/MP01_services', 'vendor/inkos'}
    paths.update(graph)
    for record in graph.values():
        paths.update(dest for _, _, dest in record['links'])
    if allow_build_output:
        paths.add('out')
    for relative in paths:
        node = tree
        for part in PurePosixPath(relative).parts:
            node = node.setdefault(part, {})
        node[None] = True

    def visit(directory, node):
        for child in directory.iterdir():
            branch = node.get(child.name)
            require(branch is not None, f'Unexpected file outside pinned source: {child}')
            if None in branch:
                continue  # Git status, verify_layer or the link check covers this leaf.
            require(child.is_dir() and not child.is_symlink(),
                    f'Invalid source directory: {child}')
            visit(child, branch)

    visit(SOURCE, tree)
    if allow_build_output:
        output = SOURCE / 'out'
        require(not output.is_symlink() and (not output.exists() or output.is_dir()),
                f'Invalid source build output directory: {output}')
    for path, record in graph.items():
        project = SOURCE / path
        require(project.is_dir() and not project.is_symlink(), f'Invalid source project: {path}')
        for kind, src, dest in record['links']:
            source = project / src
            target = SOURCE / dest
            if kind == 'linkfile':
                require(target.is_symlink() and target.resolve(strict=True) == source.resolve(strict=True),
                        f'Manifest source link changed: {dest}')
            else:
                require(target.is_file() and not target.is_symlink() and sha256(target) == sha256(source),
                        f'Manifest source copy changed: {dest}')


def source_patch_stages(actual, before, rows):
    """Allow only a clean pinned base or a prefix of the locked patch series."""
    require(set(actual) == set(before), 'Unexpected synced project set')
    stages = {}
    for row in rows:
        path = row['project']
        stages.setdefault(path, [before[path]['revision']]).append(row['result_revision'])
    result = {}
    for path, record in actual.items():
        base = before[path]
        require(record['url'] == base['url'] and record['links'] == base['links'],
                f'Unexpected source URL or link instructions: {path}')
        revisions = stages.get(path, [base['revision']])
        require(record['revision'] in revisions and len(revisions) == len(set(revisions)),
                f'Unexpected source revision: {path}')
        result[path] = revisions.index(record['revision'])
    return result


def apply_locked_patches(rows, stages):
    position = {}
    for row in rows:
        path = row['project']
        position[path] = position.get(path, 0) + 1
        if stages[path] >= position[path]:
            continue
        project = SOURCE / path
        require(clean_source_head(project) == row['base_revision'], f'Patch base changed: {path}')
        subprocess.run(['git', '-c', 'user.name=MP01 source preparation',
                        '-c', 'user.email=mp01-build@localhost', '-c', 'commit.gpgsign=false',
                        '-c', 'core.hooksPath=/dev/null', 'am', '--committer-date-is-author-date',
                        str(HERE / 'patches' / row['file'])], cwd=project, check=True)
        require(clean_source_head(project) == row['result_revision'],
                f'Applied patch did not produce the locked commit: {path}')


def write_preparation_receipt(after, prepared, inventory):
    # A new receipt is created for each preparation; previous receipts remain evidence.
    receipt = STATE / ('prepared-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ') + '.json')
    support_commit = clean_head(REPO)
    inputs_sha256 = sha256(HERE / 'inputs.json')
    with receipt.with_suffix('.xml').open('xb') as stream:
        stream.write(prepared)
        stream.flush()
        os.fsync(stream.fileno())
    write_json(receipt, {'support_commit': support_commit,
                        'inputs_sha256': inputs_sha256,
                        'source_graph': after, 'layer': inventory,
                        'prepared_manifest_sha256': hashlib.sha256(prepared).hexdigest()})
    print('Prepared source receipt:', receipt)


def prepare_sources(cfg):
    """Complete a pinned checkout using only local objects and locked patches."""
    before = source_graph((HERE / 'upstream-manifest.xml').read_bytes())
    rows, after = patches(cfg)
    verify_upstream_checkout(cfg)
    actual = source_graph(command(['repo', 'manifest', '-r'], SOURCE))
    stages = source_patch_stages(actual, before, rows)
    # Patch targets are checked against committed files before each git am.
    # Verify every project after patching, avoiding a second full read of the
    # million-file source tree before any source is used for compilation.
    verify_source_layout(actual)
    apply_locked_patches(rows, stages)
    prepared = verify_source(after, cfg)
    verify_source_layout(after)
    inventory = install_layer(cfg)
    verify_layer(inventory)
    write_preparation_receipt(after, prepared, inventory)


def layer_sources(cfg):
    """Map the complete imported layer to committed sources and the pinned APK."""
    mappings = [('grapheneos/product', 'device/mp01'),
                ('vendor/MP01_services', 'vendor/MP01_services'),
                ('vendor/inkos', 'vendor/inkos')]
    sources = {}
    for prefix, destination in mappings:
        entries = command(['git', 'ls-tree', '-rz', 'HEAD', '--', prefix], REPO).split(b'\0')
        for raw in entries:
            if not raw:
                continue
            metadata, separator, path = raw.partition(b'\t')
            fields = metadata.split()
            require(separator and len(fields) == 3 and fields[0] in {b'100644', b'100755'}
                    and fields[1] == b'blob' and SHA1.fullmatch(fields[2].decode()),
                    f'Unsupported committed layer entry: {raw!r}')
            rel = safe_relative(path.decode())
            src = REPO / rel
            require(src.is_file() and not src.is_symlink(), f'Unsupported layer source: {rel}')
            committed_sha256 = hashlib.sha256(
                command(['git', 'cat-file', 'blob', fields[2].decode()], REPO)
            ).hexdigest()
            require(sha256(src) == committed_sha256
                    and bool(src.stat().st_mode & 0o111) == (fields[0] == b'100755'),
                    f'Layer source differs from committed file: {rel}')
            dest_rel = safe_relative(destination + rel[len(prefix):])
            require(dest_rel not in sources, f'Duplicate MP01 layer destination: {dest_rel}')
            sources[dest_rel] = (src, committed_sha256)
    apk = pinned_inkos_apk(cfg)
    dest_rel = 'vendor/inkos/inkos_v0.1.apk'
    require(dest_rel not in sources, f'Duplicate MP01 layer destination: {dest_rel}')
    sources[dest_rel] = (apk, cfg['inkos_sha256'])
    require('device/mp01/mp01.mk' in sources, 'Product must be committed before sync')
    return sources


def expected_layer_inventory(cfg):
    return {dest_rel: digest for dest_rel, (_, digest) in layer_sources(cfg).items()}


def install_layer(cfg):
    """Copy committed MP01 source and the verified upstream APK cache."""
    sources = layer_sources(cfg)
    inventory = {dest_rel: digest for dest_rel, (_, digest) in sources.items()}
    for dest_rel, (src, digest) in sources.items():
        dest = SOURCE / dest_rel
        checked_directory(dest.parent)
        require(not dest.is_symlink(), f'Layer destination symlink: {dest}')
        if dest.exists():
            require(sha256(dest) == digest,
                    f'Stale MP01 layer: {dest}; preserve/remove it explicitly before resync')
        else:
            shutil.copyfile(src, dest)
            if src != inkos_cache_path():
                dest.chmod(src.stat().st_mode & 0o777)
    return inventory


def verify_layer(inventory):
    for relative, digest in inventory.items():
        path = SOURCE / safe_relative(relative)
        require(path.is_file() and not path.is_symlink() and sha256(path) == digest,
                f'MP01 source layer changed: {relative}')
    actual = set()
    for prefix in ['device/mp01', 'vendor/MP01_services', 'vendor/inkos']:
        for p in (SOURCE / prefix).rglob('*'):
            if p.is_file() or p.is_symlink():
                actual.add(p.relative_to(SOURCE).as_posix())
    require(actual == set(inventory), 'Unexpected file in the imported MP01 layer')


def plan_incomplete_prefetch(before):
    """Check every locked project before fetching any interrupted project."""
    raw = (HERE / 'upstream-manifest.xml').read_bytes()
    require(source_graph(raw) == before, 'Prefetch manifest differs from locked source graph')
    manifest = ET.fromstring(raw)
    default = manifest.find('default')
    remote_default = default.get('remote') if default is not None else None
    projects = manifest.findall('project')
    require(len(projects) == len(before), 'Prefetch project set differs from source graph')
    planned = []
    for project in projects:
        name = safe_relative(project.get('name', ''))
        path = safe_relative(project.get('path', name))
        pinned = before[path]
        gitdir = SOURCE / '.repo/projects' / (path + '.git')
        objdir = SOURCE / '.repo/project-objects' / (name + '.git')
        checkout_git = SOURCE / path / '.git'
        for metadata in (gitdir, objdir):
            for part in (metadata, *metadata.parents):
                if part == SOURCE:
                    break
                require(not part.is_symlink(), f'Symlink project metadata: {path}')
        require(not gitdir.is_symlink() and not objdir.is_symlink(),
                f'Symlink project metadata: {path}')
        require(gitdir.is_dir() == objdir.is_dir(), f'Incomplete project metadata: {path}')
        if not gitdir.is_dir():
            require(not checkout_git.exists() and not checkout_git.is_symlink(),
                    f'Project checkout exists without repo metadata: {path}')
            continue  # repo sync will create a shallow checkout.
        objects = gitdir / 'objects'
        require((objdir / 'objects').is_dir() and not (objdir / 'objects').is_symlink(),
                f'Invalid project object store: {path}')
        require(objects.is_symlink() and objects.resolve(strict=True) ==
                (objdir / 'objects').resolve(strict=True),
                f'Project object store differs from repo layout: {path}')
        if subprocess.run(['git', '--git-dir=' + str(gitdir), 'cat-file', '-e',
                           pinned['revision'] + '^{commit}'], cwd=SOURCE,
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
            continue  # A completed, pinned fetch is retained unchanged.
        require(not checkout_git.exists() and not checkout_git.is_symlink(),
                f'Incomplete project has a worktree; preserve and inspect it: {path}')
        remote = project.get('remote', remote_default)
        upstream = project.get('upstream', '')
        require(remote is not None and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', remote),
                f'Invalid prefetch remote: {path}')
        require(upstream.startswith('refs/tags/') and
                re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', upstream[10:]),
                f'Prefetch requires a pinned upstream tag: {path}')
        # Refuse local URL rewrites and credential-bearing project metadata.
        config = gitdir / 'config'
        require(config.is_file() and not config.is_symlink(), f'Invalid Git config: {path}')
        names = command(['git', 'config', '--file', config, '--name-only', '--list']).decode().splitlines()
        require(not any(key.startswith(('include.', 'includeif.', 'url.', 'credential.',
                                            'http.', 'https.')) for key in names),
                f'Unsafe fetch configuration: {path}')
        urls = command(['git', 'config', '--file', config, '--get-all',
                        f'remote.{remote}.url']).decode().splitlines()
        require(urls == [pinned['url']], f'Project remote differs from source lock: {path}')
        planned.append((path, gitdir, remote, upstream, pinned['revision']))
    return planned


def prefetch_incomplete_projects(cfg, before, logdir):
    """Finish interrupted project fetches shallowly, without replacing source work."""
    planned = plan_incomplete_prefetch(before)
    for count, (path, gitdir, remote, upstream, revision) in enumerate(planned, 1):
        project_logdir = checked_directory(logdir / f'prefetch-{count:04d}')
        print(f'Completing pinned shallow fetch: {path}; transcript: {project_logdir / "fetch.log"}',
              flush=True)
        env = os.environ.copy()
        for key in list(env):
            if key.startswith('GIT_CONFIG_') or key in {'GIT_DIR', 'GIT_WORK_TREE',
                    'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES',
                    'GIT_SSH', 'GIT_SSH_COMMAND'}:
                env.pop(key)
        env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
                   GIT_TERMINAL_PROMPT='0', GIT_ASKPASS='/bin/false',
                   GCM_INTERACTIVE='never')
        run_logged(['git', '-c', 'credential.helper=', '--git-dir=' + str(gitdir),
                    'fetch', '--depth=1', '--no-tags', '--no-recurse-submodules',
                    remote, '+' + upstream + ':' + upstream],
                   SOURCE, env, project_logdir / 'fetch.log', synced_build_budget_bytes(cfg))
        require(command(['git', '--git-dir=' + str(gitdir), 'rev-parse',
                         upstream + '^{}']).decode().strip() == revision,
                f'Fetched tag does not identify the pinned commit: {path}')
        require(command(['git', '--git-dir=' + str(gitdir), 'cat-file', '-t',
                         revision]).decode().strip() == 'commit',
                f'Pinned commit missing after shallow fetch: {path}')
    return len(planned)


def sync_sources(cfg):
    checked_directory(SOURCE)
    before = source_graph((HERE / 'upstream-manifest.xml').read_bytes())
    rows, _ = patches(cfg)
    allowed = {}
    for path, record in before.items():
        allowed[path] = {record['revision']}
    for row in rows:
        allowed[row['project']].add(row['result_revision'])
    if not (SOURCE / '.repo').exists():
        require(not any(SOURCE.iterdir()), 'New Android source directory must be empty')
    else:
        # repo sync must never discard independent local edits or commits.
        for path, record in before.items():
            if (SOURCE / path / '.git').exists():
                head = clean_source_head(SOURCE / path)
                require(head in allowed[path],
                        f'Preserve independent source work before syncing: {path}')
    command(['repo', 'init', '-u', cfg['manifest_url'], '-b', cfg['manifest_commit'],
             '--repo-url=' + cfg['repo_url'], '--repo-rev=' + cfg['repo_commit'],
             '--no-clone-bundle', '--no-use-superproject', '--groups=all', '--depth=1'], SOURCE)
    tag = 'refs/tags/' + cfg['grapheneos_release']
    command(['git', 'fetch', '--no-tags', cfg['manifest_url'], tag + ':' + tag], SOURCE / '.repo/manifests')
    verify_upstream_checkout(cfg)
    sync_logdir = checked_directory(STATE / ('sync-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')))
    prefetch_incomplete_projects(cfg, before, sync_logdir)
    sync_log = sync_logdir / 'sync.log'
    print('Source sync transcript:', sync_log, flush=True)
    run_logged(['repo', 'sync', '-c', '-j4', '--fail-fast', '--no-clone-bundle',
                '--no-tags', '--optimized-fetch'],
               SOURCE, os.environ.copy(), sync_log, synced_build_budget_bytes(cfg))
    prepare_sources(cfg)


def validate_receipt(path, cfg, *, allow_build_output=False):
    require(path.is_file() and path.parent.resolve() == STATE.resolve(), 'Use a retained preparation receipt in the build state directory')
    receipt = json.loads(path.read_text())
    require(receipt['support_commit'] == clean_head(REPO), 'Build support changed since preparation')
    require(receipt['inputs_sha256'] == sha256(HERE / 'inputs.json'), 'Build inputs changed since preparation')
    _, expected = patches(cfg)
    # JSON converts the tuples in link instructions into lists.
    require(receipt['source_graph'] == json.loads(json.dumps(expected)), 'Preparation graph mismatch')
    prepared = verify_source(expected)
    verify_source_layout(expected, allow_build_output=allow_build_output)
    require(hashlib.sha256(prepared).hexdigest() == receipt['prepared_manifest_sha256'],
            'Current prepared XML differs from preparation receipt')
    require(sha256(path.with_suffix('.xml')) == receipt['prepared_manifest_sha256'], 'Prepared XML changed')
    require(receipt['layer'] == expected_layer_inventory(cfg),
            'Preparation layer inventory differs from committed MP01 sources')
    verify_layer(receipt['layer'])
    return receipt


def validate_device_inventory(path):
    require(path is not None, 'Collect and review a fresh MP01 inventory before building (--device-inventory)')
    report = json.loads(path.read_text())
    require(report.get('schema') == 'mp01-device-inventory-v1'
            and report.get('identity', {}).get('ro.product.vendor.model') == 'MP01',
            'Expected an MP01 device inventory')
    props = report['properties']
    for key in ['ro.product.cpu.abilist64', 'ro.vendor.build.fingerprint', 'ro.vndk.version']:
        require(props.get(key, {}).get('exit_code') == 0 and props[key]['value'],
                f'Device contract is missing {key}; do not infer vendor compatibility')
    require('arm64-v8a' in props['ro.product.cpu.abilist64']['value'].split(','), 'Unsupported device ABI')
    for entry in report['observations'].values():
        for stream in ['stdout', 'stderr']:
            if stream in entry:
                blob = entry[stream]
                require(sha256(path.parent / safe_relative(blob['file'])) == blob['sha256'],
                        'Device inventory evidence changed')
    return sha256(path)


def run_logged(argv, cwd, env, logpath, reserve_bytes):
    """Retain a complete transcript or fail, stopping the entire build group."""
    if argv and str(argv[0]) == 'repo':
        env = dict(env)
        for key in list(env):
            if key.startswith('GIT_'):
                env.pop(key)
        env['GIT_NO_REPLACE_OBJECTS'] = '1'
        env['GIT_TERMINAL_PROMPT'] = '0'
        env['PYTHONDONTWRITEBYTECODE'] = '1'
    def sample():
        return {'time': time.time(), 'free_bytes': shutil.disk_usage(WORKSPACE).free,
                'memory_bytes': memory_bytes()}

    samples = [sample()]
    require(samples[0]['free_bytes'] >= reserve_bytes, 'Disk reserve exhausted before command start')
    stop = threading.Event()
    monitor_errors = []
    with logpath.open('xb') as log:
        proc = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, start_new_session=True)

        def stop_process():
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
            except ProcessLookupError:
                pass

        def monitor():
            try:
                while not stop.is_set():
                    current = sample()
                    samples.append(current)
                    if current['free_bytes'] < reserve_bytes:
                        monitor_errors.append('Disk packaging/reserve allowance exhausted')
                        stop_process()
                        return
                    stop.wait(5)
            except Exception as exc:
                monitor_errors.append('Resource monitor failed: ' + str(exc))
                stop_process()

        thread = threading.Thread(target=monitor, daemon=True)
        thread.start()
        try:
            while block := proc.stdout.read(65536):
                log.write(block)
            rc = proc.wait()
        except BaseException:
            stop_process()
            raise
        finally:
            stop.set()
            thread.join()
            proc.stdout.close()
            log.flush()
            os.fsync(log.fileno())
            write_json(logpath.parent / 'resources.json', samples)
    require(rc == 0 and not monitor_errors,
            f'Build failed ({rc}); {"; ".join(monitor_errors)}; retained log: {logpath}')


def build(cfg, args):
    receipt = validate_receipt(args.receipt.resolve(), cfg)
    device_inventory_sha256 = validate_device_inventory(args.device_inventory)
    require(1 <= args.jobs <= cfg['maximum_jobs'], 'Build jobs must be 1 through 4')
    # Fresh output avoids confusing a previous artifact with this invocation.
    require(not (SOURCE / 'out').exists(), 'Preserve previous outputs and remove out explicitly before a formal build')
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    logdir = checked_directory(STATE / ('build-' + stamp))
    logpath = logdir / 'build.log'
    env = {'PATH': '/usr/bin:/bin', 'HOME': str(STATE / 'home'),
           'TMPDIR': str(STATE / 'tmp'), 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8',
           'PYTHONDONTWRITEBYTECODE': '1',
           'BUILD_DATETIME': str(cfg['build_datetime']), 'BUILD_NUMBER': cfg['build_number'],
           'OUT_DIR': 'out', 'USE_CCACHE': '1', 'CCACHE_EXEC': '/usr/bin/ccache',
           'CCACHE_DIR': str(STATE / 'ccache'), 'CCACHE_MAXSIZE': str(cfg['cache_budget_gib']) + 'Gi',
           'MP01_VARIANT': args.variant, 'MP01_JOBS': str(args.jobs)}
    for key in ['HOME', 'TMPDIR', 'CCACHE_DIR']:
        checked_directory(Path(env[key]))
    provenance = {'schema': 1, 'status': 'INCOMPLETE', 'profile': 'development',
                  'support_commit': receipt['support_commit'], 'variant': args.variant,
                  'source_receipt_sha256': sha256(args.receipt),
                  'device_inventory_sha256': device_inventory_sha256,
                  'container_image_id': os.environ['MP01_BUILDER_IMAGE_ID'],
                  'dependencies_sha256': sha256('/opt/mp01/dependencies.tsv'),
                  'environment': env, 'resources_start': resource_report(cfg, 'build')}
    write_json(logdir / 'invocation.json', provenance)
    command_text = '''set -eo pipefail
source build/envsetup.sh
lunch "mp01-cur-$MP01_VARIANT"
[[ "$TARGET_PRODUCT" == mp01 && "$TARGET_BUILD_VARIANT" == "$MP01_VARIANT" ]]
m -j"$MP01_JOBS" target-files-package otatools-package
'''
    run_logged(['/bin/bash', '-c', command_text], SOURCE, env, logpath,
               (cfg['reserve_gib'] + cfg['packaging_budget_gib']) * GIB)
    validate_receipt(args.receipt.resolve(), cfg, allow_build_output=True)
    packages = list((SOURCE / 'out/target/product/mp01/obj/PACKAGING/target_files_intermediates').glob('*.zip'))
    require(len(packages) == 1, 'Expected exactly one newly built target-files archive')
    provenance.update(status='UNSIGNED_TARGET_FILES_REQUIRES_INDEPENDENT_AUDIT',
                      target_files=str(packages[0]), target_files_sha256=sha256(packages[0]),
                      log_sha256=sha256(logpath), resources_sha256=sha256(logdir / 'resources.json'))
    write_json(logdir / 'result.json', provenance)
    print(json.dumps(provenance, indent=2))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['preflight', 'fetch-prebuilts', 'sync', 'prepare',
                                           'verify-source', 'build'])
    parser.add_argument('--phase', choices=['sync', 'prepare', 'build'], default='build')
    parser.add_argument('--receipt', type=Path)
    parser.add_argument('--device-inventory', type=Path)
    parser.add_argument('--variant', choices=['user', 'userdebug'], default='userdebug')
    parser.add_argument('--jobs', type=int, default=4)
    args = parser.parse_args(argv)
    try:
        cfg = inputs()
        if args.command == 'preflight':
            report = resource_report(cfg, args.phase)
            print(json.dumps(report, indent=2))
            return 2 if report['problems'] else 0
        if args.command in {'sync', 'prepare', 'build'}:
            report = resource_report(cfg, args.command)
            require(not report['problems'], '; '.join(report['problems']))
        checked_directory(STATE)
        with (STATE / 'build.lock').open('a') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            clean_head(REPO)
            if args.command == 'fetch-prebuilts':
                fetch_prebuilts(cfg)
            elif args.command == 'sync':
                sync_sources(cfg)
            elif args.command == 'prepare':
                prepare_sources(cfg)
            else:
                require(args.receipt is not None, '--receipt is required')
                if args.command == 'verify-source':
                    validate_receipt(args.receipt.resolve(), cfg, allow_build_output=True)
                    print('Pinned source graph and MP01 layer verified')
                else:
                    build(cfg, args)
        return 0
    except (BuildError, OSError, ValueError, KeyError, subprocess.CalledProcessError, ET.ParseError) as exc:
        print(f'BLOCKED: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
