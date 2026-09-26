import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from io import BytesIO

SPEC = importlib.util.spec_from_file_location('mp01_graphene_builder', Path(__file__).with_name('build.py'))
BUILD = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BUILD
SPEC.loader.exec_module(BUILD)


def manifest(revision='a' * 40, fetch='https://example.org', path='build/make', extra=''):
    return (f'<manifest><remote name="a" fetch="{fetch}"/><default remote="a"/>'
            f'<project name="platform/build" path="{path}" revision="{revision}"/>{extra}</manifest>').encode()


class SourceGraphTests(unittest.TestCase):
    def test_upstream_graph_and_scoped_patches_are_fully_pinned(self):
        cfg = BUILD.inputs()
        graph = BUILD.source_graph((BUILD.HERE / 'upstream-manifest.xml').read_bytes())
        self.assertEqual(len(graph), 1057)
        rows, prepared = BUILD.patches(cfg)
        patched = {'build/make', 'packages/modules/Permission'}
        self.assertEqual([r['project'] for r in rows], sorted(patched))
        self.assertEqual({p for p in graph if graph[p] != prepared[p]}, patched)

    def test_lock_detects_noncustom_project_and_remote_mutation(self):
        original = BUILD.source_graph(manifest())
        self.assertNotEqual(original, BUILD.source_graph(manifest('b' * 40)))
        self.assertNotEqual(original, BUILD.source_graph(manifest(fetch='https://changed.example')))

    def test_explicit_and_inherited_remotes_compare_equally(self):
        raw = manifest()
        explicit = raw.replace(b'name="platform/build"', b'name="platform/build" remote="a"')
        self.assertEqual(BUILD.source_graph(raw), BUILD.source_graph(explicit))

    def test_moving_revisions_and_non_https_transports_rejected(self):
        for raw in [manifest('main'), manifest(fetch='ssh://git@example.org'),
                    manifest(fetch='https://user@example.org'), manifest(fetch='file:///source')]:
            with self.subTest(raw=raw), self.assertRaises(BUILD.BuildError):
                BUILD.source_graph(raw)

    def test_manifest_escape_duplicate_and_include_rejected(self):
        for raw in [manifest(path='../escape'), manifest(path='.'),
                    manifest(extra='<include name="extra.xml"/>'),
                    manifest(extra='<project name="extra" path="build/make" revision="' + 'a' * 40 + '"/>')]:
            with self.subTest(raw=raw), self.assertRaises(BUILD.BuildError):
                BUILD.source_graph(raw)

    def test_link_destination_is_part_of_lock(self):
        raw = manifest().replace(b'/></manifest>', b'><linkfile src="." dest="one"/></project></manifest>')
        self.assertNotEqual(BUILD.source_graph(raw), BUILD.source_graph(raw.replace(b'dest="one"', b'dest="two"')))

    def test_extra_layer_file_blocks_verification(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(BUILD, 'SOURCE', Path(tmp)):
            p = Path(tmp) / 'device/mp01/test'
            p.parent.mkdir(parents=True)
            p.write_text('original')
            inventory = {'device/mp01/test': BUILD.sha256(p)}
            BUILD.verify_layer(inventory)
            p.with_name('unexpected').write_text('addition')
            with self.assertRaisesRegex(BUILD.BuildError, 'Unexpected'):
                BUILD.verify_layer(inventory)

    def test_symlink_workspace_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp)
            (p / 'real').mkdir()
            (p / 'link').symlink_to(p / 'real')
            with self.assertRaises(BUILD.BuildError):
                BUILD.checked_directory(p / 'link/new')


class PinnedInkOSTests(unittest.TestCase):
    def test_offline_cache_requires_exact_size_and_sha256(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            apk = state / 'prebuilts/inkos_v0.1.apk'
            apk.parent.mkdir(parents=True)
            payload = b'pinned test APK bytes'
            apk.write_bytes(payload)
            cfg = {
                   'inkos_source_size': len(payload),
                   'inkos_sha256': hashlib.sha256(payload).hexdigest()}
            with mock.patch.object(BUILD, 'STATE', state):
                self.assertEqual(BUILD.pinned_inkos_apk(cfg), apk)
                with self.assertRaisesRegex(BUILD.BuildError, 'differs'):
                    BUILD.pinned_inkos_apk({**cfg, 'inkos_source_size': len(payload) + 1})
                with self.assertRaisesRegex(BUILD.BuildError, 'differs'):
                    BUILD.pinned_inkos_apk({**cfg, 'inkos_sha256': '0' * 64})
                apk.unlink()
                with self.assertRaisesRegex(BUILD.BuildError, 'absent'):
                    BUILD.pinned_inkos_apk(cfg)
                apk.symlink_to(state / 'elsewhere')
                with self.assertRaisesRegex(BUILD.BuildError, 'absent'):
                    BUILD.pinned_inkos_apk(cfg)

    def test_fetch_rejects_wrong_bytes_and_cleans_temporary_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            state = Path(tmp)
            payload = b'pinned test APK bytes'
            cfg = {'inkos_release_url': 'https://example.org/inkos.apk',
                   'inkos_source_size': len(payload),
                   'inkos_sha256': hashlib.sha256(payload).hexdigest()}

            class Response(BytesIO):
                url = cfg['inkos_release_url']

            with mock.patch.object(BUILD, 'STATE', state), \
                 mock.patch.object(BUILD.urllib.request, 'urlopen', return_value=Response(payload)):
                BUILD.fetch_prebuilts(cfg)
                self.assertEqual(BUILD.pinned_inkos_apk(cfg).read_bytes(), payload)
            (state / 'prebuilts/inkos_v0.1.apk').unlink()
            with mock.patch.object(BUILD, 'STATE', state), \
                 mock.patch.object(BUILD.urllib.request, 'urlopen', return_value=Response(b'wrong')):
                with self.assertRaisesRegex(BUILD.BuildError, 'differs'):
                    BUILD.fetch_prebuilts(cfg)
            self.assertEqual(list((state / 'prebuilts').iterdir()), [])


class OfflinePreparationTests(unittest.TestCase):
    def git(self, path, *args, env=None):
        return subprocess.check_output(['git', '-C', str(path), *args], env=env).decode().strip()

    def commit(self, path, message, date=None):
        env = os.environ.copy()
        if date:
            env.update(GIT_AUTHOR_DATE=date, GIT_COMMITTER_DATE=date)
        subprocess.run(['git', '-C', str(path), 'add', '-A'], check=True, stdout=subprocess.DEVNULL)
        subprocess.run(['git', '-C', str(path), '-c', 'user.name=MP01 source preparation',
                        '-c', 'user.email=mp01-build@localhost', 'commit', '-qm', message,
                        '--allow-empty'], check=True, env=env)
        return self.git(path, 'rev-parse', 'HEAD')

    def fixture(self, root):
        support = root / 'support'
        here = support / 'grapheneos'
        source = root / 'source'
        state = root / 'state'
        for path in (here / 'patches', support / 'grapheneos/product', source / '.repo/manifests',
                     source / '.repo/repo', source / 'platform', state):
            path.mkdir(parents=True, exist_ok=True)
        for path in (support, source / '.repo/manifests', source / '.repo/repo', source / 'platform'):
            subprocess.run(['git', 'init', '-q', str(path)], check=True)

        project = source / 'platform'
        (project / 'feature.txt').write_text('base\n')
        (project / 'envsetup.sh').write_text('export MP01_TEST=base\n')
        (project / 'envsetup-link').symlink_to('envsetup.sh')
        base = self.commit(project, 'base', '2026-09-19T00:00:00+0000')
        (project / 'feature.txt').write_text('first\n')
        first = self.commit(project, 'first', '2026-09-19T00:01:00+0000')
        patch1 = self.git(project, 'format-patch', '--stdout', base + '..' + first)
        (project / 'feature.txt').write_text('second\n')
        second = self.commit(project, 'second', '2026-09-19T00:02:00+0000')
        patch2 = self.git(project, 'format-patch', '--stdout', first + '..' + second)
        self.git(project, 'reset', '--hard', first)
        project_gitdir = source / '.repo/projects/platform.git'
        project_gitdir.parent.mkdir(parents=True, exist_ok=True)
        (project / '.git').rename(project_gitdir)
        (project / '.git').symlink_to(os.path.relpath(project_gitdir, project))

        manifest_bytes = manifest(revision=base, path='platform')
        (here / 'upstream-manifest.xml').write_bytes(manifest_bytes)
        (source / '.repo/manifests/default.xml').write_bytes(manifest_bytes)
        manifest_commit = self.commit(source / '.repo/manifests', 'manifest')
        subprocess.run(['git', '-C', str(source / '.repo/manifests'), '-c', 'user.name=Test',
                        '-c', 'user.email=test@localhost', 'tag', '-am', 'release', 'test-release'], check=True)
        repo_commit = self.commit(source / '.repo/repo', 'repo')
        manifest_gitdir = source / '.repo/manifests.git'
        (source / '.repo/manifests/.git').rename(manifest_gitdir)
        (source / '.repo/manifests/.git').symlink_to('../manifests.git')
        (here / 'upstream-allowed-signers').write_text('test public signer\n')
        (here / 'inputs.json').write_text('{}\n')
        (support / 'grapheneos/product/mp01.mk').write_text('PRODUCT_NAME := mp01\n')
        (state / 'prebuilts').mkdir()
        (state / 'prebuilts/inkos_v0.1.apk').write_bytes(b'test-inkos-apk')
        for name, content, prior, result in [('first.patch', patch1, base, first),
                                              ('second.patch', patch2, first, second)]:
            (here / 'patches' / name).write_text(content + '\n')
        rows = [{'project': 'platform', 'file': name, 'sha256': BUILD.sha256(here / 'patches' / name),
                 'base_revision': prior, 'result_revision': result, 'reason': 'test fixture'}
                for name, prior, result in [('first.patch', base, first),
                                            ('second.patch', first, second)]]
        (here / 'patches/series.json').write_text(json.dumps(rows))
        self.commit(support, 'locked support')
        cfg = {'manifest_commit': manifest_commit,
               'manifest_sha256': BUILD.sha256(here / 'upstream-manifest.xml'),
               'repo_commit': repo_commit, 'grapheneos_release': 'test-release',
               'manifest_tag_object': self.git(source / '.repo/manifests', 'rev-parse', 'refs/tags/test-release'),
               'inkos_source_size': len(b'test-inkos-apk'),
               'inkos_sha256': hashlib.sha256(b'test-inkos-apk').hexdigest()}
        return support, here, source, state, cfg, second

    def run_prepare(self, fixture, *, signature_ok=True):
        support, here, source, state, cfg, _ = fixture
        original = BUILD.command
        calls = []

        def local_command(argv, cwd=None, **kwargs):
            calls.append(tuple(argv))
            if argv == ['repo', 'manifest', '-r']:
                revision = self.git(source / 'platform', 'rev-parse', 'HEAD')
                return manifest(revision=revision, path='platform')
            if 'verify-tag' in argv:
                if not signature_ok:
                    raise subprocess.CalledProcessError(1, argv)
                return b'verified\n'
            self.assertNotIn('fetch', argv)
            self.assertNotIn('sync', argv)
            self.assertNotIn('init', argv)
            return original(argv, cwd or BUILD.REPO, **kwargs)

        with mock.patch.object(BUILD, 'REPO', support), mock.patch.object(BUILD, 'HERE', here), \
             mock.patch.object(BUILD, 'SOURCE', source), mock.patch.object(BUILD, 'STATE', state), \
             mock.patch.object(BUILD, 'command', side_effect=local_command):
            BUILD.prepare_sources(cfg)
        self.assertTrue(any('verify-tag' in call for call in calls))
        self.assertFalse(any(call[:2] == ('repo', 'sync') for call in calls))

    def run_validate(self, fixture, *, allow_build_output=False):
        support, here, source, state, cfg, _ = fixture
        original = BUILD.command

        def local_command(argv, cwd=None, **kwargs):
            if argv == ['repo', 'manifest', '-r']:
                revision = self.git(source / 'platform', 'rev-parse', 'HEAD')
                return manifest(revision=revision, path='platform')
            if 'verify-tag' in argv:
                return b'verified\n'
            return original(argv, cwd or BUILD.REPO, **kwargs)

        receipt = next(state.glob('prepared-*.json'))
        with mock.patch.object(BUILD, 'REPO', support), mock.patch.object(BUILD, 'HERE', here), \
             mock.patch.object(BUILD, 'SOURCE', source), mock.patch.object(BUILD, 'STATE', state), \
             mock.patch.object(BUILD, 'inputs', return_value=cfg), \
             mock.patch.object(BUILD, 'command', side_effect=local_command):
            return BUILD.validate_receipt(receipt, cfg, allow_build_output=allow_build_output)

    def test_preapplied_patch_is_preserved_and_new_patch_gets_a_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.fixture(Path(tmp))
            source, state, expected = fixture[2], fixture[3], fixture[5]
            self.run_prepare(fixture)
            self.assertEqual(self.git(source / 'platform', 'rev-parse', 'HEAD'), expected)
            receipts = list(state.glob('prepared-*.json'))
            self.assertEqual(len(receipts), 1)
            self.assertEqual(json.loads(receipts[0].read_text())['source_graph']['platform']['revision'], expected)
            self.assertTrue((source / 'device/mp01/mp01.mk').is_file())
            self.assertEqual((source / 'vendor/inkos/inkos_v0.1.apk').read_bytes(), b'test-inkos-apk')
            self.run_prepare(fixture)
            self.assertEqual(len(list(state.glob('prepared-*.json'))), 2)
            self.assertEqual(self.git(source / 'platform', 'rev-parse', 'HEAD'), expected)

    def test_receipt_rechecks_root_layout_before_and_after_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.fixture(Path(tmp))
            source, state = fixture[2], fixture[3]
            self.run_prepare(fixture)
            self.run_validate(fixture)

            rogue = source / 'buildspec.mk'
            rogue.write_text('$(error unexpected build input)\n')
            with self.assertRaisesRegex(BUILD.BuildError, 'outside pinned source'):
                self.run_validate(fixture)
            rogue.unlink()

            output = source / 'out'
            output.mkdir()
            (output / 'build.ninja').write_text('generated\n')
            with self.assertRaisesRegex(BUILD.BuildError, 'outside pinned source'):
                self.run_validate(fixture)
            self.run_validate(fixture, allow_build_output=True)

            rogue.write_text('$(error unexpected build input)\n')
            with self.assertRaisesRegex(BUILD.BuildError, 'outside pinned source'):
                self.run_validate(fixture, allow_build_output=True)
            rogue.unlink()
            shutil.rmtree(output)
            output.symlink_to(state, target_is_directory=True)
            with self.assertRaisesRegex(BUILD.BuildError, 'Invalid source build output'):
                self.run_validate(fixture, allow_build_output=True)

    def test_receipt_and_imported_layer_cannot_be_changed_together(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.fixture(Path(tmp))
            source, state = fixture[2], fixture[3]
            self.run_prepare(fixture)
            receipt_path = next(state.glob('prepared-*.json'))
            receipt = json.loads(receipt_path.read_text())
            relative = 'device/mp01/mp01.mk'
            imported = source / relative
            imported.write_text('PRODUCT_NAME := altered\n')
            receipt['layer'][relative] = BUILD.sha256(imported)
            receipt_path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(BUILD.BuildError, 'layer inventory differs'):
                self.run_validate(fixture)

    def test_committed_layer_blob_wins_over_assume_unchanged_worktree(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.fixture(Path(tmp))
            support, source, state = fixture[0], fixture[2], fixture[3]
            self.run_prepare(fixture)
            relative_source = 'grapheneos/product/mp01.mk'
            subprocess.run(
                ['git', '-C', str(support), 'update-index', '--assume-unchanged', relative_source],
                check=True,
            )
            (support / relative_source).write_text('PRODUCT_NAME := altered\n')
            self.assertEqual(self.git(support, 'status', '--porcelain', '--untracked-files=all'), '')

            receipt_path = next(state.glob('prepared-*.json'))
            receipt = json.loads(receipt_path.read_text())
            relative_import = 'device/mp01/mp01.mk'
            imported = source / relative_import
            imported.write_text('PRODUCT_NAME := altered\n')
            receipt['layer'][relative_import] = BUILD.sha256(imported)
            receipt_path.write_text(json.dumps(receipt))
            with mock.patch.object(BUILD, 'REPO', support), \
                 mock.patch.object(BUILD, 'STATE', state):
                with self.assertRaisesRegex(BUILD.BuildError, 'differs from committed file'):
                    BUILD.expected_layer_inventory(fixture[4])
            with self.assertRaisesRegex(BUILD.BuildError, 'Suppressed or unexpected index state'):
                self.run_validate(fixture)

    def test_receipt_and_prepared_xml_cannot_be_changed_together(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.fixture(Path(tmp))
            state = fixture[3]
            self.run_prepare(fixture)
            receipt_path = next(state.glob('prepared-*.json'))
            receipt = json.loads(receipt_path.read_text())
            prepared_xml = receipt_path.with_suffix('.xml')
            prepared_xml.write_text('<manifest/>\n')
            receipt['prepared_manifest_sha256'] = BUILD.sha256(prepared_xml)
            receipt_path.write_text(json.dumps(receipt))
            with self.assertRaisesRegex(BUILD.BuildError, 'Current prepared XML differs'):
                self.run_validate(fixture)

    def test_local_source_files_and_independent_commits_stop_preparation(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.fixture(Path(tmp))
            source, state = fixture[2], fixture[3]
            (source / 'platform/rogue.txt').write_text('local edit\n')
            with self.assertRaisesRegex(BUILD.BuildError, 'uncommitted source'):
                self.run_prepare(fixture)
            (source / 'platform/rogue.txt').unlink()
            (source / 'platform/.git/info/exclude').write_text('ignored.txt\n')
            (source / 'platform/ignored.txt').write_text('ignored local input\n')
            with self.assertRaisesRegex(BUILD.BuildError, 'uncommitted source'):
                self.run_prepare(fixture)
            (source / 'platform/ignored.txt').unlink()
            (source / 'rogue.txt').write_text('outside projects\n')
            with self.assertRaisesRegex(BUILD.BuildError, 'outside pinned source'):
                self.run_prepare(fixture)
            (source / 'rogue.txt').unlink()
            (source / 'platform/feature.txt').write_text('independent commit\n')
            self.commit(source / 'platform', 'independent')
            with self.assertRaisesRegex(BUILD.BuildError, 'Unexpected source revision'):
                self.run_prepare(fixture)
            self.assertFalse(list(state.glob('prepared-*.json')))

    def test_suppressed_index_flags_cannot_hide_changed_source_files(self):
        for flag in ('--assume-unchanged', '--skip-worktree'):
            with self.subTest(flag=flag), tempfile.TemporaryDirectory() as tmp:
                fixture = self.fixture(Path(tmp))
                project = fixture[2] / 'platform'
                subprocess.run(['git', '-C', str(project), 'update-index', flag,
                                'envsetup.sh'], check=True)
                (project / 'envsetup.sh').write_text('export MP01_TEST=poisoned\n')
                self.assertEqual(self.git(project, 'status', '--porcelain',
                                          '--untracked-files=all'), '')
                with mock.patch.object(BUILD, 'SOURCE', fixture[2]), \
                     self.assertRaisesRegex(BUILD.BuildError, 'Suppressed or unexpected index state'):
                    BUILD.clean_source_head(project)

    def test_preparation_rechecks_already_patched_source_before_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.fixture(Path(tmp))
            source, state = fixture[2], fixture[3]
            self.run_prepare(fixture)
            receipts = set(state.glob('prepared-*.json'))
            project = source / 'platform'
            subprocess.run(['git', '-C', str(project), 'update-index', '--assume-unchanged',
                            'envsetup.sh'], check=True)
            (project / 'envsetup.sh').write_text('export MP01_TEST=poisoned\n')
            with self.assertRaisesRegex(BUILD.BuildError, 'Suppressed or unexpected index state'):
                self.run_prepare(fixture)
            self.assertEqual(set(state.glob('prepared-*.json')), receipts)

    def test_git_environment_and_replace_refs_cannot_redirect_verification(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.fixture(Path(tmp))
            project = fixture[2] / 'platform'
            poisoned = {'GIT_DIR': str(Path(tmp) / 'missing'),
                        'GIT_INDEX_FILE': str(Path(tmp) / 'missing-index'),
                        'GIT_WORK_TREE': str(Path(tmp) / 'other-tree'),
                        'GIT_CONFIG_COUNT': '1',
                        'GIT_CONFIG_KEY_0': 'core.worktree',
                        'GIT_CONFIG_VALUE_0': str(Path(tmp) / 'other-tree')}
            with mock.patch.object(BUILD, 'SOURCE', fixture[2]), \
                 mock.patch.dict(os.environ, poisoned):
                self.assertEqual(BUILD.clean_source_head(project), self.git(project, 'rev-parse', 'HEAD',
                                                                             env={k: v for k, v in os.environ.items()
                                                                                  if not k.startswith('GIT_')}))
            self.git(project, 'replace', self.git(project, 'rev-parse', 'HEAD'),
                     self.git(project, 'rev-parse', 'HEAD~1'))
            with mock.patch.object(BUILD, 'SOURCE', fixture[2]), \
                 self.assertRaisesRegex(BUILD.BuildError, 'replace refs are forbidden'):
                BUILD.clean_source_head(project)

    def test_git_metadata_and_tracked_parent_must_remain_ordinary(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.fixture(Path(tmp))
            project = fixture[2] / 'platform'
            marker = project / '.git'
            marker.unlink()
            marker.symlink_to('../unexpected.git')
            with mock.patch.object(BUILD, 'SOURCE', fixture[2]), \
                 self.assertRaisesRegex(BUILD.BuildError, 'Git metadata redirect changed'):
                BUILD.clean_source_head(project)
            marker.unlink()
            marker.symlink_to(os.path.relpath(fixture[2] / '.repo/projects/platform.git', project))
            (project / 'nested').mkdir()
            (project / 'nested/input.txt').write_text('pinned\n')
            self.commit(project, 'nested input')
            oid = self.git(project, 'rev-parse', 'HEAD:nested/input.txt').encode()
            (project / 'nested/input.txt').unlink()
            (project / 'nested').rmdir()
            alternate = Path(tmp) / 'alternate'
            alternate.mkdir()
            (alternate / 'input.txt').write_text('pinned\n')
            (project / 'nested').symlink_to(alternate)
            with self.assertRaisesRegex(BUILD.BuildError, 'Source parent is not an ordinary directory'):
                BUILD._verify_worktree_blob(project, 'nested/input.txt', b'100644', oid)

    def test_pinned_crlf_checkout_is_verified_against_lf_blob(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.fixture(Path(tmp))
            project = fixture[2] / 'platform'
            (project / '.gitattributes').write_text('*.bat text=auto eol=crlf\n')
            (project / 'trigger.bat').write_bytes(b'@echo clean\r\nexit /b 0\r\n')
            self.commit(project, 'add CRLF checkout rule')
            self.assertEqual((project / 'trigger.bat').read_bytes(), b'@echo clean\r\nexit /b 0\r\n')
            oid = self.git(project, 'rev-parse', 'HEAD:trigger.bat').encode()
            with mock.patch.object(BUILD, 'SOURCE', fixture[2]):
                BUILD.clean_source_head(project)
            (project / 'trigger.bat').write_bytes(b'@echo poison\r\nexit /b 0\r\n')
            with self.assertRaisesRegex(BUILD.BuildError, 'bytes differ'):
                BUILD._verify_worktree_blob(project, 'trigger.bat', b'100644', oid,
                                            allow_crlf=True)
            (project / 'trigger.bat').write_bytes(b'@echo clean\nexit /b 0\r\n')
            with self.assertRaisesRegex(BUILD.BuildError, 'Invalid CRLF'):
                BUILD._verify_worktree_blob(project, 'trigger.bat', b'100644', oid,
                                            allow_crlf=True)

    def test_crlf_without_committed_rule_and_local_override_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.fixture(Path(tmp))
            project = fixture[2] / 'platform'
            (project / 'envsetup.sh').write_bytes(b'export MP01_TEST=base\r\n')
            original_command = BUILD.command

            def status_only_masked(args, cwd=BUILD.REPO, **kwargs):
                if args[:2] == ['git', 'status']:
                    return b''
                return original_command(args, cwd, **kwargs)

            with mock.patch.object(BUILD, 'SOURCE', fixture[2]):
                self.assertFalse(BUILD._committed_crlf_attribute(project, 'envsetup.sh'))
            with mock.patch.object(BUILD, 'SOURCE', fixture[2]), \
                 mock.patch.object(BUILD, 'command', side_effect=status_only_masked), \
                 self.assertRaisesRegex(BUILD.BuildError, 'bytes differ from committed blob'):
                BUILD.clean_source_head(project)
            local_attributes = fixture[2] / '.repo/projects/platform.git/info/attributes'
            local_attributes.write_text('envsetup.sh text=auto eol=crlf\n')
            with mock.patch.object(BUILD, 'SOURCE', fixture[2]), \
                 self.assertRaisesRegex(BUILD.BuildError, 'Local Git attributes'):
                BUILD._committed_crlf_attribute(project, 'envsetup.sh')

    def test_committed_source_type_mode_and_symlink_target_are_verified(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.fixture(Path(tmp))
            project = fixture[2] / 'platform'
            with mock.patch.object(BUILD, 'SOURCE', fixture[2]):
                BUILD.clean_source_head(project)
            file_oid = self.git(project, 'rev-parse', 'HEAD:envsetup.sh').encode()
            link_oid = self.git(project, 'rev-parse', 'HEAD:envsetup-link').encode()
            script = project / 'envsetup.sh'
            script.chmod(0o755)
            with self.assertRaisesRegex(BUILD.BuildError, 'executable mode'):
                BUILD._verify_worktree_blob(project, 'envsetup.sh', b'100644', file_oid)
            script.chmod(0o644)
            script.unlink()
            script.symlink_to('feature.txt')
            with self.assertRaisesRegex(BUILD.BuildError, 'Cannot verify committed source file'):
                BUILD._verify_worktree_blob(project, 'envsetup.sh', b'100644', file_oid)
            link = project / 'envsetup-link'
            link.unlink()
            link.symlink_to('feature.txt')
            with self.assertRaisesRegex(BUILD.BuildError, 'bytes differ'):
                BUILD._verify_worktree_blob(project, 'envsetup-link', b'120000', link_oid)

    def test_uninitialized_gitlink_must_remain_an_empty_real_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.fixture(Path(tmp))
            project = fixture[2] / 'platform'
            referenced_commit = self.git(project, 'rev-parse', 'HEAD')
            subprocess.run(['git', '-C', str(project), 'update-index', '--add',
                            '--cacheinfo', f'160000,{referenced_commit},dependency'],
                           check=True)
            (project / 'dependency').mkdir()
            self.commit(project, 'record uninitialized gitlink')
            with mock.patch.object(BUILD, 'SOURCE', fixture[2]):
                BUILD.clean_source_head(project)
            (project / 'dependency/unexpected').write_text('unverified submodule bytes\n')
            with mock.patch.object(BUILD, 'SOURCE', fixture[2]), \
                 self.assertRaisesRegex(BUILD.BuildError, 'Gitlink must remain an empty directory'):
                BUILD.clean_source_head(project)

    def test_invalid_signature_stops_before_patch_application(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.fixture(Path(tmp))
            source, state = fixture[2], fixture[3]
            first = self.git(source / 'platform', 'rev-parse', 'HEAD')
            with self.assertRaises(subprocess.CalledProcessError):
                self.run_prepare(fixture, signature_ok=False)
            self.assertEqual(self.git(source / 'platform', 'rev-parse', 'HEAD'), first)
            self.assertFalse(list(state.glob('prepared-*.json')))

    def test_wrong_tag_object_and_patch_result_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = self.fixture(Path(tmp))
            support, here, source, state, cfg, actual_result = fixture
            first = self.git(source / 'platform', 'rev-parse', 'HEAD')
            cfg['manifest_tag_object'] = '0' * 40
            with self.assertRaisesRegex(BUILD.BuildError, 'signed tag object'):
                self.run_prepare(fixture)
            self.assertEqual(self.git(source / 'platform', 'rev-parse', 'HEAD'), first)
            cfg['manifest_tag_object'] = self.git(source / '.repo/manifests',
                                                  'rev-parse', 'refs/tags/test-release')
            rows = json.loads((here / 'patches/series.json').read_text())
            rows[-1]['result_revision'] = 'f' * 40
            (here / 'patches/series.json').write_text(json.dumps(rows))
            self.commit(support, 'test wrong result lock')
            with self.assertRaisesRegex(BUILD.BuildError, 'locked commit'):
                self.run_prepare(fixture)
            self.assertEqual(self.git(source / 'platform', 'rev-parse', 'HEAD'), actual_result)
            self.assertFalse(list(state.glob('prepared-*.json')))


class ShallowResumeTests(unittest.TestCase):
    def fixture(self, root, *, revision=None, upstream_ref='refs/tags/test-release'):
        upstream = root / 'upstream'
        upstream.mkdir()
        subprocess.run(['git', 'init', '-q', str(upstream)], check=True)
        (upstream / 'source.txt').write_text('pinned source\n')
        subprocess.run(['git', '-C', str(upstream), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(upstream), '-c', 'user.name=Test',
                        '-c', 'user.email=test@localhost', 'commit', '-qm', 'pin'], check=True)
        pin = subprocess.check_output(['git', '-C', str(upstream), 'rev-parse', 'HEAD']).decode().strip()
        subprocess.run(['git', '-C', str(upstream), 'tag', 'test-release'], check=True)
        (upstream / 'source.txt').write_text('later source\n')
        subprocess.run(['git', '-C', str(upstream), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(upstream), '-c', 'user.name=Test',
                        '-c', 'user.email=test@localhost', 'commit', '-qm', 'later'], check=True)
        source = root / 'source'
        here = root / 'support/grapheneos'
        logdir = root / 'logs'
        for directory in (here, logdir):
            directory.mkdir(parents=True)
        locked = revision or pin
        raw = (f'<manifest><remote name="a" fetch="https://example.org"/>'
               f'<default remote="a"/>'
               f'<project name="demo" path="demo" revision="{locked}" '
               f'upstream="{upstream_ref}"/>'
               f'<project name="new" path="new" revision="{pin}" '
               f'upstream="{upstream_ref}"/></manifest>').encode()
        (here / 'upstream-manifest.xml').write_bytes(raw)
        gitdir = source / '.repo/projects/demo.git'
        objdir = source / '.repo/project-objects/demo.git'
        gitdir.parent.mkdir(parents=True)
        objdir.parent.mkdir(parents=True)
        subprocess.run(['git', 'init', '--bare', '-q', str(gitdir)], check=True)
        subprocess.run(['git', 'init', '--bare', '-q', str(objdir)], check=True)
        shutil.rmtree(gitdir / 'objects')
        (gitdir / 'objects').symlink_to(os.path.relpath(objdir / 'objects', gitdir))
        subprocess.run(['git', 'config', '--file', str(gitdir / 'config'),
                        'remote.a.url', 'https://example.org/demo'], check=True)
        cfg = {'output_growth_budget_gib': 150, 'packaging_budget_gib': 24,
               'cache_budget_gib': 16, 'reserve_gib': 50}
        return source, here, logdir, gitdir, upstream, BUILD.source_graph(raw), cfg, pin

    def local_fetch(self, upstream, calls):
        def run(argv, cwd, env, logpath, reserve):
            calls.append((argv, cwd, env, logpath, reserve))
            self.assertIn('--depth=1', argv)
            self.assertIn('--no-tags', argv)
            self.assertIn('--no-recurse-submodules', argv)
            self.assertEqual(argv[-1], '+refs/tags/test-release:refs/tags/test-release')
            self.assertEqual(env['GIT_TERMINAL_PROMPT'], '0')
            self.assertEqual(reserve, 240 * BUILD.GIB)
            local = list(argv)
            local[-2] = upstream.as_uri()
            subprocess.run(local, cwd=cwd, env=env, check=True, stdout=subprocess.DEVNULL)
            logpath.write_text('local test fetch\n')
        return run

    def test_interrupted_project_is_shallow_fetched_once_and_fresh_project_is_left_for_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, here, logdir, gitdir, upstream, graph, cfg, pin = self.fixture(Path(tmp))
            calls = []
            with mock.patch.object(BUILD, 'SOURCE', source), mock.patch.object(BUILD, 'HERE', here), \
                 mock.patch.object(BUILD, 'run_logged', side_effect=self.local_fetch(upstream, calls)):
                self.assertEqual(BUILD.prefetch_incomplete_projects(cfg, graph, logdir), 1)
                self.assertEqual(BUILD.prefetch_incomplete_projects(cfg, graph, logdir), 0)
            self.assertEqual(len(calls), 1)
            self.assertTrue((gitdir / 'shallow').is_file())
            self.assertEqual(subprocess.check_output(['git', '--git-dir=' + str(gitdir),
                             'rev-parse', 'refs/tags/test-release^{}']).decode().strip(), pin)
            self.assertFalse((source / '.repo/projects/new.git').exists())

    def test_incomplete_worktree_or_changed_remote_blocks_network_fetch(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, here, logdir, gitdir, upstream, graph, cfg, _ = self.fixture(Path(tmp))
            (source / 'demo').mkdir()
            (source / 'demo/.git').write_text('preserve local work\n')
            with mock.patch.object(BUILD, 'SOURCE', source), mock.patch.object(BUILD, 'HERE', here), \
                 mock.patch.object(BUILD, 'run_logged') as run:
                with self.assertRaisesRegex(BUILD.BuildError, 'worktree'):
                    BUILD.prefetch_incomplete_projects(cfg, graph, logdir)
                run.assert_not_called()
            (source / 'demo/.git').unlink()
            subprocess.run(['git', 'config', '--file', str(gitdir / 'config'),
                            'remote.a.url', 'https://changed.example/demo'], check=True)
            with mock.patch.object(BUILD, 'SOURCE', source), mock.patch.object(BUILD, 'HERE', here), \
                 mock.patch.object(BUILD, 'run_logged') as run:
                with self.assertRaisesRegex(BUILD.BuildError, 'remote differs'):
                    BUILD.prefetch_incomplete_projects(cfg, graph, logdir)
                run.assert_not_called()

    def test_tag_mismatch_stops_before_repo_sync(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, here, logdir, gitdir, upstream, graph, cfg, _ = self.fixture(
                Path(tmp), revision='f' * 40)
            calls = []
            with mock.patch.object(BUILD, 'SOURCE', source), mock.patch.object(BUILD, 'HERE', here), \
                 mock.patch.object(BUILD, 'run_logged', side_effect=self.local_fetch(upstream, calls)):
                with self.assertRaisesRegex(BUILD.BuildError, 'Fetched tag does not identify'):
                    BUILD.prefetch_incomplete_projects(cfg, graph, logdir)
            self.assertEqual(len(calls), 1)

    def test_non_tag_upstream_or_url_rewrite_blocks_fetch(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, here, logdir, gitdir, upstream, graph, cfg, _ = self.fixture(
                Path(tmp), upstream_ref='refs/heads/main')
            with mock.patch.object(BUILD, 'SOURCE', source), mock.patch.object(BUILD, 'HERE', here), \
                 mock.patch.object(BUILD, 'run_logged') as run:
                with self.assertRaisesRegex(BUILD.BuildError, 'upstream tag'):
                    BUILD.prefetch_incomplete_projects(cfg, graph, logdir)
                run.assert_not_called()
            raw = (here / 'upstream-manifest.xml').read_bytes().replace(
                b'refs/heads/main', b'refs/tags/test-release')
            (here / 'upstream-manifest.xml').write_bytes(raw)
            graph = BUILD.source_graph(raw)
            subprocess.run(['git', 'config', '--file', str(gitdir / 'config'),
                            'url.file:///tmp/fake.insteadOf', 'https://example.org'], check=True)
            with mock.patch.object(BUILD, 'SOURCE', source), mock.patch.object(BUILD, 'HERE', here), \
                 mock.patch.object(BUILD, 'run_logged') as run:
                with self.assertRaisesRegex(BUILD.BuildError, 'Unsafe fetch configuration'):
                    BUILD.prefetch_incomplete_projects(cfg, graph, logdir)
                run.assert_not_called()


class PreflightTests(unittest.TestCase):
    def report(self, ram, disk, phase='build', source=0):
        with mock.patch.object(BUILD, 'memory_bytes', return_value=(ram * BUILD.GIB, ram * BUILD.GIB)), \
             mock.patch.object(BUILD.shutil, 'disk_usage', return_value=mock.Mock(free=disk * BUILD.GIB)), \
             mock.patch.object(BUILD, 'sync_source_allocated_bytes', return_value=source * BUILD.GIB):
            return BUILD.resource_report(BUILD.inputs(), phase)

    def test_swap_or_nominal_maximum_cannot_satisfy_ram_requirement(self):
        r = self.report(8, 500)
        self.assertTrue(any('allocated' in x for x in r['problems']))

    def test_packaging_and_retention_reserve_are_in_disk_preflight(self):
        r = self.report(48, 200)
        self.assertEqual(r['required_free_bytes'], 240 * BUILD.GIB)
        self.assertTrue(any('free' in x for x in r['problems']))

    def test_source_sync_does_not_require_build_ram(self):
        r = self.report(8, 500, 'sync')
        self.assertEqual(r['required_free_bytes'], 420 * BUILD.GIB)
        self.assertFalse(any('RAM' in x for x in r['problems']))

    def test_partial_source_only_reduces_remaining_source_allowance(self):
        at_limit = self.report(8, 380, 'sync', source=40)
        self.assertEqual(at_limit['required_free_bytes'], 380 * BUILD.GIB)
        self.assertEqual(at_limit['source_sync_credit_bytes'], 40 * BUILD.GIB)
        self.assertFalse(any('free' in x for x in at_limit['problems']))
        self.assertTrue(any('free' in x for x in self.report(8, 379, 'sync', source=40)['problems']))

    def test_source_credit_is_capped_and_external_consumption_still_counts(self):
        self.assertEqual(self.report(8, 240, 'sync', source=500)['required_free_bytes'], 240 * BUILD.GIB)
        self.assertEqual(self.report(8, 360, 'sync', source=40)['required_free_bytes'], 380 * BUILD.GIB)
        self.assertTrue(any('free' in x for x in self.report(8, 360, 'sync', source=40)['problems']))
        self.assertEqual(BUILD.synced_build_budget_bytes(BUILD.inputs()), 240 * BUILD.GIB)

    def test_only_pinned_source_checkout_is_credited_and_out_is_excluded(self):
        with tempfile.TemporaryDirectory() as tmp:
            workspace = Path(tmp)
            source = workspace / 'source'
            source.mkdir()
            with mock.patch.object(BUILD, 'WORKSPACE', workspace), mock.patch.object(BUILD, 'SOURCE', source):
                cfg = {'manifest_commit': '', 'repo_commit': '', 'manifest_sha256': ''}
                (source / 'unrelated').write_bytes(b'x' * (1024 * 1024))
                self.assertEqual(BUILD.sync_source_allocated_bytes(cfg), 0)
                metadata = source / '.repo'
                manifest = metadata / 'manifests'
                repo_tool = metadata / 'repo'
                for path in (manifest, repo_tool):
                    path.mkdir(parents=True)
                    subprocess.run(['git', 'init', '-q', str(path)], check=True)
                (manifest / 'default.xml').write_text('<manifest/>')
                subprocess.run(['git', '-C', str(manifest), 'add', 'default.xml'], check=True)
                for path in (manifest, repo_tool):
                    subprocess.run(['git', '-C', str(path), '-c', 'user.name=Test',
                                    '-c', 'user.email=test@localhost', 'commit', '-qm', 'pin',
                                    '--allow-empty'], check=True)
                cfg = {'manifest_commit': subprocess.check_output(['git', '-C', str(manifest),
                        'rev-parse', 'HEAD']).decode().strip(),
                       'repo_commit': subprocess.check_output(['git', '-C', str(repo_tool),
                        'rev-parse', 'HEAD']).decode().strip(),
                       'manifest_sha256': BUILD.sha256(manifest / 'default.xml')}
                (source / 'out').mkdir()
                (source / 'out' / 'large-output').write_bytes(b'x' * (8 * 1024 * 1024))
                credited = BUILD.sync_source_allocated_bytes(cfg)
                self.assertGreater(credited, 1024 * 1024)
                self.assertLess(credited, 4 * 1024 * 1024)
                cfg['manifest_commit'] = '0' * 40
                with self.assertRaisesRegex(BUILD.BuildError, 'manifest commit'):
                    BUILD.sync_source_allocated_bytes(cfg)

    def test_build_needs_device_evidence(self):
        with self.assertRaisesRegex(BUILD.BuildError, 'fresh MP01'):
            BUILD.validate_device_inventory(None)


class TranscriptTests(unittest.TestCase):
    def invoke(self, folder, command, reserve=0):
        BUILD.run_logged(['/bin/sh', '-c', command], folder, os.environ.copy(),
                         folder / 'build.log', reserve)

    def test_success_keeps_stdout_stderr_and_resource_samples(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            self.invoke(folder, 'printf output; printf error >&2')
            self.assertEqual((folder / 'build.log').read_text(), 'outputerror')
            self.assertTrue(json.loads((folder / 'resources.json').read_text()))

    def test_child_failure_cannot_be_hidden_by_logging(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            with self.assertRaisesRegex(BUILD.BuildError, 'failed \\(7\\)'):
                self.invoke(folder, 'printf failed; exit 7')
            self.assertEqual((folder / 'build.log').read_text(), 'failed')

    def test_log_fsync_failure_cannot_produce_success(self):
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(BUILD.os, 'fsync', side_effect=OSError('disk error')):
            with self.assertRaises(OSError):
                self.invoke(Path(tmp), 'printf output')

    def test_lost_reserve_terminates_the_build(self):
        samples = [mock.Mock(free=2 * BUILD.GIB), mock.Mock(free=0)]
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(BUILD.shutil, 'disk_usage', side_effect=samples):
            with self.assertRaisesRegex(BUILD.BuildError, 'reserve allowance exhausted'):
                self.invoke(Path(tmp), 'sleep 30', BUILD.GIB)

    def test_monitor_error_terminates_the_build(self):
        samples = [mock.Mock(free=2 * BUILD.GIB), OSError('cannot measure disk')]
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(BUILD.shutil, 'disk_usage', side_effect=samples):
            with self.assertRaisesRegex(BUILD.BuildError, 'Resource monitor failed'):
                self.invoke(Path(tmp), 'sleep 30', BUILD.GIB)


if __name__ == '__main__':
    unittest.main()
