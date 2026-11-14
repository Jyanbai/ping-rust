"""Disposable systemd runner: old-schema binary, automatic upgrade and rollback."""
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import tempfile
from pathlib import Path


def verify_sudoku_compatibility(binary, run, state, pid, free_port, menu_edit):
    shoes = Path('/usr/local/bin/shoes')

    def replace_binary(content):
        with tempfile.NamedTemporaryFile(dir=shoes.parent, delete=False) as candidate:
            candidate.write(content)
            candidate_path = Path(candidate.name)
        candidate_path.chmod(0o755)
        os.replace(candidate_path, shoes)

    provenance_path = Path('/var/lib/ping-rust/shoes-install.json')
    backup = shoes.with_name('shoes-sudoku-fixture-backup')
    assert not backup.exists()
    shoes.rename(backup)
    # Model an old, digest-tracked release while retaining a real working kernel
    # for the existing non-Sudoku service. Never rely on the reported version.
    shoes.write_text('#!/bin/sh\n'
                     'if [ "$1" = --dry-run ] && grep -q sudoku_mask "$2"; then\n'
                     "  echo 'invalid protocol: unknown variant `sudoku_mask`' >&2\n"
                     '  exit 1\nfi\nexec ' + shlex.quote(str(backup)) + ' "$@"\n')
    shoes.chmod(0o755)
    provenance = json.loads(provenance_path.read_text())
    provenance.update(version='0.3.6', release_tag='v0.3.6',
                      binary_sha256=hashlib.sha256(shoes.read_bytes()).hexdigest())
    provenance_path.write_text(json.dumps(provenance))
    original_binary = shoes.read_bytes()
    original_provenance = provenance_path.read_bytes()
    files = lambda: {str(p): p.read_bytes() for p in Path('/etc/shoes').rglob('*') if p.is_file()}
    original_files = files()
    port = free_port()
    args = ['add', 'vless-sudoku', '--name', 'compat-sudoku', '--port', str(port),
            '--server-address', '127.0.0.1', '--yes', '--plain']
    try:
        # Invalid additions must be rejected before the independently committed
        # kernel upgrade can migrate files or restart the existing service.
        existing = state()['profiles'][0]
        original_pid = pid()
        invalid_requests = [
            (['--port', '0'], '端口必须在'),
            (['--port', str(existing['port'])], '已由现有配置使用'),
            (['--port', str(port), '--name', ' ' + existing['name'].swapcase() + ' '],
             '名称必须唯一'),
            (['--port', str(port), '--name', ' '], '配置名称必须为'),
        ]
        for options, expected_error in invalid_requests:
            result = subprocess.run(
                [binary, 'generate', 'vless-sudoku', *options],
                capture_output=True, timeout=360)
            errors = result.stderr.decode()
            assert result.returncode != 0 and expected_error in errors, errors
            assert '正在自动升级' not in errors, errors
            assert shoes.read_bytes() == original_binary
            assert provenance_path.read_bytes() == original_provenance
            assert files() == original_files, 'invalid request changed managed configuration'
            assert pid() == original_pid, 'invalid request restarted the existing service'
        with tempfile.TemporaryDirectory(prefix='prs-sudoku-restart-failure-') as temporary:
            root = Path(temporary)
            marker = root / 'failed-once'
            wrapper = root / 'systemctl'
            wrapper.write_text('#!/bin/sh\nif [ "$1" = restart ] && [ ! -e ' + shlex.quote(str(marker)) + ' ]; then\n touch ' + shlex.quote(str(marker)) + '\n exit 42\nfi\nexec ' + shlex.quote(shutil.which('systemctl')) + ' "$@"\n')
            wrapper.chmod(0o755)
            environment = dict(os.environ, PATH=str(root) + ':' + os.environ['PATH'])
            result = subprocess.run([binary, *args], env=environment, capture_output=True, timeout=360)
            assert result.returncode != 0 and marker.exists(), 'upgrade restart fault was not exercised'
            assert shoes.read_bytes() == original_binary
            assert provenance_path.read_bytes() == original_provenance
            assert files() == original_files, 'failed automatic upgrade changed managed configuration'
            pid()
        _, errors = run(*args)
        assert '正在自动升级' in errors
        assert shoes.read_bytes() != original_binary
        pid()
        entry = next(e for e in state()['sudoku_profiles'] if e['profile']['name'] == 'compat-sudoku')
        plain = entry['profile']
        new_port = free_port()
        menu_edit(entry['position'], port=new_port)
        # Deleting the last mask must work even with an incompatible, untracked
        # binary: no download or implicit downgrade may be required to recover.
        installed_binary = shoes.read_bytes()
        installed_provenance = provenance_path.read_bytes()
        replace_binary(original_binary)
        try:
            # With a Sudoku node still managed, an invalid deletion must not
            # upgrade even when the old binary's provenance permits it.
            provenance_path.write_bytes(original_provenance)
            missing_id = '00000000-0000-0000-0000-000000000000'
            current_state = state()
            assert all(p['id'] != missing_id for p in current_state['profiles'])
            assert all(e['profile']['id'] != missing_id
                       for e in current_state['sudoku_profiles'])
            before_files = files()
            before_pid = pid()
            result = subprocess.run(
                [binary, 'delete', missing_id, '--yes'],
                capture_output=True, timeout=360)
            errors = result.stderr.decode()
            assert result.returncode != 0 and f'未找到配置 {missing_id}' in errors, errors
            assert '正在自动升级' not in errors, errors
            assert shoes.read_bytes() == original_binary
            assert provenance_path.read_bytes() == original_provenance
            assert files() == before_files, 'invalid deletion changed managed configuration'
            assert pid() == before_pid, 'invalid deletion restarted the existing service'
            # 修改请求同样必须先校验再自动升级：对非 NaiveProxy 节点重新生成测试证书
            # 不得升级内核、迁移配置、改动来源记录或重启服务。
            not_naive = next(p for p in current_state['profiles']
                             if 'NaiveProxy' not in p['credentials'])
            result = subprocess.run(
                [binary, 'regenerate-test-certificate', not_naive['id']],
                capture_output=True, timeout=360)
            errors = result.stderr.decode()
            assert (result.returncode != 0
                    and '只有 NaiveProxy 自签测试节点支持重新生成测试证书' in errors), errors
            assert '正在自动升级' not in errors, errors
            assert shoes.read_bytes() == original_binary
            assert provenance_path.read_bytes() == original_provenance
            assert files() == before_files, 'invalid modification changed managed configuration'
            assert pid() == before_pid, 'invalid modification restarted the existing service'
            provenance_path.write_bytes(installed_provenance)
            _, errors = run('delete', plain['id'], '--yes')
            assert '正在自动升级' not in errors
        finally:
            replace_binary(installed_binary)
            provenance_path.write_bytes(installed_provenance)
        run('add', 'vless-enc', '--sudoku', '--name', 'compat-enc-sudoku', '--port', str(free_port()),
            '--server-address', '127.0.0.1', '--yes', '--plain')
        encrypted = next(p for p in state()['profiles'] if p['name'] == 'compat-enc-sudoku')
        menu_edit(state()['profiles'].index(encrypted), port=free_port())
        run('delete', encrypted['id'], '--yes')
        pid()
        print('PASS Sudoku automatic upgrade rollback and plain/encrypted add/edit/delete lifecycle')
    finally:
        backup.unlink()
