#!/usr/bin/env python3
"""Run as alex on avg-connect-dev from a checkout of this release after sudo -v."""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request

assert socket.gethostname() == 'avg-connect-dev', 'Wrong server'
os.umask(0o077)
source = Path(__file__).resolve().parents[2]
docker = ['sudo', '-n', 'docker']
def run(args, **kw):
    return subprocess.run(args, check=True, **kw)
def inspect(name, kind='container'):
    return json.loads(subprocess.check_output(docker + [kind, 'inspect', name]))[0]
ui = inspect('avantime-connect-wg-ui-1')
api = inspect('avantime-connect-wg-api-1')
labels = ui['Config']['Labels']
cfg = Path(labels['com.docker.compose.project.config_files'])
assert api['Config']['Labels']['com.docker.compose.project.config_files'] == str(cfg)
assert cfg == Path.home() / 'avantime-connect-runtime-0.4.0/compose.release.json'
original = cfg.read_bytes()
config = json.loads(original)
mounts = [m for m in ui['Mounts'] if m['Destination'] == '/app' and m['Type'] == 'bind']
assert len(mounts) == 1
old = Path(mounts[0]['Source'])
new = source / 'admin-frontend'
assert old.resolve() != new.resolve(), 'Use a separate release checkout'
assert (old / 'vite.deploy.config.ts').is_file()
assert '0.5.1' in (new / 'src/App.tsx').read_text()
shutil.copy2(old / 'vite.deploy.config.ts', new / 'vite.deploy.config.ts')
for file in old.glob('.env*'):
    if file.is_file():
        shutil.copy2(file, new / file.name)
revision = subprocess.check_output(['git', '-C', str(source), 'rev-parse', 'HEAD'], text=True).strip()
image = 'avantime-connect-integration:0.5.1-' + revision[:12]
print('Building admin and API from', revision, flush=True)
run(docker + ['run', '--rm', '-v', str(new)+':/app', '-w', '/app', ui['Config']['Image'],
              'sh', '-c', 'npm ci && npm run test:ui && npm run build'])
run(docker + ['build', '--label', 'org.opencontainers.image.revision='+revision,
              '-t', image, str(source / 'admin-backend')])
backup = Path(tempfile.mkdtemp(prefix='avantime-backup-0.5.1-', dir=Path.home()))
(backup / 'compose.before.json').write_bytes(original)
with (backup / 'mongo.before.archive.gz').open('wb') as out:
    run(docker + ['exec', 'avantime-connect-wg-mongo-1', 'mongodump', '--archive', '--gzip'], stdout=out, timeout=180)
assert (backup / 'mongo.before.archive.gz').stat().st_size > 0
def matches_old(value):
    path = Path(value)
    if not path.is_absolute():
        path = Path(labels['com.docker.compose.project.working_dir']) / path
    return path.resolve() == old.resolve()
count = 0
for i, v in enumerate(config['services']['ui']['volumes']):
    if isinstance(v, str):
        bits = v.split(':')
        if len(bits) >= 2 and bits[1] == '/app':
            assert matches_old(bits[0])
            bits[0] = str(new)
            config['services']['ui']['volumes'][i] = ':'.join(bits)
            count += 1
    elif v.get('target') == '/app':
        assert v.get('type') == 'bind' and matches_old(v['source'])
        v['source'] = str(new)
        count += 1
assert count == 1
assert 'build' not in config['services']['api']
config['services']['api']['image'] = image
compose = docker + ['compose', '-p', labels['com.docker.compose.project'], '--project-directory',
                    labels['com.docker.compose.project.working_dir'], '-f', str(cfg)]
def replace(data):
    fd, name = tempfile.mkstemp(dir=cfg.parent, prefix='.release-')
    try:
        with os.fdopen(fd, 'wb') as out:
            out.write(data)
        os.replace(name, cfg)
    finally:
        if os.path.exists(name):
            os.unlink(name)
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
def get(path, port):
    req = urllib.request.Request(f'http://127.0.0.1:{port}{path}', headers={'Host':'connect.avantime.lv'})
    with opener.open(req, timeout=3) as r:
        return r.read().decode()
def ready():
    for _ in range(60):
        try:
            if json.loads(get('/api/health',8000)).get('status') == 'ok' and '0.5.1' in get('/src/App.tsx',5173):
                return True
        except Exception:
            pass
        time.sleep(2)
    return False
print('Backup:', backup, flush=True)
try:
    replace(json.dumps(config, indent=2).encode())
    run(compose + ['config','--quiet'])
    run(compose + ['up','-d','--no-deps','--force-recreate','api','ui'])
    assert ready(), 'Readiness failed'
    after = inspect('avantime-connect-wg-api-1')
    assert after['Image'] == inspect(image, 'image')['Id']
    assert sorted(after['Config']['Env']) == sorted(api['Config']['Env'])
    probe = '''
import json, urllib.request
from app.config import settings
req = urllib.request.Request('http://127.0.0.1:8000/api/audit/?limit=1', headers={'Authorization':'Bearer '+settings.admin_api_token})
with urllib.request.urlopen(req, timeout=10) as r:
    data = json.load(r)
    assert 'items' in data and 'total' in data
print('Audit API: OK')
'''
    run(docker + ['exec','avantime-connect-wg-api-1','python','-c',probe], timeout=20)
except Exception as exc:
    print('Update failed:', type(exc).__name__, '; restoring previous API and UI.', flush=True)
    replace(original)
    run(compose + ['up','-d','--no-deps','--force-recreate','api','ui'])
    print('Previous configuration restored. Verify previous UI/API health. Backup:', backup)
    raise SystemExit(1)
print('ADMIN + AUDIT 0.5.1: OK')
print('Open https://connect.avantime.lv and hard-refresh. Header must show 0.5.1.')
print('Backup:', backup)
