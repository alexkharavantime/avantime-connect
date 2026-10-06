import json
import pytest
from app.config import settings
from app.services import wireguard as wg
pytestmark = pytest.mark.asyncio(loop_scope='session')

@pytest.fixture
def ssh(monkeypatch):
    monkeypatch.setattr(settings, 'wg_mode', 'ssh')
    monkeypatch.setattr(settings, 'admin_api_token', 's' * 32)

async def test_disabled_is_not_success(monkeypatch):
    monkeypatch.setattr(settings, 'wg_mode', 'disabled')
    with pytest.raises(wg.WireGuardError, match='disabled'):
        await wg.request({'action': 'status'})

async def test_strict_ssh_and_json_stdin(ssh, monkeypatch):
    captured = {}
    class Process:
        returncode = 0
        async def communicate(self, data):
            captured['data'] = json.loads(data)
            return b'{"ok":true}', None
    async def spawn(*args, **kwargs):
        captured['args'] = args
        return Process()
    monkeypatch.setattr(wg.asyncio, 'create_subprocess_exec', spawn)
    assert await wg.request({'action': 'status'}) == {'ok': True}
    assert captured['data'] == {'action': 'status'}
    assert 'StrictHostKeyChecking=yes' in captured['args']
    assert 'BatchMode=yes' in captured['args']
    assert 'GlobalKnownHostsFile=/dev/null' in captured['args']
    assert captured['args'][-1] == 'avantime-wg@10.20.0.2'

@pytest.mark.parametrize('rc,out', [(255, b''), (0, b'WG_ACCESS_OK'), (0, b'{"ok":false}'), (0, b'[]')])
async def test_ssh_failure_never_success(ssh, monkeypatch, rc, out):
    class Process:
        returncode = rc
        async def communicate(self, data):
            return out, None
    async def spawn(*args, **kwargs):
        return Process()
    monkeypatch.setattr(wg.asyncio, 'create_subprocess_exec', spawn)
    with pytest.raises(wg.WireGuardError):
        await wg.request({'action': 'status'})

async def test_timeout_kills_local_process(ssh, monkeypatch):
    calls = []
    class Process:
        returncode = None
        async def communicate(self, data):
            raise TimeoutError()
        def kill(self):
            calls.append('kill')
        async def wait(self):
            calls.append('wait')
    async def spawn(*args, **kwargs):
        return Process()
    monkeypatch.setattr(wg.asyncio, 'create_subprocess_exec', spawn)
    with pytest.raises(wg.WireGuardError, match='unknown'):
        await wg.request({'action': 'status'})
    assert calls == ['kill', 'wait']

async def test_server_key_mismatch(monkeypatch):
    async def response(payload):
        return {'ok': True, 'server_public_key': 'other', 'occupied': []}
    monkeypatch.setattr(wg, 'request', response)
    with pytest.raises(wg.WireGuardError, match='mismatch'):
        await wg.occupied_networks()

async def test_add_requires_matching_result(monkeypatch):
    import base64
    async def response(payload):
        return {'ok': True, 'state': 'active', 'ip': '10.30.0.8', 'owner': 'different'}
    monkeypatch.setattr(wg, 'request', response)
    with pytest.raises(wg.WireGuardError, match='Unexpected'):
        await wg.add_peer(base64.b64encode(b'X' * 32).decode(), '10.30.0.7', 'owner')

@pytest.mark.parametrize('confirmation', [None, False, 'true', 1])
async def test_remove_requires_explicit_confirmation(monkeypatch, confirmation):
    import base64
    async def response(payload):
        return {'ok': True, 'state': 'revoked', 'ip': '10.30.0.7', 'owner': 'owner',
                'absence_confirmed': confirmation}
    monkeypatch.setattr(wg, 'request', response)
    with pytest.raises(wg.WireGuardError, match='Unexpected remove'):
        await wg.remove_peer(base64.b64encode(b'X' * 32).decode(), '10.30.0.7', 'owner')

@pytest.mark.parametrize('created', [True, False])
async def test_add_reports_creation(monkeypatch, created):
    import base64
    async def response(payload):
        return {'ok': True, 'state': 'active', 'ip': '10.30.0.7', 'owner': 'owner', 'created': created}
    monkeypatch.setattr(wg, 'request', response)
    assert await wg.add_peer(base64.b64encode(b'X' * 32).decode(), '10.30.0.7', 'owner') is created
