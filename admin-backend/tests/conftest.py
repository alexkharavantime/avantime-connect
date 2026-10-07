"""Mocks are test-only. Runtime code never has a successful fake-WireGuard mode."""
import os
import sys
import importlib.util
import json
from pathlib import Path
os.environ["db_name"] = "avantime_connect_test"
# Never inherit a developer's production mongo_uri or SSH mode from .env.
os.environ['mongo_uri'] = os.environ.get('AVANTIME_TEST_MONGO_URI', 'mongodb://127.0.0.1:27018')
os.environ['wg_mode'] = 'disabled'
os.environ['admin_api_token'] = ''
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest
from app.services import wireguard
from app.config import settings

@pytest.fixture(autouse=True)
def fake_wireguard(monkeypatch, request, tmp_path):
    if request.node.path.name == "test_wg_transport.py":
        return
    spec = importlib.util.spec_from_file_location(
        'test_helper', Path(__file__).resolve().parents[2] / 'deploy/wireguard/helper.py')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    helper.CONF = tmp_path / 'wg0.conf'
    helper.CONF.write_text('[Interface]\nAddress = 10.30.0.1/24\n')
    helper.STATE = tmp_path / 'state'
    peers, calls = {}, []

    def run(args):
        if args[0] == helper.IP:
            return json.dumps([{'addr_info': [{'local': '10.30.0.1'}]}])
        if args[1:4] == ['show', 'wg0', 'allowed-ips']:
            return '\n'.join(key + '\t' + ' '.join(nets) for key, nets in peers.items())
        if args[1:4] == ['show', 'wg0', 'public-key']:
            return settings.wg_server_public_key
        if args[1:4] == ['set', 'wg0', 'peer']:
            if args[5] == 'remove':
                peers.pop(args[4], None)
            else:
                peers[args[4]] = [args[6]]
            return ''
        raise AssertionError(args)

    helper.run = run

    async def dispatch(payload):
        calls.append(dict(payload))
        try:
            return helper.execute(payload)
        except helper.Refused as exc:
            raise wireguard.WireGuardError(str(exc)) from exc

    monkeypatch.setattr(wireguard, 'request', dispatch)
    return {'helper': helper, 'peers': peers, 'calls': calls, 'dispatch': dispatch}
