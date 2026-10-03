"""Mocks are test-only. Runtime code never has a successful fake-WireGuard mode."""
import os
import sys
from pathlib import Path
os.environ["db_name"] = "avantime_connect_test"
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
if os.environ.get('AVANTIME_MOCK_MONGO') == '1':
    from mongomock_motor import AsyncMongoMockClient
    from app.db import mongo
    mongo.db = AsyncMongoMockClient()['avantime_connect_test']

import pytest
from app.services import wireguard

@pytest.fixture(autouse=True)
def fake_wireguard(monkeypatch, request):
    if request.node.path.name == "test_wg_transport.py":
        return
    async def occupied():
        return []
    async def add(*args):
        pass
    async def remove(*args):
        pass
    monkeypatch.setattr(wireguard, 'occupied_networks', occupied)
    monkeypatch.setattr(wireguard, 'add_peer', add)
    monkeypatch.setattr(wireguard, 'remove_peer', remove)
