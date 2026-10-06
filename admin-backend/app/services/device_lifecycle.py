"""Only a verified helper result permits revoking -> revoked."""
from datetime import datetime, timezone
from pymongo import ReturnDocument
from app.db.mongo import db
from app.services import wireguard


async def finish_revocation(dev):
    # The helper verifies runtime/config absence and persists the owned tombstone
    # under the same flock. Repeating this also handles a lost removal reply.
    await wireguard.remove_peer(dev['public_key'], dev['vpn_ip'], dev['wg_owner'])
    return await db.devices.find_one_and_update(
        {'_id': dev['_id'], 'state': 'revoking'},
        {'$set': {'state': 'revoked', 'revoked': True,
                  'revoked_at': datetime.now(timezone.utc)}},
        return_document=ReturnDocument.AFTER)
