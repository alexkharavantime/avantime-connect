"""Server-authoritative access. Enrollment snapshots remain immutable."""
import hashlib
from fastapi import HTTPException
from app.db.mongo import db
from app.services import wireguard
from app.models import AccessSettings

HOSTS = {'dev': '10.20.0.20', 'prod': '10.40.0.20'}

def group(login):
    return hashlib.sha256(login.encode()).hexdigest()

def policy(user):
    return AccessSettings(environments=user.get('environments', ['prod'])).environments, user.get('access_revision', 0)

def profile_fields(environments, revision):
    routes = [('10.40.0.0/24' if e == 'prod' else HOSTS[e] + '/32') for e in environments]
    # PROD already includes DNS; DEV receives only the DNS host, not PROD access.
    if 'prod' not in environments:
        routes.append('10.40.0.10/32')
    return {'environments': environments, 'access_revision': revision,
            'allowed_ips': ', '.join(routes),
            'rdp_host': HOSTS['prod' if 'prod' in environments else 'dev']}

async def reconcile(dev):
    user = await db.users.find_one({'login': dev['login']})
    if not user:
        raise HTTPException(409, 'Пользователь отсутствует')
    environments, revision = policy(user)
    await wireguard.set_user_access(group(dev['login']), environments, revision)
    await wireguard.set_access(dev['public_key'], dev['vpn_ip'], dev['wg_owner'], environments, revision, group(dev['login']))
    result = await db.devices.update_one({'_id': dev['_id'], 'state': 'active',
        '$or': [{'applied_access_revision': {'$exists': False}}, {'applied_access_revision': {'$lte': revision}}]},
        {'$set': {'applied_environments': environments, 'applied_access_revision': revision}})
    if result.matched_count != 1:
        raise HTTPException(409, 'Состояние устройства изменилось; повторите проверку')
    latest = await db.users.find_one({'login': dev['login']})
    if not latest or policy(latest) != (environments, revision):
        raise HTTPException(409, 'Назначение доступа изменилось; повторите операцию')
    return profile_fields(environments, revision)
