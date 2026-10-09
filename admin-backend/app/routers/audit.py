from datetime import datetime, timezone
import csv
import io
from fastapi import APIRouter, Query, HTTPException
from fastapi.responses import StreamingResponse
from app.db.mongo import db

router = APIRouter()

def selection(login='', start=None, end=None):
    query = {}
    if login:
        query['login'] = login
    dates = {}
    for value, op in ((start, '$gte'), (end, '$lt')):
        if value:
            try:
                date = datetime.fromisoformat(value.replace('Z', '+00:00'))
                if date.tzinfo is None:
                    date = date.replace(tzinfo=timezone.utc)
                dates[op] = date
            except ValueError:
                raise HTTPException(422, 'Некорректная дата')
    if '$gte' in dates and '$lt' in dates and dates['$gte'] >= dates['$lt']:
        raise HTTPException(422, 'Начало периода должно быть раньше окончания')
    if dates:
        query['timestamp'] = dates
    return query

def public(row):
    return {k: (str(v) if k == '_id' else v) for k, v in row.items()}

@router.get('/')
async def events(login: str = '', start: str | None = None, end: str | None = None,
                 offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=500)):
    query = selection(login, start, end)
    rows = [public(r) async for r in db.audit_events.find(query).sort([('timestamp', -1), ('_id', -1)]).skip(offset).limit(limit)]
    return {'items': rows, 'total': await db.audit_events.count_documents(query)}

@router.get('/export')
async def export(login: str = '', start: str | None = None, end: str | None = None):
    query = selection(login, start, end)
    def line(values):
        output = io.StringIO()
        # Spreadsheet formula injection, including whitespace-prefixed values.
        safe = []
        for value in values:
            value = str(value)
            safe.append("'" + value if value.lstrip().startswith(('=', '+', '-', '@')) or value.startswith(('\t', '\r', '\n')) else value)
        csv.writer(output, delimiter=';').writerow(safe)
        return output.getvalue()
    async def rows():
        yield '\ufeff' + line(['Дата UTC', 'Операция', 'Результат', 'Логин', 'Компьютер', 'VPN-IP', 'Доступ', 'Источник', 'Инициатор', 'HTTP'])
        async for r in db.audit_events.find(query).sort([('timestamp', -1), ('_id', -1)]):
            yield line([r['timestamp'].isoformat() + ('Z' if r['timestamp'].tzinfo is None else ''), r['action'], r['status'],
                        r.get('login', ''), r.get('device_name', ''), r.get('vpn_ip', ''),
                        ', '.join(r.get('environments', [])), r['source'], r['actor'], r.get('http_status', '')])
    return StreamingResponse(rows(), media_type='text/csv; charset=utf-8',
                             headers={'Content-Disposition': 'attachment; filename="avantime-access-journal.csv"', 'Cache-Control': 'no-store'})
