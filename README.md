# Avantime Connect

Утилита автонастройки (WireGuard + RDP/RemoteApp) и внутренняя админ-панель.

## Структура
- admin-backend/  — FastAPI + MongoDB (Фаза 1: пользователи, приглашения, enroll, IPAM)
- admin-frontend/ — React + TypeScript + Vite (Фаза 2: админка)
- windows-client/ — WPF (.NET) (Фаза 3, не входит в 1-2)
- shared/, docs/

## Требования
- Python 3.11+, Node 18+, MongoDB (локально или docker)

## Запуск backend
    cd admin-backend
    python3 -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    # Mongo: docker run -d -p 27017:27017 mongo:7
    uvicorn app.main:app --reload
    # Swagger: http://localhost:8000/docs

## Запуск админки
    cd admin-frontend
    npm install
    npm run dev          # http://localhost:5173 (API проксируется на :8000)

## Проверка сценария
1. POST /api/users/ — создать пользователя
2. POST /api/invites/{login} — получить токен
3. POST /api/enroll/ — токен + public_key + device_name -> выдаётся VPN-адрес
4. GET  /api/devices/ и POST /api/devices/{public_key}/revoke

## Статус
- Реализовано и проверяемо локально: users, invites, enroll, IPAM, devices, админка.
- ЗАГЛУШКА: app/services/wireguard.py (add_peer/remove_peer) — требует SSH к WG-серверу.
- Авторизация админки НЕ реализована (контур закрытый); добавить перед деплоем.

## Безопасность
- Приватные ключи/пароли/токены в Git НЕ хранятся.
- .env не коммитить.
