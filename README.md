# Avantime Connect

Утилита автонастройки (WireGuard + RDP/RemoteApp) и внутренняя админ-панель.

## Структура
- admin-backend/  — FastAPI + MongoDB (Фаза 1)
- admin-frontend/ — React + TypeScript + Vite (Фаза 2)
- windows-client/ — WPF (.NET) (Фаза 3, вне 1-2)

## Требования
- Python 3.11+, Node 18+, MongoDB 7 (локально или docker)

## Backend
    cd admin-backend
    python3 -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    # Mongo: docker run -d -p 27017:27017 mongo:7
    uvicorn app.main:app --reload        # http://localhost:8000/docs

## Тесты backend (нужен запущенный MongoDB)
    pip install -r requirements-dev.txt
    pytest                               # использует БД avantime_connect_test

## Frontend
    cd admin-frontend
    npm install
    npm run build                        # tsc --noEmit && vite build
    npm run dev                          # http://localhost:5173 (прокси /api -> :8000)

## Сценарий проверки
1. POST /api/users/           — создать пользователя
2. POST /api/invites/{login}  — получить токен
3. POST /api/enroll/          — token + public_key + device_name -> VPN-адрес
4. GET  /api/devices/, POST /api/devices/{public_key}/revoke

## Известные ограничения
- app/services/wireguard.py (add_peer/remove_peer) — ЗАГЛУШКА. Реальное заведение peer
  требует SSH к WG-серверу; в тестах используется имитация, боевой VPN не трогается.
- Авторизации административных операций НЕТ (контур закрытый). Добавить перед деплоем.
- Секреты/приватные ключи/токены в Git не хранятся; .env не коммитить.
