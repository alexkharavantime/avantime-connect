# Avantime Connect

Утилита однократной автонастройки подключения к серверу Avantime (WireGuard + RDP/RemoteApp)
и внутренняя админ-панель управления доступами.

## Структура
- `admin-backend/`  — FastAPI + MongoDB
- `admin-frontend/` — React + TypeScript (внутренний контур)
- `windows-client/` — WPF (.NET), клиент Windows
- `shared/`         — контракт API (OpenAPI/JSON)
- `docs/`           — ТЗ, план, сеть, безопасность

## Параметры сети (см. docs/network.md)
- WG Endpoint: 65.21.22.189:51820
- Серверная сеть: 10.40.0.0/24 (RDP-хост 10.40.0.20)
- VPN-клиенты: отдельный пул (НЕ 10.40.0.0/24), уникальный адрес+ключи на устройство
