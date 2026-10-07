# Avantime Connect

Утилита автонастройки (WireGuard + RDP/RemoteApp) и внутренняя админ-панель.

## Структура
- admin-backend/  — FastAPI + MongoDB (Фаза 1)
- admin-frontend/ — React + TypeScript + Vite (Фаза 2)
- windows-client/ — WPF (.NET) (Фаза 3, вне 1-2)

## Требования
- Python 3.11+, MongoDB 7 (локально или Docker).
- Node.js 22.22.2+ (22.x), 24.15.0+ (24.x) или 26+ (`engines` в package.json и lockfile, включая UI-тесты).

## Backend
    cd admin-backend
    python3 -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    # Mongo: docker run -d -p 127.0.0.1:27017:27017 mongo:7
    uvicorn app.main:app --reload        # http://localhost:8000/docs

## Тесты backend (отдельная тестовая MongoDB)
    docker run --rm -d --name avantime-connect-test-mongo -p 127.0.0.1:27018:27017 mongo:7
    pip install -r requirements-dev.txt
    pytest                               # localhost:27018, БД avantime_connect_test

Для другого **тестового** экземпляра задать `AVANTIME_TEST_MONGO_URI`.
Тесты принудительно выбирают `avantime_connect_test`, очищают её коллекции и
не наследуют рабочий `mongo_uri`/SSH-режим из `.env`. Helper и системные команды
WireGuard имитируются; успешные тесты не подтверждают работу реального VPN.
Из корня: `python -m pytest -q tests` — отдельные тесты helper.

## Frontend
    cd admin-frontend
    npm ci
    npm run typecheck
    npm run build                        # tsc --noEmit && vite build
    npm run dev                          # http://localhost:5173 (прокси /api -> :8000)

UI-регрессии: `npm run test:ui` (Vitest + jsdom, все запросы API подменены).
Это компонентные проверки поведения интерфейса, не браузерная интеграция с backend.

## Сценарий проверки
1. POST /api/users/           — создать пользователя
2. POST /api/invites/{login}  — получить токен
3. POST /api/enroll/          — token + public_key + device_name -> VPN-адрес
4. GET  /api/devices/, POST /api/devices/{public_key}/revoke

В `wg_mode=disabled` новая регистрация не создаёт peer и возвращает 503.
В `wg_mode=ssh` backend вызывает ограниченный root-helper через SSH с обязательной
проверкой host key и передачей JSON через stdin. Подготовка сервера и SSH-ключей
описана в [инструкции](docs/WIREGUARD_INTEGRATION_RU.md); в рамках PR-review
подключения и установки на VM 101 **не выполнялись**.

## Восстановление регистрации и отзыв

Один токен закрепляется за одной парой `public_key` + `device_name`.
Повтор завершённого enroll с той же тройкой token/key/device возвращает 200 и
**сохранённый** профиль, без нового peer/IP и без пересчёта по текущему конфигу.
`ENROLL_RECOVERY_TTL=86400` (секунды, по умолчанию 24 часа) отсчитывается от
`completed_at`; повторы не продлевают окно. Другой ключ/имя — 409, истёкшее окно —
410, `revoking`/`revoked` — отказ. Срок нового приглашения этим не продлевается.
Для старых записей без снимка профиль не реконструируется: повтор использованного
токена возвращает 409.

Отозвать можно `pending` и `active`. Атомарный переход в `revoking` предшествует
удалению; `revoked` выставляется только после подтверждения helper: peer отсутствует
в runtime и конфигурации, в `managed.json` сохранена защитная запись `revoked`.
При потере ответа возвращается 502, состояние остаётся `revoking`, отзыв нужно
повторить. Поздний enroll не может заменить отмену на `active`; его успешный поздний
add-ответ вызывает компенсирующее удаление. Helper запрещает add по защитной записи.

IP отозванных устройств остаются зарезервированы в MongoDB и `managed.json`.
Пул может исчерпаться; автоматического освобождения IP нет. Не удалять защитные записи.

## Известные ограничения
- Административные API защищены Bearer-токеном, если `admin_api_token` задан;
  в SSH-режиме он обязателен и должен содержать минимум 32 символа. В disabled без
  токена административная авторизация не включена: использовать только локально.
- Полноценных пользовательских ролей, TLS reverse proxy, rate limit enroll и полного
  аудита пока нет. API и админка не предназначены для публикации в интернет.
- Реальные WireGuard/SSH forced command/sudo, Docker Compose и RDP на VM 101
  в рамках этой доработки не проверены. Windows-клиент — каркас фазы 3.
- Секреты/приватные ключи/токены в Git не хранятся; .env не коммитить.

## Реальный WireGuard

Порядок подготовки ограниченного SSH-обработчика, настройки ключа администратора и
локального запуска: [docs/WIREGUARD_INTEGRATION_RU.md](docs/WIREGUARD_INTEGRATION_RU.md).
Инструкция предназначена для отдельной согласованной проверки, не означает её
выполнение. Backend требует актуальный helper с `created`/`absence_confirmed`;
старый ответ без подтверждения отвергается, а не считается успехом.

Для сценариев отмены pending и потери ответа подготовлен отдельный
[порядок интеграционного прогона VM 101](docs/VM101_INTEGRATION_RUNBOOK_RU.md)
и локальный инструмент `admin-backend/integration/fault_backend.py`.
Он вызывает штатный SSH transport и управляет только моментом отправки/получения
add для одного тестового key/IP. В обычный backend инструмент не подключён.
Реальный прогон по этой инструкции **ещё не выполнен**.
