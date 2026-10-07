# Исправления review PR #1 — 2026-10-06

Репозиторий: alexkharavantime/avantime-connect. Ветка: feature/phase-1-2.
Исходный head: `7c331b615ebeca4aecf00cca525a46d22494f4ec`.
PR: https://github.com/alexkharavantime/avantime-connect/pull/1

## Подтверждённые причины дефектов

1. Revoke принимал только active/revoking, поэтому peer с потерянным add-ответом
   оставался доступен при записи pending. Helper запрещал отмену ещё не созданного
   peer. Безусловные update_one состояния позволяли позднему enroll записать active
   поверх отмены, а конкурентному revoke — вернуть revoked в revoking.
2. Любой used-токен возвращал 409. Снимка ответа не было: повтор после потери HTTP
   не мог получить прежние параметры, а сбой между active и used не был закрыт.
3. UsersPage подавлял ошибку listUsers через пустой catch.
4. Find-before-insert логина не исключал DuplicateKeyError при конкуренции.
5. README содержал устаревшие заявления об SSH-заглушке, отсутствии авторизации
   и поддержке Node 18.

## Изменённые файлы

| Файл | Изменение |
|---|---|
| admin-backend/app/routers/enroll.py | Восстановление результата, атомарный снимок, условная активация, компенсация отмены |
| admin-backend/app/routers/devices.py | Отзыв pending/active, повтор revoking/revoked, исключение enrolled_token из списка |
| admin-backend/app/services/device_lifecycle.py | Общее подтверждение удаления и условная финализация revoked |
| admin-backend/app/services/wireguard.py | Проверка created/absence_confirmed в ответе helper |
| deploy/wireguard/helper.py | Идемпотентная отмена отсутствующего peer, защитная запись, подтверждение удаления |
| admin-backend/app/config.py | Положительный ENROLL_RECOVERY_TTL в секундах, default 86400 |
| admin-backend/app/models/__init__.py | Модель EnrollSnapshot |
| admin-backend/app/db/mongo.py | Уникальный sparse-индекс enrolled_token; остальные индексы сохранены |
| admin-backend/app/routers/users.py | DuplicateKeyError при insert превращается в 409 |
| admin-frontend/src/pages/DevicesPage.tsx | Отзыв pending, повтор revoking, ошибка сохраняется после обновления списка |
| admin-frontend/src/pages/UsersPage.tsx | Loading/error/empty различаются, кнопка повтора |
| admin-frontend/package.json, package-lock.json | Node engines, typecheck, Vitest/jsdom/Testing Library только для разработки |
| admin-frontend/vitest.config.ts, tests/admin.test.tsx | Четыре компонентных UI-регрессии с подменой HTTP |
| admin-backend/tests/conftest.py | Изолированная MongoDB, реальная логика helper с подменой SSH/системных команд |
| admin-backend/tests/test_enrollment_recovery.py | Сценарии потери ответов, гонок, TTL, snapshot, конфликта логина |
| admin-backend/tests/test_api.py, test_wg_flow.py, test_wg_transport.py | Новый контракт повторов и подтверждения helper |
| tests/test_wg_helper.py | Отмена отсутствующего peer, tombstone, чужие peers, потеря ответа и проверки удаления |
| README.md, docs/WIREGUARD_INTEGRATION_RU.md, docs/security.md, этот отчёт | Актуальные режимы, ограничения, инструкции и фактические проверки |

## Конкурентные enroll/revoke

Все изменения state существующего устройства выполняются через find_one_and_update:

- pending/active → revoking: фильтр `_id` и `state: {$in: [pending, active]}`.
- pending → active: фильтр `_id` и `state: pending`; тем же апдейтом записан снимок.
- revoking → revoked: фильтр `_id` и `state: revoking`; только после успешного
  подтверждения helper, с revoked_at. Повторы не перезаписывают это время.

Если успешный add-ответ опоздал и отмена уже победила, enroll вызывает remove для
того же owner/key/IP и отвечает ошибкой. Неподтверждённая компенсация оставляет
revoking для повторного отзыва. Если другой запрос той же регистрации уже записал
active после истечения lease, поздний ответ не удаляет его peer и получает тот же
снимок; этот отдельный случай проверен тестом.

Helper сериализует операции через flock. Отмена ещё не созданного peer записывает
owned tombstone, поэтому поздний add запрещён. Чужой существующий peer без записи
managed.json и несовпадающий owner/IP остаются защищены. remove проверяет отсутствие
в runtime и wg0.conf, затем наличие сохранённой записи revoked в managed.json.
Tombstone не удаляется; IP остаётся зарезервирован. Нового освобождения IP нет.

## Восстановление enroll

Тройка token/public_key/device_name должна совпадать. В active возвращается снимок
в пределах `now - completed_at <= ENROLL_RECOVERY_TTL`, default **86400 секунд**.
Запрос не создаёт peer/IP, не пересчитывает профиль и не продлевает срок. Изменение
настроек, пользователя, истечение приглашения или disabled-транспорт не изменяют
снимок. Сбой после active, но до used, закрывается повтором без новой VPN-операции.

Другой key/device — 409. Истёкший recovery TTL — 410. Для завершённой регистрации
revoking/revoked — 410; для отменённого pending — отказ 409. У старых used-записей без
снимка восстановление невозможно (409). Новое истёкшее приглашение не продлевается.

## Фактические результаты

Среда: Python 3.12.14, MongoDB **7.0.16**, Node.js **24.19.0**, Vite 7.3.6.
MongoDB — отдельный локальный процесс на 127.0.0.1:27018 с собственной директорией
данных, БД avantime_connect_test. Рабочие БД и VM 101 не использовались.

| Проверка | Результат |
|---|---|
| Backend: `python -m pytest -q` из admin-backend | **45 passed**, 2026-10-06 |
| Helper: `python -m pytest -q tests` из корня | **27 passed**, 2026-10-07 |
| UI: `npm run test:ui` | **4 passed**, 2026-10-06, Vitest + jsdom, HTTP подменён |
| TypeScript: `npm run typecheck` | Успешно |
| Production build: `npm run build` | Успешно, 30 модулей |
| Python: compileall затронутых app/tests/helper | Успешно |
| Shell: `bash -n deploy/wireguard/install-server.sh` | Успешно; скрипт не менялся и не исполнялся |
| `git diff --check` | Без ошибок |

Проверены: потеря add/remove/HTTP-ответа; pending с peer и без него; поздние add и
add-ответ; неудачная компенсация и повтор; конкурентные revoke и создание логина;
снимок при изменении настроек; другая пара key/device; истечение и точная граница
TTL; запрет recovery после отзыва; защита чужих peers, резервов и tombstone.

Браузерный запуск **не выполнен**: загрузчик Chromium получил HTML (195 байт)
вместо ZIP-архива. Компонентные UI-проверки выполнены вместо него и не названы
браузерной проверкой. Playwright не добавлен в итоговые зависимости.

Реальные WireGuard, SSH forced command/sudo, VM 101, установка helper, Docker Compose,
tunnel handshake и RDP **не проверялись**. Mock-проверки не подтверждают их работу.
Сети, NAT/firewall, адреса, local bind и Windows-клиент не менялись.

## Условия дальнейшей проверки

Backend требует новый helper-контракт с created/absence_confirmed. Старый helper
будет отвергнут как неподтверждённый результат; согласованное обновление требуется
перед отдельной реальной проверкой. В рамках этой задачи сервер не обновлялся.
IP отозванных устройств не освобождаются, пул может исчерпаться.

PR должен оставаться draft, без merge. Итоговый SHA и подтверждение push приведены
в итоговом сообщении агента; SHA коммита с этим отчётом можно получить командой
`git log -1 --format=%H -- docs/PR1_REVIEW_FIXES.md`.

## Дополнение по финальному review — 2026-10-07

База дополнения: `291f246bb1a50e9fac050f5a7b8447aaac378bca`.
Повтор удаления уже удалённого peer покрыт существующим тестом
`test_add_remove_idempotent_and_persistent`; отмена никогда не созданного peer —
`test_cancel_absent_peer_preserves_tombstone_and_blocks_late_add`.

Добавлен `test_interruption_after_journal_before_any_mutation_retries` с двумя
вариантами: add и remove. Прерывание происходит сразу после успешной записи
pending_add/pending_remove в managed.json, до изменения wg0.conf и runtime.
Тест проверяет неизменность обоих состояний при прерывании, сохранение owner/IP
в журнале и завершение повторного запроса с тем же owner/IP без изменения чужого peer.
Это отдельная точка отказа: прежние тесты прерывали операцию уже после изменения
конфигурации, перед runtime-командой или после её применения.

В WIREGUARD_INTEGRATION_RU.md явно уточнено: сторонние изменения управляемых peers
в managed.json, wg0.conf и runtime в обход helper/flock не поддерживаются и могут
вернуть отозванный доступ даже между запросами. Детект изменения конфигурации
не заменяет эту эксплуатационную границу.

Изменены только tests/test_wg_helper.py и два документа. Повторно выполнены все
helper-тесты (**27 passed**), py_compile изменённого теста и git diff --check.
Backend/UI/build повторно не запускались; их результаты выше относятся к 2026-10-06.
VM 101 не использовалась; согласованное обновление backend/helper и реальная
интеграционная проверка остаются условиями снятия draft.
