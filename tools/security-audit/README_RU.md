# Аудит безопасности серверов Avantime

Цель: убедиться, что снаружи никто не может попасть на серверы Avantime.
Домен AD: `ad.avantime.lv` (NetBIOS `AVANTIME`).

## Скрипт `Security-Audit-EN.ps1`

Только читает настройки, ничего не меняет. Все строки на латинице, поэтому
кодировка файла не важна (Windows PowerShell 5.1 читает UTF-8 без BOM как ANSI,
из-за этого русская версия ломалась).

Проверяет: обновления и ожидающую перезагрузку, файрвол, слушающие порты
(RDP, SMB, SQL, 1С 1540/1541/1545/1560–1591, WinRM), NLA и шифрование RDP,
локальные учётки и администраторов, политику паролей и блокировки, неудачные
входы за 24 ч и RDP-входы за 7 дней, Defender, SMBv1, общие папки с записью для
Everyone, учётки служб 1С/SQL, задачи планировщика не от Microsoft.

Отчёт: `C:\SecurityAudit\<HOST>_<дата>.txt`.

### Запуск

1. Скачать **оригинальный** `.ps1` (не копировать через текстовый редактор:
   файл может сохраниться как RTF) в `C:\Security_Audit\`.
2. PowerShell **от имени администратора** на проверяемом сервере:

```
Unblock-File C:\Security_Audit\Security-Audit-EN.ps1
```
```
Set-ExecutionPolicy -Scope Process Bypass -Force; & C:\Security_Audit\Security-Audit-EN.ps1
```

`-Scope Process` снимает запрет на скрипты только для текущего окна.
Команды копировать, а не набирать (были опечатки вида `Security-Audut`).

Скрипт не видит, что открыто из интернета: внешний периметр проверяется отдельно
(см. ниже).

## Серверы

| Сервер | Адрес | Статус |
|---|---|---|
| WIN-APP-DEV | 10.20.0.20 | Проверен 20.10.2026, частично исправлен |
| DEV-ADMIN | — | Windows 11 Pro; удалён из AD (см. открытые вопросы) |
| PROD-ADMIN | 10.40.0.30 | Windows 11 Pro; проверен и исправлен 31.10.2026 (0 критично, 4 предупреждения о портах) |
| web-avg | 10.40.0.50 | Не проверен |
| AVG-DC01 (контроллер домена) | 10.20.0.10 | Windows Server 2022; проверен 31.10.2026 |
| AVG-DC-PROD (контроллер домена) | 10.40.0.10 | Windows Server 2022 **build 20348.169 — тоже не обновлялся с 2021**; Print Spooler отключён 31.10.2026; аудит не запускался |

## Результаты WIN-APP-DEV (20.10.2026 15:14): 1 критично, 18 предупреждений

Windows Server 2025 Standard **Evaluation**, сервер 1С 8.3, служба от `.\USR1CV8`.

| Статус | Проверка | Что найдено |
|---|---|---|
| КРИТИЧНО | Пароли | Блокировка после неудачных попыток выключена, локально и в домене — **исправлено** |
| ВНИМАНИЕ | Пароли | Минимальная длина пароля 7 — **исправлено** (12) |
| ВНИМАНИЕ | SMB | `Incoming` (D:\Incoming), `Install` (D:\Install), `Testing` (D:\Testing): запись для Everyone |
| ВНИМАНИЕ | Учётки | Встроенный `Administrator` включён, не переименован, пароль бессрочный |
| ВНИМАНИЕ | RDP | MinEncryptionLevel = 2 (нужно 3) |
| ВНИМАНИЕ | Порты | 135, 139, 445, 1540, 1541, 1561–1564, 1576 (java), 3389, 5985 — нормально для внутреннего сервера, если не проброшены наружу |
| ИНФО | Учётки | Админы: AVANTIME\Domain Admins, AVANTIME\GG-DEV-Local-Admins, Administrator. У USR1CV8 бессрочный пароль |
| ОК | — | Обновления 4 дня назад, файрвол во всех профилях, NLA, Defender (сигнатуры 1 день), SMBv1 выключен, неудачных входов нет, 1С не от LocalSystem |

## Результаты PROD-ADMIN (31.10.2026 14:33): 1 критично, 6 предупреждений

Windows 11 Pro build 26200, в домене. Политика домена применилась (блокировка 10, длина 12).

| Статус | Проверка | Что найдено |
|---|---|---|
| КРИТИЧНО | Учётки | Локальный админ `AvantimeAdmin`: флаг «пароль не требуется» (PasswordRequired = False), пароль бессрочный |
| ВНИМАНИЕ | SMB | `Incoming` (D:\Incoming): запись для Everyone |
| ВНИМАНИЕ | RDP | MinEncryptionLevel = 2 (нужно 3) |
| ВНИМАНИЕ | Порты | 135, 139, 445, 3389 — нормально внутри сети, если не проброшены наружу |
| ВНИМАНИЕ | Порты | 22 (OpenSSH Server, sshd) на 0.0.0.0 — скрипт не помечает; выяснить, нужен ли, и как настроен вход |
| ИНФО | Учётки | Админы: AVANTIME\Domain Admins, AVANTIME\GG-DEV-Local-Admins, Administrator (отключён), AvantimeAdmin. У локального `alexkhar` пароль бессрочный |
| ИНФО | Задачи | `\Avantime-Archive-PROD` запускает `Run-Prod-Archive.ps1` из профиля AvantimeAdmin; при смене пароля AvantimeAdmin проверить, от чьего имени работает задача |
| ОК | — | Обновления сегодня, файрвол во всех профилях, NLA, Defender (сигнатуры 0 дней), SMBv1 выключен, неудачных входов нет |

**Исправлено на PROD-ADMIN 31.10.2026** (повторный аудит 14:48: 0 критично, 4 предупреждения
о портах 135/139/445/3389):
- `net user AvantimeAdmin /passwordreq:yes`. Пароль не менялся; задача
  `Avantime-Archive-PROD` (запуск от AvantimeAdmin, сохранённый пароль) работает, LastTaskResult 0.
- OpenSSH Server остановлен и отключён (`Stop-Service sshd; Set-Service sshd -StartupType Disabled`).
  Последний вход по SSH: 01.10.2026, avantimeadmin по паролю с 10.20.0.2 (VPN-шлюз).
  Правило файрвола было только для Private, сеть DomainAuthenticated.
- RDP MinEncryptionLevel = 3.
- Share `Incoming`: Everyone (Full) удалён, добавлен AVANTIME\Domain Users (Change).

## Результаты AVG-DC01 (31.10.2026 14:56): 1 критично, 7 предупреждений

Windows Server 2022 Standard build 20348, аптайм 39 дней. На контроллере домена
`Get-LocalUser` возвращает **доменные** учётки, поэтому раздел Accounts в отчёте
относится ко всему домену, а список локальных админов пуст.

| Статус | Проверка | Что найдено |
|---|---|---|
| КРИТИЧНО | Обновления | **Подтверждено**: build 20348.169 (RTM, август 2021), последние KB5005552/KB5005039/KB5004330 от 07.08.2021. GPO AUOptions=3 (скачивать, ставить вручную) — никто не ставил. Не закрыты noPac (CVE-2021-42278/42287: любой пользователь домена → Domain Admin), PrintNightmare и др. |
| ВНИМАНИЕ | Учётки | Доменный `Administrator` включён, пароль бессрочный |
| ВНИМАНИЕ | RDP | MinEncryptionLevel = 2 (нужно 3) |
| ВНИМАНИЕ | Порты | 135, 139, 445, 3389, 5985 (WinRM) — нормально внутри сети, если не проброшены наружу |
| ИНФО | Учётки | Почти у всех доменных пользователей (~75) пароль бессрочный; политика MaxPasswordAge 42 дня на них не действует |
| ИНФО | Учётки | DEV-ADMIN: в AD есть действующий объект и один удалённый — машину удаляли и ввели в домен заново. Вопрос закрыт |
| ВНИМАНИЕ | Учётки | ~60 учёток с паролем, заданным одновременно 07.10.2026 22:58 (массовое создание/сброс); около половины ни разу не входили |
| ВНИМАНИЕ | Учётки | Domain Admins: **только** `Administrator`; он же активно используется (пароль 19.09.2026, вход 23.10.2026). Нужна вторая персональная админ-учётка, прежде чем трогать Administrator |
| ИНФО | AD | Два DC: AVG-DC01 (10.20.0.10) и AVG-DC-PROD (10.40.0.10), оба Server 2022; репликация без ошибок (repadmin 31.10.2026) |
| ВНИМАНИЕ | Службы | Print Spooler на DC (вектор PrintNightmare) — **исправлено 31.10.2026**: остановлен и отключён |
| ОК | — | Файрвол во всех профилях, NLA, Defender (сигнатуры 1 день), SMBv1 выключен, неудачных входов нет, политика блокировки 10 / длина 12 |

## Сделано

1. Локальная политика на WIN-APP-DEV (блокировка 10 попыток / 15 минут, длина 12).
   Командная строка или PowerShell от администратора на WIN-APP-DEV:
```
net accounts /lockoutthreshold:10 /lockoutwindow:15 /lockoutduration:15 /minpwlen:12
```
2. Политика домена, PowerShell на контроллере домена. Проверено через
   `Get-ADDefaultDomainPasswordPolicy`: LockoutThreshold 10, Duration и
   ObservationWindow 00:15:00, MinPasswordLength 12, Complexity True,
   MaxPasswordAge 42 дня, история 24.
```
Set-ADDefaultDomainPasswordPolicy -Identity ad.avantime.lv -LockoutThreshold 10 -LockoutDuration 00:15:00 -LockoutObservationWindow 00:15:00 -MinPasswordLength 12
```

## Открытые задачи

1. **DEV-ADMIN удалён из AD** (`Remove-ADComputer -Identity DEV-ADMIN` на
   контроллере домена). Не подтверждено, было ли это намеренно. Если нет —
   восстановить из корзины AD (PowerShell на контроллере домена) или заново
   ввести машину в домен под локальным администратором DEV-ADMIN:
```
Get-ADObject -Filter 'Name -like "DEV-ADMIN*"' -IncludeDeletedObjects | Restore-ADObject
```
2. **Общие папки на WIN-APP-DEV**: сначала выяснить, кто в них пишет, затем
   заменить Everyone на Domain Users. PowerShell от администратора на WIN-APP-DEV:
```
foreach ($n in 'Incoming','Install','Testing') { Grant-SmbShareAccess -Name $n -AccountName 'AVANTIME\Domain Users' -AccessRight Change -Force; Revoke-SmbShareAccess -Name $n -AccountName 'Everyone' -Force }
```
3. **Встроенный Administrator на WIN-APP-DEV**: сначала убедиться, что вход
   доменной учёткой работает. PowerShell от администратора на WIN-APP-DEV:
```
Disable-LocalUser -Name Administrator
```
4. **Шифрование RDP High**, PowerShell от администратора на WIN-APP-DEV:
```
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name MinEncryptionLevel -Value 3
```
5. **Что за java на порту 1576**, PowerShell на WIN-APP-DEV:
```
Get-Process -Id (Get-NetTCPConnection -LocalPort 1576 -State Listen).OwningProcess | Select Name,Path
```
6. **Лицензия**: WIN-APP-DEV на Evaluation; после окончания пробного периода
   сервер будет перезагружаться каждый час.
7. **Аудит остальных**: запустить скрипт на ProdAdmin, web-avg и контроллере
   домена; повторно на WIN-APP-DEV после исправлений.
8. **Внешний периметр**: проверить проброс портов на роутере/файрволе на 10.20.x
   и 10.40.x; просканировать внешний IP с машины **вне офиса**:
```
nmap -Pn -p 1-65535 ВНЕШНИЙ_IP
```
   Снаружи не должно быть 3389, 1540/1541/1545/1560–1591, 1433, 445, 5985/5986.
   RDP — только через VPN или RD Gateway. Уточнить, какой VPN реально
   используется снаружи (в сводке упоминался OpenVPN, Avantime Connect — WireGuard).
9. **Блокировки в первые дни**, PowerShell на контроллере домена:
```
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4740} -MaxEvents 20 | Select TimeCreated,@{n='User';e={$_.Properties[0].Value}},@{n='From';e={$_.Properties[1].Value}}
```
10. **1С и SQL** (вручную): администратор кластера 1С с паролем; в базах нет
    пользователей без пароля; `sa` в SQL отключена или со сложным паролем;
    бэкапы вне сервера, и у сервера нет к ним доступа на запись.
