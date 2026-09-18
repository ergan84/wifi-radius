# custom-radius

Самописный RADIUS-сервер на Python для аутентификации Wi-Fi по протоколу
**PEAP-MSCHAPv2** с проверкой учётных данных в Active Directory через
Samba/winbind. Без сторонних RADIUS-фреймворков (FreeRADIUS и т.п.) — весь
протокол (RADIUS, EAP, PEAP/TLS-туннель, MSCHAPv2) реализован вручную на
чистом Python + pyOpenSSL.

## Возможности

- RADIUS Access-Request/Accept/Reject/Challenge с HMAC-MD5
  Message-Authenticator
- PEAP-туннель (TLS 1.2) с ручной фрагментацией/сборкой сообщений
- Внутренний EAP: Identity → MSCHAPv2 challenge/response → Result TLV
- Проверка пароля через `ntlm_auth` (Samba winbind), с опциональной
  проверкой членства в AD-группе
- Генерация MPPE-ключей (MS-MPPE-Recv/Send-Key) для WPA-Enterprise
- Поддержка нескольких сетей/IP точек доступа (`RADIUS_CLIENT_IP` принимает
  список через запятую, включая CIDR: `192.168.18.0/24,10.10.1.5`)
- Единая нормализация логина независимо от формата (`user`,
  `user@domain`, `DOMAIN\user`) — с корректной обработкой MSCHAPv2
  challenge-hash по RFC 2759
- Read-only веб-панель мониторинга (`admin_web.py`) без сторонних
  зависимостей: статус службы, таблица попыток входа (кто прошёл / кого
  отклонили), безопасное редактирование части конфигурации

## Структура репозитория

| Файл | Назначение |
|---|---|
| [custom_radius.py](custom_radius.py) | сам RADIUS-сервер |
| [admin_web.py](admin_web.py) | веб-панель мониторинга/редактирования конфига |
| [custom-radius.service](custom-radius.service) | systemd-юнит основного сервера |
| [custom-radius-admin.service](custom-radius-admin.service) | systemd-юнит веб-панели |
| [smb-radius.conf](smb-radius.conf) | пример `smb.conf` для присоединения к AD через winbind |
| [krb5-radius.conf](krb5-radius.conf) | пример `krb5.conf` |
| [gen_ios_profile.py](gen_ios_profile.py) | генератор `.mobileconfig` для iOS (CA + Wi-Fi в одном профиле, нужен только при самоподписанном сертификате) |
| `.env.example` | шаблон конфигурации (реальный `.env` в репозиторий не попадает) |

## Установка

Зависимости:

```bash
pip install pyOpenSSL
```

Сервер аутентифицирует пользователей через `ntlm_auth`, поэтому машина
должна быть присоединена к домену через Samba/winbind (см.
`smb-radius.conf`, `krb5-radius.conf`). Проверить:

```bash
wbinfo -t
wbinfo -u
```

## Конфигурация

Скопируйте шаблон и заполните реальными значениями:

```bash
cp .env.example .env
chmod 600 .env
```

Ключевые параметры:

- `RADIUS_SHARED_SECRET` — общий ключ с точкой доступа/контроллером
- `RADIUS_LISTEN_IP` — интерфейс, на котором слушает сервер (не `127.0.0.1`,
  если запросы идут от реальной точки доступа по сети)
- `RADIUS_CLIENT_IP` — кто может слать запросы: `*`, один IP, или список
  через запятую с поддержкой CIDR (`192.168.18.225,10.10.1.0/24`)
- `RADIUS_TLS_CERT_FILE` / `RADIUS_TLS_KEY_FILE` — сертификат и ключ для
  PEAP-туннеля. Если сертификат от публичного CA (Let's Encrypt, Sectigo и
  т.п.) — **обязательно включите в `RADIUS_TLS_CERT_FILE` полную цепочку**
  (лист + промежуточные), иначе многие клиенты (особенно iOS) не смогут
  проверить сертификат
- `RADIUS_SERVER_NAME` — имя, которое будет проверяться в CN/SAN
  сертификата
- `AD_ALLOWED_GROUP` — группа AD, которой разрешён доступ (`-` — разрешить
  всем успешно аутентифицированным)

## Запуск

Напрямую (для теста):

```bash
python3 custom_radius.py
```

Через systemd (продакшен):

```bash
sudo mkdir -p /opt/custom-radius /etc/custom-radius
sudo cp custom_radius.py admin_web.py /opt/custom-radius/
sudo cp .env /etc/custom-radius/radius.env
sudo useradd --system --no-create-home custom-radius
sudo usermod -aG winbindd_priv custom-radius
sudo cp custom-radius.service custom-radius-admin.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now custom-radius custom-radius-admin
```

## Веб-панель мониторинга

`admin_web.py` — read-only дашборд на стандартной библиотеке Python (без
Flask/сторонних пакетов), с HTTP Basic Auth:

```
http://<RADIUS_ADMIN_WEB_LISTEN_IP>:<RADIUS_ADMIN_WEB_PORT>/
```

Показывает:
- статус systemd-службы
- таблицу попыток входа (пользователь, время, accept/reject, причина
  отказа) — распарсено из journalctl, без сырых логов
- мини-график accept/reject по пользователям
- безопасную часть конфигурации (без паролей и ключей)

Логин/пароль задаются в `.env` (`RADIUS_ADMIN_WEB_USER`,
`RADIUS_ADMIN_WEB_PASSWORD`) — обязательно смените дефолтные значения.

Страница `/edit` позволяет менять безопасные параметры
(`RADIUS_CLIENT_IP`, `RADIUS_LISTEN_IP`, тайминги и т.д.), но **не пишет
конфиг сама** — генерирует готовые `sudo sed` + `systemctl restart` команды
для ручного применения. Это осознанное ограничение: процесс панели не имеет
прав ни на запись в защищённый `radius.env`, ни на перезапуск службы без
участия администратора.

## Тестирование без реальной точки доступа

```bash
eapol_test -c eapol-test.conf -a <IP сервера> -p 1812 -s <shared secret>
```

`eapol-test.conf` в репозиторий не попадает (в нём пароль тестового
пользователя в открытом виде) — создайте свой на основе:

```
network={
    ssid="ваш-SSID"
    key_mgmt=WPA-EAP
    eap=PEAP
    identity="test-user"
    anonymous_identity="anonymous"
    password="пароль"
    ca_cert="/etc/ssl/certs/ca-certificates.crt"
    phase2="auth=MSCHAPV2"
}
```

## Профиль для iOS (только для самоподписанного CA)

Если используется собственный (не публичный) CA, установка отдельного
сертификата на iPhone требует ручного включения доверия в настройках —
это неудобно и часто забывается. `gen_ios_profile.py` собирает единый
`.mobileconfig` с CA-сертификатом и настройками Wi-Fi в одном файле:

```bash
python3 gen_ios_profile.py "SSID-сети"
```

При использовании сертификата от публичного CA этот профиль не нужен —
устройства доверяют сертификату автоматически.

## Безопасность

- `.env`, приватные ключи (`*.key`) и каталог `certs/` исключены из
  репозитория через `.gitignore` — никогда не коммитьте их
- Веб-панель никогда не показывает пароли, `RADIUS_SHARED_SECRET` или
  содержимое приватных ключей
- Рекомендуется держать `RADIUS_ADMIN_WEB_LISTEN_IP=127.0.0.1` и открывать
  доступ к панели только через SSH-туннель, если не установлен HTTPS
  перед ней
