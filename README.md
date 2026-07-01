# mtls_ob_test — OceanBase mTLS monitoring agent (prototype)

Агент ставится на хост с OceanBase. К базе ходит по mTLS, наружу отдаёт метрики.
Оба сервера — **HTTPS + mTLS + IP-allowlist + CN-allowlist**. Клиентский серт к
базе живёт **только в памяти** и заливается в рантайме — на диске секретов нет.

> Прототип / spike. Консольный вывод — на английском. Ограничения — в конце.

---

## Модель безопасности (коротко)

- **На диске нет секретов.** Клиентский серт+ключ к базе — только в памяти.
  На диске рядом — лишь публичный `ca.pem` и конфиг.
- **Холодный старт.** Агент поднимается «пустым» (фаза `NoCert`) и ждёт заливки
  серта через mgmt-эндпоинт. Рестарт = снова пусто, красть нечего.
- **Оба сервера mTLS.** Клиент обязан предъявить серт из нашего CA; проверяется
  цепочка **и** CN (белый список на каждый сервер). Плюс IP-allowlist.
- **Доступ к базе — под read-only пользователем**, привязанным к subject серта.
- **Чистый Rust** (`rustls`/`ring`, без системного OpenSSL): один бинарь,
  зависит только от glibc — переносим на любой RHEL 9 / Rocky / Alma / Oracle 9.

---

## Архитектура

Два сервера в одном процессе, оба HTTPS+mTLS:

| Сервер | Порт | Эндпоинты |
|--------|------|-----------|
| **data** | `8443` | `GET /version`, `GET /health` |
| **mgmt** | `9443` | `POST /cert` (multipart cert+key), `GET /cert/validity` |

Серверный серт обоих — **встроенный самоподписанный** (зашит в бинарь,
`embedded/mgmt-*.pem`). Это идентичность канала, не секрет.

До заливки серта `/version` и `/cert/validity` отвечают `503 {"error":"nocert"}`,
`/health` — `ok`.

---

## Сборка

```bash
cargo build --release          # бинарь: target/release/mtls_ob_test
```

Linux-бинарь также публикуется в Releases (тег `latest_release`) через GitHub
Actions (`.github/workflows/build-and-release.yml`, ручной запуск).

---

## Конфиг (`agent.toml`)

```toml
[network]
# Общий белый список IP/CIDR (если у сервера ниже нет своего allow_ips).
# Пустой список = пускать с любых адресов.
allow_ips = ["192.168.55.0/24"]

[data]
listen   = "0.0.0.0:8443"
allow_cn = ["ob-monitor", "ob-control"]   # чьи client-cert читают метрики
# allow_ips = ["192.168.55.0/24"]         # опциональный per-server список

[mgmt]
listen   = "0.0.0.0:9443"
allow_cn = ["ob-control"]                 # кто может заливать серт
# allow_ips = ["192.168.55.11/32"]        # mgmt можно сузить до управляющих серверов

[oceanbase]
host = "192.168.55.202"
port = 2881
user = "test_mtls"
ca   = "./ca.pem"
```

Путь к конфигу — env `CONFIG` (по умолчанию `./agent.toml`). Пути в конфиге
относительны каталогу запуска.

---

## Запуск на новом сервере

### Шаг 1. Выпустить клиентскую пару из своего CA

Нужны: `ca.pem` (корневой CA), `client-cert.pem` + `client-key.pem` (как
выпускать — вне рамок README). CN серта должен попасть в `allow_cn`.

### Шаг 2. Завести пользователя в OceanBase под subject серта

OceanBase в `REQUIRE SUBJECT` ждёт **весь subject** в слэш-формате:

```bash
openssl x509 -in client-cert.pem -noout -subject -nameopt compat
# subject=/C=SU/O=lab/OU=Database/CN=obcluster200
```

```sql
CREATE USER 'test_mtls'@'192.168.55.%'
  REQUIRE SUBJECT '/C=SU/O=lab/OU=Database/CN=obcluster200';
GRANT SELECT ON oceanbase.* TO 'test_mtls'@'192.168.55.%';
```

> **Важно:** host-маска юзера должна покрывать IP, с которого агент коннектится
> к OB (адрес хоста агента, не localhost). Иначе self-check заливки упадёт
> с `new cert failed to authenticate against OceanBase`.

### Шаг 3. Запустить

Три файла в одном каталоге — бинарь, `agent.toml`, `ca.pem` — запуск оттуда:

```bash
mkdir -p ~/ob-agent && cd ~/ob-agent
cp /path/to/mtls_ob_test .
cp /path/to/agent.toml .
cp /path/to/ca.pem .
./mtls_ob_test
```

Firewall (если ходишь с другой машины):

```bash
firewall-cmd --permanent --add-port=8443/tcp
firewall-cmd --permanent --add-port=9443/tcp
firewall-cmd --reload
```

---

## Тестовые команды

Клиентский серт (`--cert/--key`) обязателен на обоих серверах — это mTLS.
`-k` отключает проверку самоподписанного серта сервера (для теста; в проде —
`--cacert` или пиннинг, см. ниже).

```bash
CRT=~/certpas/client-cert.pem
KEY=~/certpas/client-key.pem
H=192.168.55.190

# 1. фаза NoCert
curl -sk --cert $CRT --key $KEY https://$H:8443/version         # {"error":"nocert"} (503)

# 2. залить серт к OB (mgmt; CN серта должен быть в [mgmt].allow_cn)
curl -sk --cert $CRT --key $KEY https://$H:9443/cert \
  -F cert=@$CRT -F key=@$KEY
# {"ok":true,"cn":"...","not_before":"...","not_after":"...","note":"..."}

# 3. метрики (data)
curl -sk --cert $CRT --key $KEY https://$H:8443/version         # {"version":"5.7.25-OceanBase_CE_CL-..."}
curl -sk --cert $CRT --key $KEY https://$H:9443/cert/validity   # CN + срок текущего серта
curl -sk --cert $CRT --key $KEY https://$H:8443/health          # ok
```

### Негативные тесты (доказывают, что фильтры режут)

```bash
# без client-cert -> mTLS обязателен, handshake отлетает (не JSON, а ошибка TLS)
curl -sk https://$H:9443/cert/validity

# серт с CN не из allow_cn -> в консоли агента: TLS: client CN='...' REJECTED
# (временно убери его CN из agent.toml -> [mgmt].allow_cn, перезапусти)

# запрос с IP вне allow_ips -> 403 {"error":"ip_not_allowed"}
```

### Диагностика в консоли агента

Каждый handshake и запрос логируются:

```
[mgmt] TLS: client CN='obcluster200' accepted
[mgmt] POST /cert from 192.168.55.190 -> 200
[data] TLS: client CN='ob-monitor' REJECTED (not in allow_cn)
[data] GET /version from 10.0.0.5 -> 403 ip_not_allowed
```

### `-k` vs проверка сервера (для прода)

```bash
# отпечаток встроенного серта
openssl x509 -in embedded/mgmt-cert.pem -noout -fingerprint -sha256

# вместо -k: доверять только этому серту (пиннинг)
curl --cacert mgmt-cert.pem --cert $CRT --key $KEY https://$H:9443/cert/validity
```

---

## Ограничения (честно)

- **Личность заливающего = client-cert + CN + IP.** Заливать может только
  держатель серта из нашего CA с CN из `[mgmt].allow_cn` и с разрешённого IP.
  Криптопривязки «именно этот хост» нет — это обеспечивается средой
  (IP из UCMDB, закрытый хост, зарезервированный порт).
- **Защита серта в рантайме — права ОС.** Серт в памяти; кто может ptrace-нуть
  процесс (тот же uid / root), тот его прочитает. Запускать под отдельным
  непривилегированным сервис-юзером (`systemd User=...`), закрыть ptrace чужим.
- **Встроенный серт одинаков во всех бинарях** и извлекается — пиннинг ловит
  чужой серт, но не подмену этим же встроенным. Реальный барьер — среда (выше).
- **Только Linux** (glibc). musl-статика — опционально через контейнерную сборку.
- **Заливка серта в память переживает только до рестарта** — по дизайну.

---

## Структура

```
src/
  main.rs         — бутстрап, поднимает оба сервера
  config.rs       — конфиг из TOML
  state.rs        — разделяемое состояние + горячая замена серта
  credentials.rs  — Identity (cert/key/ca в памяти)
  db.rs           — пул к OceanBase поверх mTLS, запросы
  api.rs          — data-сервер: /version, /health
  mgmt.rs         — mgmt-сервер: POST /cert, GET /cert/validity
  acl.rs          — CN-verifier (TLS) + IP-allowlist + логирование запросов
  tls.rs          — сборка rustls ServerConfig (серт + client verifier)
  certinfo.rs     — разбор сертификата (CN, срок действия)
  error.rs        — единый тип ошибки API
embedded/
  mgmt-cert.pem   — встроенный серт mgmt/data-серверов
  mgmt-key.pem    — встроенный ключ
```
