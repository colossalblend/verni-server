# verni-server — свой сервер для Verni-Desktop

Полная замена verniapp.ru:18766. Раз в прошлом была только точка входа у овнеров,
теперь точка входа — твоя машина.

```
iPhone (Verni-Desktop)                Windows-ПК
 ┌──────────────────┐   HTTPS/JSON    ┌───────────────────────────┐
 │ + VERNI1 ключ    │ ───────────────►│ server.py (uvicorn:18766) │
 │ после импорта    │                 │ auth + sessions + bridge  │
 └──────────────────┘                 └────────────┬──────────────┘
                                                   │ TCP:27987, framed
                                                   ▼
                                      ┌───────────────────────────┐
                                      │ iOSAuthSingle.exe (x86)   │
                                      │  └ iOSAuthRuntime.dll     │
                                      │     └ iTunes.dll (32-bit) │
                                      │        └ SC Info.sidb/sidd│
                                      │  DSID твоего Apple ID     │
                                      └───────────────────────────┘
```

## Что будет на телефоне и в iTunes

Verni-Desktop после `result` командой `exchange` гонит FairPlay-запрос по
`com.apple.atc` → серверу. Сервер обрабатывает через iTunes и вернёт
`Grappa → afsync.rs + afsync.rs.sig`. На телефоне появится `<DSID>` в
authoriation store, App-Store подпись появится для установок ipa.

## Безопасность сервера

Что enforced на сервере (не клиенте):

* **Токены**: `VERNI_TOKENS="tok1,tok2"` — по токену на телефон; сессии,
  привязка UDID и слот `begin` изолированы по токену. Один `VERNI_TOKEN`
  тоже работает (back-compat). Проверка `secrets.compare_digest`.
* **Сессии**: `complete`/`abort` работают только со своей сессией — чужой
  `session_id` даёт `404 unknown_session` (IDOR/BOLA закрыт; abort чужой
  сессии — безопасный no-op без раскрытия существования).
* **Rate limiting**: 120 req/мин на IP (sliding window, `VERNI_RATE_LIMIT`),
  429 `owner_generator_busy`; IP с 10 неудачными авторизациями за 10 мин
  блокируется на окно (`VERNI_AUTH_FAIL_LIMIT/WINDOW`).
* **Валидация**: строгая типизация полей (bool не проходит за int), лимит
  тела 2 MB, лимиты размеров cert/rq/deviceGrappa, base64 strict, deny по
  умолчанию. Резервация слота до обращения к воркеру — гонка begin'ов
  одного токена даёт мгновенный 409, двойных сессий нет.
* **Конфиг**: `VERNI_MAX_SESSIONS=64`, `VERNI_WEBHOOK_URL` — POST JSON при
  отказе/восстановлении FairPlay-интеграции (без секретов, дедуп 15–30 мин).
* **Здоровье интеграции**: `GET /v1/health` (токен) — состояние воркера
  (UNKNOWN/HEALTHY/DEGRADED/RECOVERING/FAILED), последние ошибки, метрики.
  Мёртвый воркер автоматически respawn'ится (backoff+jitter, single-flight);
  проблемы iTunes-стороны (SC Info/авторизация) автоматически не чинятся —
  только уведомление админу. CAPTCHA/2FA не обходятся никогда.
* **Логи**: JSON-строки в `srvlog.txt` (5 MB × 3 ротация) + консоль:
  ts, event, rid, ip, path, status, ms. Токены и тела запросов не пишутся.
* **Файлы**: `setup.ps1` ужимает ACL на `.env.server`/`key.pem`/
  `verni-key.txt` (SYSTEM + Administrators + текущий юзер); JSON-стейт
  пишется атомарно (tmp + os.replace).

Проверяется батареей `test_security.py` (34 проверки: auth, IDOR, replay,
race begin, rate limit, lockout, отсутствие утечки токена в логах) + SCA
`pip-audit` в CI (job `sca`).

## Быстрая установка на сервер (минимум движений)

На чистой Windows-машине (VPS или этот ПК):

```powershell
git clone https://github.com/colossalblend/verni-server
cd verni-server
powershell -ExecutionPolicy Bypass -File setup.ps1 -ServerHost <IP-или-DNS> [-Task]
```

`setup.ps1` сам: ставит Python и зависимости, генерит cert/key/token и
`verni-key.txt`, качает последний воркер из GitHub Actions, кладёт `dsid.txt`
рядом с exe, открывает порт 18766 в фаерволе. С `-Task` регистрирует
автозапуск через Планировщик (SYSTEM, при загрузке).

Остаются только Apple-шаги, которые автоматизировать нельзя:

```powershell
.\install_itunes.ps1        # скачать + тихо установить iTunes 12.10.11 32-bit
```

1. Открой iTunes один раз, войди под своим Apple ID, `Store → Authorize This
   Computer` (появятся `SC Info.sidb/sidd`).
2. `accounts.json` — реальные email + `dsid` по каждому аккаунту: на машине с
   браузером запусти `python get_dsid.py edge --account you@example.com`
   (после входа скрипт сам пропишет аккаунт в `accounts.json`), затем перенеси
   `accounts.json` на сервер.
3. Старт: `.\run_server.ps1` — воркер поднимается сам (сервер spawns
   `iOSAuthSingle.exe`, если порт закрыт). Перезапуск при падении — тоже сам.

Ключ для телефона: `verni-key.txt` (импорт через Verni-Desktop). Логи:
`.\srvlog.txt` не нужен — uvicorn пишет в консоль задачи Планировщика
(или запусти вручную и смотри вывод).

### Автонастройка аккаунта из логина+пароля

Всё то же самое одной командой (в RDP-сессии сервера):

```powershell
python setup_account.py --email you@example.com
# пароль спросит скрыто; либо: --password-stdin < pw.txt, либо env VERNI_APPLE_PASSWORD
```

Скрипт сам: логинится в Edge на icloud.com (2FA ты подтверждаешь в окне или
вставляешь код в консоль — Apple-защиты не обходятся), вытаскивает DSID,
прописывает его в `accounts.json` и `dsid.txt` (включая каталог воркера),
ставит iTunes 12.10.11 при необходимости, запускает его первый раз и ждёт
появления `SC Info.sidb/sidd`. Если после первого запуска SC Info не
появились — останется ровно один ручной шаг (войти в аккаунт + `Store →
Authorize This Computer` в окне iTunes), скрипт дождётся файлов сам.
`--skip-browser` — только iTunes; `--skip-itunes` — только браузер+DSID.
Пароль нигде не печатается и не логируется. RDP-сессию не закрывай
(disconnect вместо log off).

## Шаг 0 — требования

* Windows 10/11 x64 (не ARM) — сам server.py безразличен к битности, но
  **iOSAuthSingle собирается только под Win32 (x86)** и грузит **32-битный**
  iTunes.dll (32-битный процесс не может загрузить x64 DLL).
* iTunes classique **32-bit** (последний x86-билд: **iTunes 12.10.11** с сайта
  Apple — «64-bit» вариант НЕ подходит воркеру), установленный и запущенный
  **хотя бы раз** после регистрации под своим Apple ID. Плюс `Apple
  Application Support (x86)` и `Apple Mobile Device Support` — их ставит
  установщик iTunes сам.
* Python 3.10+ (серверная часть и `get_dsid.py`) — `pip install -r requirements.txt`.
* Visual Studio 2019/2022 (если собирать iOSAuthRuntime самому).

## Шаг 1 — iTunes + авторизация Apple ID

1. Установи **iTunes 12.10.11 (32-bit)** — классический проводный setup
   (`.exe` оффлайн-инсталлятор), Store-версия не подойдёт: у ней нет ни
   32-битного iTunes.dll, ни нужной ветки реестра.
2. `Store -> Authorize This Computer` под **своим Apple ID** ("Lapbase").
3. После этого рядом появятся:
   `C:\ProgramData\Apple Computer\iTunes\SC Info\SC Info.sidb`
   `C:\ProgramData\Apple Computer\iTunes\SC Info\SC Info.sidd`
   — «Сид»-файлы, `KBSyncTokenCreate` будет брать именно их.
   (Их можно резервировать в стороннее место: это подключение Apple к хранилищу.)

Проверка того, что iTunes классический (32-bit) и где нужные DLL:
`C:\Program Files (x86)\Common Files\Apple\Apple Application Support` — там
`iTunes.dll` (или `iTunesCore.dll`). Если у тебя Store-версия — путь
`WindowsApps`, DLL оттуда не загрузится, переустанови классический iTunes.

## Шаг 2 — DSID

`AirFairSyncAccountAuthorize` требует DSID — численный id аккаунта Apple.

Простой пользовательский способ:
1. Запусти `python get_dsid.py edge`. Откроется обычный Edge на iCloud; войди
   под своим Apple ID.
2. Скрипт читает `X-APPLE-WEBAUTH-USER` вида `v=1:s=0:d=1234567890`;
   пароль скрипт не читает.
3. Скопируй `dsid.txt` в `worker\dsid.txt`. Воркер перечитывает DSID при
   каждом новом подключении — для смены DSID не надо пересобирать `.exe`.

### Несколько аккаунтов

`accounts.json` принимает DSID на каждый аккаунт:

```json
{
  "you@example.com":      { "display_name": "You", "dsid": 17230907310 },
  "second@example.com":   { "display_name": "Second", "dsid": 9876543210 }
}
```

Сервер выбирает аккаунт по `account_id` (sha256 от email — телефон шлёт его
сам), берёт `dsid` из записи и передаёт воркеру внутри каждого запроса
(первый QWORD поля GrappaSupportInfo; патч `tools/patch_runtime.py`).
Параллельные сессии с разными аккаунтами работают одновременно; поле `dsid`
необязательно — без него воркер берёт fallback из `worker\dsid.txt`.

Параллельность упирается в один процесс воркера: его accept-цикл поднимает
поток на каждое соединение, но thread-safety нативных iTunes-вызовов не
гарантирована, поэтому сервер сериализует сессии на порт. Для двух-трёх
аккаунтов одного воркера достаточно — сессии просто выстраиваются в очередь
(каждая занимает порт с момента `begin` до конца авторизации). Если понадобится
настоящий параллел, задай `VERNI_WORKER_PORTS=27987,27988,...` и держи по
экземпляру воркера на порт; учти, порт `27987` вшит в их `main.cpp`, так что
копиям нужен пересбор с другим портом (`auth_socket_bind`) или отдельные
машины/контейнеры. Сервер раскидывает сессии по свободным портам автоматически.

Альтернативное: sniff трафика iTunes при первом логине (для канала thread
kanxue 229601). Cookie-способ проще и рабочий.

## Шаг 3 — сборка воркера: полностью через GitHub Actions

Раньше это делалось руками в Visual Studio. Теперь весь пайплайн стоит в
`.github/workflows/build-worker.yml` этого репо:

* клонируются `iOSAuthRuntime` (DLL с вызовами `iTunes.dll`: `KBSync*`,
  `AirFairSync*`) и `iOSAuthSingle` (TCP-сервер на фикс-порту **27987**,
  из `main.cpp`);
* workflow патчит `Exec.cpp` так, чтобы DSID читался из `dsid.txt` рядом с
  `iOSAuthSingle.exe` при каждом новом соединении; DSID больше не зашит в exe;
* собираются обе сборки: `msbuild /p:Platform=Win32 /p:Configuration=Release
  /p:PlatformToolset=v143` (в vcxproj прописан v142 — на GitHub-реджнере
  тестовый runtime ок в v143, олиб транспорт не меняет ABI);
* артефакт `verni-worker-Win32`: `iOSAuthSingle.exe` + `iOSAuthRuntime.dll`,
  скачай из Actions и распакуй в каталог `verni-server\worker\`.

Пересобирать воркер при обновлении DSID не нужно: достаточно заменить
`worker\dsid.txt`; уже запущенный воркер прочитает новое значение на следующем
подключении. Сам DSID обычно постоянный идентификатор аккаунта, а не короткий
токен с регулярным сроком действия. Если Apple повторно авторизует аккаунт и
DSID изменится, запусти `get_dsid.py` ещё раз и замени файл.

Порт воркера 27987 жёстко прописан в их `main.cpp`: лучше не трогать и
использовать его всюду (`bridge.py`, `run_server.ps1` — дефолт уже 27987).
Совсем менять не надо, но если захочешь — `set VERNI_WORKER_PORT=<твой>`.

При обновлении самого кода воркера достаточно вручную запустить workflow
`build-worker`; менять DSID и пересобирать из-за него не требуется.

## Шаг 4 — установка verni-server

В каталоге данного репо:
```
pip install -r requirements.txt
python -m py_compile server.py bridge.py    # проверка синтаксиса
python .\make_key.py all <твой-hostname>     # cert.pem/key.pem + verni-key.txt + .env.server
```
`< hostname >` — имя, по которому телефон будет ходить на ПК
(например, `192.168.1.100` или домен). Он попадает в `CN` сертификата
и `endpoint` ключа.

Порт в ключе вшит `:18766`, потому что remote_provider.py смотрит на url.port.
SIG_LEN в bridge.py (0x15) — размер sig-блока в ответе воркера, получается из
кадра, если у тебя вдруг другой формат — разбей точнее: размер sig = полный
кадр len - ответ размера rs. Пока работает: 21 байт.

## Шаг 5 — запуск

```
# окно 1 — воркер, артефакт из GitHub Actions и dsid.txt лежат в .\worker\
.\worker\iOSAuthSingle.exe      # слушает фиксированный TCP 27987 (localhost)

# окно 2
powershell -ExecutionPolicy Bypass -File .\run_server.ps1
```
Сервер поднимет uvicorn:18766 с TLS (пароль ключа не ставишь).

Проверки:
```
python .\test_worker.py            # fake-пакет 1 -> [ok] Grappa frame или [warn]
$tok = (Get-Content .env.server -Raw).Trim() -replace '^VERNI_TOKEN=',''
python .\test_server.py https://127.0.0.1:18766 $tok
```
Ожидаемо 5/5.

## Шаг 6 — телефон

1. Отправь `verni-key.txt` в Verni-Desktop (AccessKeyDialog → ImportProfile).
2. В backend.py профиле возьмётся `endpoint`/`token`/`ca_pem`.
3. Вызовы: `status` → `preflight` → `exchange` — выйдет FairPlay ready, App Store
   на телефоне увидит доступны для установки приложения так же, как у овнера.

## Карта файлов

| файл | роль |
|---|---|
| `server.py` | HTTP-сервер: `Bearer`-авторизация, /v1/ready/begin/complete/abort |
| `bridge.py` | кадрированный протокол к worker'у, сессии, TTL |
| `make_key.py` | self-signed TLS (cert/key) + генератор `VERNI1.<…>` ключа |
| `accounts.json` | apple_id → display_name; account_id = sha256(email) |
| `ipa-catalog.json` | ipa_sha256 → метка (по умолчанию пусто, режим permissive) |
| `test_worker.py` | идеи fake-грам/пуffами, идёт в worker-порт |
| `test_server.py` | 5/5 HTTP-сценариев без iPhone |
| `get_dsid.py` | открывает Apple Music для входа и сохраняет cookie DSID |
| `tools/patch_runtime.py` | патч сборки: DSID читается из файла на каждом соединении |
| `run_server.ps1` | запуск uvicorn c .env.server и TLS |

## Отладка

Симптом / причина (клиентская ошибка → что ты сделал, что сломано):

* `server_tls_failed` — телефон не принял cert.pem. Проверь, что hostname в
  ключе == CN + SAN сертификата; при самоподписи это обязан быть ca_pem.
* `server_unauthorized` — в ключе другой токен, не как в `VERNI_TOKEN`серве.
* `server_wrong_device` — ключ уже импортирован другим UDID; сотри
  `key_udids.json` на сервере, если хочешь переокучить.
* `server_begin_already_used` — обмен одновременно на одной сессии для этого
  ключа. Телефон для начала должен закрыть прошлое соединение/abort.
* `server_owner_generator_busy` — worker не отвечает/connect timeout; запущен
  ли iOSAuthSingle.exe и на том ли порту.
* `server_worker_reported_error` — worker верн ошибку/разорвал соединение:
  нет SC Info.sidb (не блокирована iTunes авторизация), DSID не тот (число,
  не строка), нет iTunes.dll (Store-версия iTunes), тело rq_sig не 0x15, тело
  deviceGrappa не 0x53, GrappaSupportInfo последнее — bridge сверяется.
* `unknown_session` — lost TTL на сервере (SESSION_TTL=900 c). Попробуй ещё раз
  через нулевое время.

Совсем в глубину: клиентская часть в payload в своё время была отдана тебе
(`C:\Windows\Temp\opencode\Verni_extract\payload\app\remote_provider.py`),
там 17 известных кодов ошибок сервера; не-200 статус — это ошибка, 200 — ок,
остальное клиент парсит в `{"error_code": ...}`.

## Безопасность

* TLS 1.3 — клиенты проверяют направление ключа `ca_pem` — everything honest.
* Ключ 64-символьный — держи в `.env.server` и не публикуй.
* Порт 27987 воркера слушается на всех интерфейсах (bind INADDR_ANY в их
  Network.cpp) — серверов-использовании наружу не надо; если грозит сеть,
  ограничь брандмауэром для 127.0.0.1 или включи аутентификацию трафика
  сам (ниже через SSH-туннель).
* `key_udids.json` — привязка ключа к UDID, «чужой» не встанет.
* Возможно, надо поставить капитанней 1 прокси, если ходишь через Cloudflare —
  но Apple-канал сам clean: локальная сеть должна держать 18766/TCP.
