<img src="static/img/loona.svg" width="96" height="96" alt="Loona">

# Loona

[English](README.md) · Русский

Loona запускает плейбуки Ansible и выполняет plan/apply OpenTofu из браузера.
В задании видно вывод по хостам и diff из check mode. Инвентарь и историю запусков
Loona хранит в PostgreSQL.

Плейбуки можно брать из Git вместе с ролями и шаблонами или хранить в Loona.
Есть YAML-редактор и конструктор задач, который берёт параметры модулей
из `ansible-doc`. Плейбуки с несколькими play или handlers редактируй в YAML.

State OpenTofu Loona хранит у себя и сама подключает к проекту свой HTTP backend.
Через output `loona_hosts` созданные машины попадают в инвентарь, а workflow
передаёт outputs в плейбук Ansible. Для заказа машин пользователями есть каталог
с формами заявок.

Интерфейс есть на русском и английском. Язык выбирается в верхней панели.

## Запуск

Нужны Git, Docker Compose и OpenSSL. Команды для Linux и macOS:

```sh
git clone https://github.com/Tselikoff/loona.git
cd loona
cp .env.example .env
```

Заполни в `.env` четыре переменные:

| Переменная | Назначение |
| --- | --- |
| `LOONA_SECRET_KEY` | Ключ Django |
| `LOONA_DB_PASSWORD` | Пароль PostgreSQL |
| `LOONA_REDIS_PASSWORD` | Пароль Redis, в hex |
| `LOONA_SECRET_STORE_KEY` | Fernet-ключ для шифрования секретов |

Для каждой из первых трёх выполни `openssl rand -hex 32`.
Для Fernet-ключа выполни:

```sh
openssl rand -base64 32 | tr '+/' '-_'
```

Сохрани `LOONA_SECRET_STORE_KEY`: он понадобится при восстановлении из резервной
копии. С другим ключом ты не сможешь прочитать сохранённые секреты. Compose
запустится и с пустой переменной: тогда Loona выводит ключ из `LOONA_SECRET_KEY`,
и после его смены сохранённые секреты станут нечитаемыми.

```sh
docker compose up -d --build --wait
docker compose exec web python manage.py createsuperuser
```

Вместо `createsuperuser` можно задать в `.env` переменные `LOONA_ADMIN_USERNAME`
и `DJANGO_SUPERUSER_PASSWORD`: веб-контейнер создаст этого администратора при
первом запуске.

Открой [localhost:8080](http://localhost:8080) и войди под созданной учётной
записью.

Compose поднимает веб-сервис, worker и scheduler, PostgreSQL и Redis. База хранится
в томе `loona-db`, рабочие файлы заданий и кеши в `loona-data`.
Для разработки PostgreSQL также открыт на `127.0.0.1:5432`. Если порт занят,
задай `LOONA_DB_PORT` в `.env` или убери строку `ports` у сервиса `db`
в `compose.yaml`.

## Проверка на тестовом хосте

В «Администрирование -> Учётные данные» добавь SSH-логин с паролем или ключом.
В инвентаре создай группу и хост, выбери для него эти учётные данные.
Worker должен доходить до хоста по SSH, а на самом хосте нужен Python.

Создай плейбук в режиме YAML:

```yaml
---
- name: Check access
  hosts: all
  gather_facts: false
  tasks:
    - name: Ping the host
      ansible.builtin.ping:
```

На странице запуска выбери группу и нажми «Запустить сейчас».
Результат появится в логе задания.

Для проверки изменений используй «Превью изменений». Это Ansible
с `--check --diff`: модули без поддержки check mode могут пропускать задачи.
Когда ты применяешь превью, Loona берёт сохранённый снимок плейбука и только те
хосты, до которых дошла проверка.

Для одной команды плейбук не нужен: используй разовую команду. Запуски, которые
собирают факты, сохраняют их на хосте. По фактам можно искать хосты
в инвентаре, например `os:ubuntu ram>=8`.

Задания и проверки drift можно запускать по расписанию. Для оператора создай
шаблон запуска с формой параметров.

## Доступ

Команды получают на группы хостов роль Viewer, Operator или Admin. Право писать
плейбуки и право писать код OpenTofu выдаются отдельно, глобально. Оба права
позволяют выполнить любую команду на worker, поэтому давай их только тем, кому
дал бы shell.

Группа хостов может требовать согласования второго человека перед применением
изменений, а окна обслуживания задают, когда изменения можно применять. Вне всех окон
для применения нужно согласование, а «Запустить сейчас» недоступна.

Loona создаёт для каждого хоста свой ключ Ed25519 и закрепляет SSH-ключ хоста
при первом подключении. Изменения системных настроек, входа, пользователей,
групп каталога, исполнителей и каналов уведомлений попадают в журнал аудита.

## Workflow и уведомления

Workflow соединяет шаги стрелками success, failure и always. Шаг запускает
проект OpenTofu или плейбук, ждёт согласования или отправляет сообщение.
Outputs OpenTofu передаются в следующие шаги-плейбуки. Workflow запускают
вручную, через API, по URL триггера или по расписанию.

Сообщения уходят по email, в Telegram или в webhook. Каналы настраиваются
в «Администрирование -> Уведомления».

## Подключение к серверу

По умолчанию Compose открывает веб-порт на `127.0.0.1:8080`. Для доступа через
домен настрой обратный прокси с HTTPS и добавь в `.env`:

```dotenv
LOONA_ALLOWED_HOSTS=loona.example.com
LOONA_CSRF_TRUSTED_ORIGINS=https://loona.example.com
LOONA_HTTPS=true
LOONA_TRUST_PROXY=true
```

Включай `LOONA_TRUST_PROXY` за прокси, который перезаписывает
`X-Forwarded-Proto` и `X-Forwarded-For`. Для прокси на другой машине задай
`LOONA_BIND` с доступным ему адресом. Другие настройки смотри
в [.env.example](.env.example).

Для хостов в другой сети создай исполнителя в «Администрирование -> Исполнители»
и назначь его группе. На странице исполнителя есть токен и команда запуска
агента. На машине агента собери тот же Dockerfile или загрузи собранный образ
`loona:latest`. Агент забирает задания у Loona по исходящему HTTPS-соединению.
Хосты за разными исполнителями запускай разными заданиями.

LDAP / AD подключается в «Администрирование -> Вход», OIDC и SAML
в «Администрирование -> Единый вход». Локальные учётные записи остаются
доступны. Одноразовые коды (TOTP) можно сделать обязательными для всех или
только для суперпользователей; это касается входа по паролю, при SSO коды
остаются на стороне провайдера. Loona шифрует учётные данные в базе; для секретов
поддерживает HashiCorp Vault и Ansible Vault в проектах.

## API

Нажми на имя пользователя в верхней панели и создай персональный токен.
Задай его в `LOONA_API_TOKEN`:

```sh
curl -H "Authorization: Bearer $LOONA_API_TOKEN" \
  http://localhost:8080/api/v1/me/
```

Токен действует с правами твоей учётной записи. После входа открой `/api/docs/`
для Swagger UI или `/api/schema/` для схемы OpenAPI. На странице учётной записи
можно настроить триггеры для CI.

## Резервная копия

```sh
docker compose exec -T web python manage.py loona_backup - > loona-backup.tar.gz
```

В архив входят данные из PostgreSQL, включая state OpenTofu. Ключ шифрования
сохрани отдельно: команда его в архив не добавляет.

Для восстановления запусти Loona с тем же ключом шифрования и загрузи архив:

```sh
docker compose run --rm -T web python manage.py loona_restore - < loona-backup.tar.gz
```

В базе не должно быть пользователей. Если администратор уже создан, добавь
`--replace`: он сначала удалит всё в базе. `--check` только сверяет архив
с этой Loona и ничего не меняет.

## Разработка

Python, Django и PostgreSQL; в интерфейсе HTMX и Alpine.js. Фоновые задания
выполняет Celery, Redis служит брокером. Docker-образ содержит Ansible и OpenTofu.

Тесты при запущенном Compose:

```sh
docker compose run --rm web python manage.py test
```

Чтобы запустить Loona без образа, подними только базу:
`docker compose up -d db`. В `.env` задай `LOONA_DEBUG=true`
и `LOONA_DATABASE_URL` (пример в `.env.example`), затем:

```sh
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt ansible
python manage.py migrate
python manage.py loona_demo     # admin/admin, цель localhost, два плейбука
python manage.py runserver
```

С `LOONA_RUNNER_MODE=thread` задания выполняются внутри runserver, без worker.

[История версий](CHANGELOG.md) · [Сообщить об ошибке](https://github.com/Tselikoff/loona/issues)

Лицензия: [GPL-3.0-or-later](LICENSE).
