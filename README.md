<img src="static/img/loona.svg" width="96" height="96" alt="Loona">

# Loona

English · [Русский](README.ru.md)

Loona runs Ansible playbooks and OpenTofu plan/apply jobs from a browser. A job page
shows output per host and diffs from check mode. Loona stores the inventory and
job history in PostgreSQL.

Keep playbooks in Git with their roles and templates, or store them in Loona.
The task builder reads module parameters from `ansible-doc`. Use the YAML editor
for playbooks with multiple plays or handlers.

OpenTofu stores state in Loona through an HTTP backend. Export `loona_hosts` to add
provisioned machines to the inventory, and use a workflow to pass outputs to an
Ansible playbook. Users can request machines through forms in the self-service
catalog.

Choose English or Russian in the top bar.

## Setup

You need Git, Docker Compose and OpenSSL. On Linux or macOS:

```sh
git clone https://github.com/Tselikoff/loona.git
cd loona
cp .env.example .env
```

Fill in four variables in `.env`:

| Variable | Purpose |
| --- | --- |
| `LOONA_SECRET_KEY` | Django secret key |
| `LOONA_DB_PASSWORD` | PostgreSQL password |
| `LOONA_REDIS_PASSWORD` | Redis password, in hex |
| `LOONA_SECRET_STORE_KEY` | Fernet key for stored secrets |

Generate a value for each of the first three with `openssl rand -hex 32`.
For the Fernet key, run:

```sh
openssl rand -base64 32 | tr '+/' '-_'
```

Keep `LOONA_SECRET_STORE_KEY` for backup recovery. A different key will not decrypt
your stored secrets. Compose also starts with this variable empty: Loona then
derives the key from `LOONA_SECRET_KEY`, and changing that key makes stored
secrets unreadable.

```sh
docker compose up -d --build --wait
docker compose exec web python manage.py createsuperuser
```

Instead of `createsuperuser`, you can set `LOONA_ADMIN_USERNAME` and
`DJANGO_SUPERUSER_PASSWORD` in `.env`; the web container creates that admin on
first start.

Open [localhost:8080](http://localhost:8080) and sign in with the account you
created.

Compose starts the web service, a worker and scheduler, PostgreSQL and Redis.
PostgreSQL uses the `loona-db` volume; job files and caches use `loona-data`.
PostgreSQL is also published on `127.0.0.1:5432` for development. If that port
is taken, set `LOONA_DB_PORT` in `.env`, or remove the `ports` line from the `db`
service in `compose.yaml`.

## Try it on a test host

Add an SSH username with a password or key under Administration -> Credentials.
Create a group and a host in the inventory, then select that credential for the
host. The worker needs SSH access to the host, and the host needs Python.

Create a playbook in YAML mode:

```yaml
---
- name: Check access
  hosts: all
  gather_facts: false
  tasks:
    - name: Ping the host
      ansible.builtin.ping:
```

Select the group on the launch page and click Run now. Read the result in the
job log.

Use Preview changes to inspect a change before running it. This runs Ansible with
`--check --diff`; modules without check mode support may skip tasks. Applying a
preview uses the saved playbook snapshot and the hosts reached during that check.

For a single command, use an ad-hoc run instead of a playbook. Every run that
gathers facts stores them on the host; search hosts by them in the inventory,
for example `os:ubuntu ram>=8`.

Schedule jobs and drift checks, or create a launch template with an input form
for operators.

## Access

Teams get the Viewer, Operator or Admin role on host groups. Writing playbooks
and writing OpenTofu code are separate global rights. Both let a user run any
command on the worker, so give them only to people you would give shell access.

A host group can require a second person's approval before changes are applied,
and maintenance windows limit when changes run. Outside every window, applying
needs an approval and Run now is off.

Loona creates an Ed25519 key for each host and pins the host's SSH key at the
first connection. Changes to system settings, sign-in, users, directory groups,
executors and notification channels go to the audit log.

## Workflows and notifications

A workflow joins steps with success, failure and always arrows. A step runs an
OpenTofu project or a playbook, waits for an approval or sends a message.
OpenTofu outputs are passed to later playbook steps. Start a workflow by hand,
through the API, by a trigger URL or on a schedule.

Messages go by email, Telegram or webhook. Set up channels under
Administration -> Notifications.

## Server access

Compose binds the web port to `127.0.0.1:8080` by default. To serve Loona on a
domain, configure a reverse proxy with HTTPS and add these settings to `.env`:

```dotenv
LOONA_ALLOWED_HOSTS=loona.example.com
LOONA_CSRF_TRUSTED_ORIGINS=https://loona.example.com
LOONA_HTTPS=true
LOONA_TRUST_PROXY=true
```

Enable `LOONA_TRUST_PROXY` behind a proxy that overwrites `X-Forwarded-Proto`
and `X-Forwarded-For`. For a proxy on another machine, set `LOONA_BIND` to an
address it can reach. See
[.env.example](.env.example) for other settings.

For hosts in another network, create an executor under Administration -> Executors
and assign it to a group. The executor page has a token and an agent startup
command. Build the same Dockerfile on the agent machine or load a copy of the
`loona:latest` image you built. The agent fetches jobs from Loona over an outbound
HTTPS connection. Run hosts behind different executors in separate jobs.

Set up LDAP / AD sign-in under Administration -> Authentication, and OIDC or
SAML under Administration -> Single sign-on. Local accounts remain available.
One-time codes (TOTP) can be required for everyone or for superusers only; this
covers password sign-ins, and SSO leaves it to the identity provider.
Loona encrypts stored credentials and supports HashiCorp Vault for secrets and
Ansible Vault in projects.

## API

Click your username in the top bar to create a personal token. Set
`LOONA_API_TOKEN` to that token:

```sh
curl -H "Authorization: Bearer $LOONA_API_TOKEN" \
  http://localhost:8080/api/v1/me/
```

The token uses your account's permissions. After signing in, open `/api/docs/`
for Swagger UI or `/api/schema/` for the OpenAPI schema. You can set up CI
triggers on the account page.

## Backup

```sh
docker compose exec -T web python manage.py loona_backup - > loona-backup.tar.gz
```

The archive contains the PostgreSQL application data, including OpenTofu state.
Keep the encryption key apart from the archive; the backup command leaves it out.

To restore, start Loona with the same encryption key and load the archive:

```sh
docker compose run --rm -T web python manage.py loona_restore - < loona-backup.tar.gz
```

The database must have no users. If you have already created an admin, add
`--replace`: it deletes everything in the database first. `--check` only
compares the archive with this Loona and changes nothing.

## Development

Python, Django and PostgreSQL, with HTMX and Alpine.js in the browser. Jobs run
through Celery and Redis. The Docker image contains Ansible and OpenTofu.

Run tests with the Compose stack up:

```sh
docker compose run --rm web python manage.py test
```

To run Loona without the image, start only the database with
`docker compose up -d db`. In `.env`, set `LOONA_DEBUG=true` and
`LOONA_DATABASE_URL` (see `.env.example`), then:

```sh
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt ansible
python manage.py migrate
python manage.py loona_demo     # admin/admin, a localhost target, two playbooks
python manage.py runserver
```

With `LOONA_RUNNER_MODE=thread`, jobs run inside runserver with no worker.

[Changelog](CHANGELOG.md) · [Report a bug](https://github.com/Tselikoff/loona/issues)

License: [GPL-3.0-or-later](LICENSE).
