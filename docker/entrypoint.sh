#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
# One image, two roles:
#   web     migrate, then serve the UI with gunicorn on :8000
#   worker     run jobs with Celery
#   scheduler  start due drift checks (celery beat)
#   executor   a remote executor's agent: LOONA_URL, LOONA_EXECUTOR_TOKEN
# Anything else is run as a command, e.g. "python manage.py shell".
set -e

# The first admin's password goes to createsuperuser and nowhere else.
admin_password="${DJANGO_SUPERUSER_PASSWORD:-}"
unset DJANGO_SUPERUSER_PASSWORD

case "$1" in
  web)
    python manage.py migrate --noinput
    # First start: an admin to sign in with, if the environment names one.
    if [ -n "${LOONA_ADMIN_USERNAME}" ] && [ -n "${admin_password}" ]; then
      DJANGO_SUPERUSER_PASSWORD="${admin_password}" python manage.py createsuperuser --noinput \
        --username "${LOONA_ADMIN_USERNAME}" --email "${LOONA_ADMIN_EMAIL:-}" 2>/dev/null \
        && echo "Created admin user ${LOONA_ADMIN_USERNAME}" || true
    fi
    # The editor's module list; harmless if ansible-doc has a bad day.
    python manage.py loona_modules || echo "Module index not refreshed; the editor falls back to its catalog."
    unset admin_password
    # --preload: the master loads the settings too, and so drops the keys
    # from its environment before it forks the workers.
    exec gunicorn loona.wsgi \
      --preload \
      --bind 0.0.0.0:8000 \
      --workers "${LOONA_WEB_WORKERS:-3}" \
      --timeout 120 \
      --access-logfile -
    ;;
  worker)
    exec celery -A loona worker --loglevel "${LOONA_LOG_LEVEL:-info}" \
      --concurrency "${LOONA_WORKER_CONCURRENCY:-4}"
    ;;
  scheduler)
    # One tick a minute; the worker does the actual work.
    exec celery -A loona beat --loglevel "${LOONA_LOG_LEVEL:-info}" \
      --schedule /var/lib/loona/celerybeat-schedule
    ;;
  executor)
    # No database and no secret key: everything comes from Loona.
    exec python -m executors.agent
    ;;
  *)
    exec "$@"
    ;;
esac
