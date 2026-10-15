# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Целиков Евгений
"""Django settings for Loona."""
import os
from urllib.parse import urlsplit
from pathlib import Path

from dotenv import load_dotenv

from core.version import __version__

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def env_bool(name, default=False):
    return os.getenv(name, str(default)).lower() in ("1", "true", "yes", "on")


DEBUG = env_bool("LOONA_DEBUG", False)
SECRET_KEY = os.getenv("LOONA_SECRET_KEY", "")
if not SECRET_KEY:
    if not DEBUG:
        from django.core.exceptions import ImproperlyConfigured

        raise ImproperlyConfigured(
            "Set LOONA_SECRET_KEY (or LOONA_DEBUG=true for development)."
        )
    SECRET_KEY = "dev-insecure-change-me"
# The names Loona answers to.  Not "*" by default: absolute addresses (sign-in
# callbacks, trigger URLs) are built from the Host header when no public URL
# is set.  The internal address the worker uses is always allowed.
_internal_host = urlsplit(os.getenv("LOONA_INTERNAL_URL", "")).hostname
ALLOWED_HOSTS = [h.strip() for h in os.getenv("LOONA_ALLOWED_HOSTS", "").split(",") if h.strip()] or (
    ["*"] if DEBUG else ["localhost", "127.0.0.1", "[::1]"]
)
if _internal_host and "*" not in ALLOWED_HOSTS:
    ALLOWED_HOSTS.append(_internal_host)
CSRF_TRUSTED_ORIGINS = [
    o for o in os.getenv("LOONA_CSRF_TRUSTED_ORIGINS", "").split(",") if o
]

# --- HTTPS -------------------------------------------------------------------
# Loona serves plain HTTP on :8000; TLS is the job of a reverse proxy in front.
# LOONA_HTTPS says people reach Loona over https://: cookies are then sent over
# HTTPS only.  No redirect to https here - the healthcheck, the worker (OpenTofu
# state) and executors talk to Loona over plain HTTP inside the network.
LOONA_HTTPS = env_bool("LOONA_HTTPS")
SESSION_COOKIE_SECURE = CSRF_COOKIE_SECURE = LOONA_HTTPS
# Trust X-Forwarded-Proto: https from the proxy, so Loona knows a request came
# in over HTTPS (sign-in redirects, SSO callback addresses).  Only switch on
# behind a proxy that sets the header itself - otherwise a client can fake it.
# The same proxy's X-Forwarded-For is then where the client's address comes
# from (sign-in throttling).
LOONA_TRUST_PROXY = env_bool("LOONA_TRUST_PROXY")
if LOONA_TRUST_PROXY:
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
# Strict-Transport-Security, in seconds.  Off by default: once a browser has
# seen it, it refuses plain HTTP to this name for that long.
SECURE_HSTS_SECONDS = int(os.getenv("LOONA_HSTS_SECONDS", "0"))
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_REFERRER_POLICY = "same-origin"
# The redirect to https belongs to the proxy (see above).
SILENCED_SYSTEM_CHECKS = ["security.W008"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "core",
    "inventory",
    "playbooks",
    "runs",
    "access",
    "infra",
    "administration",
    "notifications",
    "secretstore",
    "catalog",
    "workflows",
    "executors",
    "signin",
    "rest_framework",
    "drf_spectacular",
    "drf_spectacular_sidecar",
    "api",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "core.middleware.SecurityHeadersMiddleware",
    # Serves /static/ itself, so a container needs no separate web server.
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "access.middleware.DirectoryRecheckMiddleware",
    "administration.middleware.SystemLanguageMiddleware",
    "signin.middleware.RequireCodesMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "loona.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.template.context_processors.i18n",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "core.context_processors.loona",
                "access.context_processors.access",
                "administration.context_processors.instance",
            ],
        },
    },
]

WSGI_APPLICATION = "loona.wsgi.application"

def database_from_url(url: str) -> dict:
    """postgres://user:password@host:port/name, as one setting."""
    from urllib.parse import unquote, urlsplit

    parts = urlsplit(url)
    if parts.scheme not in ("postgres", "postgresql"):
        raise ValueError(f"LOONA_DATABASE_URL must be a postgres:// URL, not {parts.scheme}://")
    return {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": unquote(parts.path.lstrip("/")),
        "USER": unquote(parts.username or ""),
        "PASSWORD": unquote(parts.password or ""),
        "HOST": parts.hostname or "",
        "PORT": str(parts.port or ""),
        # Reuse connections for a minute instead of opening one per request.
        "CONN_MAX_AGE": 60,
        "CONN_HEALTH_CHECKS": True,
    }


# PostgreSQL.  The compose stack runs it as the "db" service; for development
# on the host that service listens on 127.0.0.1:5432.
DATABASES = {
    "default": database_from_url(
        os.getenv("LOONA_DATABASE_URL", "postgres://loona:loona@127.0.0.1:5432/loona")
    )
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en"
# The default is chosen in Administration -> General; each person may pick
# their own next to the theme switch.  The API always speaks English.
LANGUAGES = [("en", "English"), ("ru", "Русский")]
LOCALE_PATHS = [BASE_DIR / "locale"]
TIME_ZONE = os.getenv("LOONA_TIME_ZONE", "UTC")
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"
STATICFILES_DIRS = [BASE_DIR / "static"]
STATIC_ROOT = BASE_DIR / "staticfiles"

MEDIA_URL = "media/"
MEDIA_ROOT = BASE_DIR / "media"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

AUTHENTICATION_BACKENDS = [
    # Tried in order: directory accounts first, then local ones such as the
    # break-glass admin.  The LDAP backend steps aside when it is not configured.
    "access.ldap.LdapBackend",
    "administration.auth.LocalBackend",
]

LOGIN_URL = "login"
LOGIN_REDIRECT_URL = "dashboard"
LOGOUT_REDIRECT_URL = "login"

# --- API --------------------------------------------------------------------
REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "api.auth.TokenAuthentication",
        "rest_framework.authentication.SessionAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": ["rest_framework.permissions.IsAuthenticated"],
    "DEFAULT_PAGINATION_CLASS": "rest_framework.pagination.LimitOffsetPagination",
    "PAGE_SIZE": 50,
    "DEFAULT_SCHEMA_CLASS": "drf_spectacular.openapi.AutoSchema",
    "DEFAULT_RENDERER_CLASSES": [
        "rest_framework.renderers.JSONRenderer",
        "rest_framework.renderers.BrowsableAPIRenderer",
    ],
}
SPECTACULAR_SETTINGS = {
    "TITLE": "Loona API",
    "DESCRIPTION": "Everything the UI can do, with the same rights and rules. "
                   "Authenticate with a personal token: Authorization: Bearer loona_...",
    # The API itself is /api/v1/; this is the Loona release serving it.
    "VERSION": __version__,
    "SERVE_INCLUDE_SCHEMA": False,
    # The map of the API is for people who may use it.
    "SERVE_PERMISSIONS": ["rest_framework.permissions.IsAuthenticated"],
    # Swagger UI from Loona itself: closed networks often cannot reach a CDN.
    "SWAGGER_UI_DIST": "SIDECAR",
    "SWAGGER_UI_FAVICON_HREF": "SIDECAR",
}

# --- Loona -----------------------------------------------------------------

# Where ansible-runner private_data_dirs live (one per job).
LOONA_DATA_DIR = Path(os.getenv("LOONA_DATA_DIR", BASE_DIR / "var" / "jobs"))

# Where SSH keys uploaded through the UI are stored.
LOONA_KEYS_DIR = Path(os.getenv("LOONA_KEYS_DIR", BASE_DIR / "var" / "keys"))

# "celery" runs jobs through a worker; "thread" runs them in-process (dev only).
LOONA_RUNNER_MODE = os.getenv("LOONA_RUNNER_MODE", "thread")

# Fernet key used to encrypt credential secrets at rest. Generate with:
#   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
LOONA_SECRET_STORE_KEY = os.getenv("LOONA_SECRET_STORE_KEY", "")

# Keep at most this many events per job in the database (0 = unlimited).
LOONA_MAX_JOB_EVENTS = int(os.getenv("LOONA_MAX_JOB_EVENTS", "5000"))

# Build editor forms for any installed module from ansible-doc.  Off, the
# editor offers only its hand-written catalog.  The test runner turns it off
# so the suite does not depend on which collections the machine has.
LOONA_MODULE_DOCS = env_bool("LOONA_MODULE_DOCS", True)

TEST_RUNNER = "core.test_runner.LoonaTestRunner"

# --- OpenTofu ---------------------------------------------------------------
LOONA_TOFU_BINARY = os.getenv("LOONA_TOFU_BINARY", "tofu")
# How a run reaches Loona's state backend.  The worker may be another
# container: compose points this at the web service.
LOONA_INTERNAL_URL = os.getenv("LOONA_INTERNAL_URL", "http://127.0.0.1:8000").rstrip("/")
# Galaxy roles and collections from a project's requirements.yml, kept by
# content so the same requirements are downloaded once.
LOONA_GALAXY_CACHE = Path(os.getenv("LOONA_GALAXY_CACHE", LOONA_DATA_DIR.parent / "galaxy-cache"))
# Providers are downloaded once and shared by every run.
LOONA_TOFU_PLUGIN_CACHE = Path(
    os.getenv("LOONA_TOFU_PLUGIN_CACHE", LOONA_DATA_DIR.parent / "tofu-plugins")
)

# How notification mail leaves; the SMTP server itself is set in
# Administration.  Tests swap in Django's in-memory backend.
LOONA_EMAIL_BACKEND = os.getenv("LOONA_EMAIL_BACKEND", "django.core.mail.backends.smtp.EmailBackend")
# Telegram's Bot API; tests point it at a local stand-in.
LOONA_TELEGRAM_API = os.getenv("LOONA_TELEGRAM_API", "https://api.telegram.org")

# --- LDAP / Active Directory ----------------------------------------------
# Off unless a server is set.  Every LDAP group a user belongs to (nested
# groups included) becomes a Loona team; roles on host groups are then granted
# to those teams.  See access/ldap.py.
LOONA_LDAP = {
    "SERVER_URI": os.getenv("LOONA_LDAP_SERVER_URI", ""),
    "START_TLS": env_bool("LOONA_LDAP_START_TLS"),
    # Verify the server certificate on ldaps:// and StartTLS.  Only switch off
    # for a lab directory with a self-signed certificate.
    "VERIFY_TLS": env_bool("LOONA_LDAP_VERIFY_TLS", True),
    "CA_FILE": os.getenv("LOONA_LDAP_CA_FILE", ""),
    "TIMEOUT": int(os.getenv("LOONA_LDAP_TIMEOUT", "5")),
    # Service account Loona searches with; empty for an anonymous search.
    "BIND_DN": os.getenv("LOONA_LDAP_BIND_DN", ""),
    "BIND_PASSWORD": os.getenv("LOONA_LDAP_BIND_PASSWORD", ""),
    "USER_BASE": os.getenv("LOONA_LDAP_USER_BASE", ""),
    # {username} is escaped before it is substituted.  For AD: (sAMAccountName={username})
    "USER_FILTER": os.getenv("LOONA_LDAP_USER_FILTER", "(uid={username})"),
    "USERNAME_ATTR": os.getenv("LOONA_LDAP_USERNAME_ATTR", "uid"),
    "EMAIL_ATTR": os.getenv("LOONA_LDAP_EMAIL_ATTR", "mail"),
    "FIRST_NAME_ATTR": os.getenv("LOONA_LDAP_FIRST_NAME_ATTR", "givenName"),
    "LAST_NAME_ATTR": os.getenv("LOONA_LDAP_LAST_NAME_ATTR", "sn"),
    "GROUP_BASE": os.getenv("LOONA_LDAP_GROUP_BASE", ""),
    "GROUP_FILTER": os.getenv(
        "LOONA_LDAP_GROUP_FILTER",
        "(|(objectClass=groupOfNames)(objectClass=groupOfUniqueNames)"
        "(objectClass=posixGroup)(objectClass=group))",
    ),
    "GROUP_NAME_ATTR": os.getenv("LOONA_LDAP_GROUP_NAME_ATTR", "cn"),
    # "all": every directory group becomes a team on first sight.
    # "mapped": only groups an administrator has already linked to a team.
    "MIRROR_GROUPS": os.getenv("LOONA_LDAP_MIRROR_GROUPS", "all"),
    # Group DNs.  Membership turns the flag on, leaving the group turns it off.
    "REQUIRE_GROUP": os.getenv("LOONA_LDAP_REQUIRE_GROUP", ""),
    "SUPERUSER_GROUP": os.getenv("LOONA_LDAP_SUPERUSER_GROUP", ""),
    "STAFF_GROUP": os.getenv("LOONA_LDAP_STAFF_GROUP", ""),
    # How often a signed-in directory user is checked against the directory:
    # removed users are signed out, group changes apply without a new sign-in.
    "RECHECK_MINUTES": int(os.getenv("LOONA_LDAP_RECHECK_MINUTES", "15")),
}

CELERY_BROKER_URL = os.getenv("LOONA_BROKER_URL", "redis://localhost:6379/0")
CELERY_RESULT_BACKEND = os.getenv("LOONA_RESULT_BACKEND", CELERY_BROKER_URL)
CELERY_TASK_TRACK_STARTED = True
# Acknowledge a task only once it has run, so a worker dying between taking
# it and starting it does not lose it.  A task that already started is not
# rerun on redelivery: executor.run_job claims each job exactly once.
CELERY_TASK_ACKS_LATE = True
CELERY_TASK_REJECT_ON_WORKER_LOST = True
CELERY_WORKER_PREFETCH_MULTIPLIER = 1
# How long Redis waits before handing an unacknowledged task to another
# worker.  Safe to keep short for the same reason: a duplicate is a no-op.
CELERY_BROKER_TRANSPORT_OPTIONS = {"visibility_timeout": 600}
# The scheduler (celery beat, the "scheduler" container) sends one tick a
# minute; the worker starts whatever drift checks are due.
CELERY_BEAT_SCHEDULE = {"loona-tick": {"task": "loona.tick", "schedule": 60.0}}
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TIMEZONE = TIME_ZONE

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {"console": {"class": "logging.StreamHandler"}},
    "root": {"handlers": ["console"], "level": os.getenv("LOONA_LOG_LEVEL", "INFO")},
}

# Everything secret has been read; children of this process get none of it.
# See core.hardening.
from core.hardening import harden  # noqa: E402

harden()
