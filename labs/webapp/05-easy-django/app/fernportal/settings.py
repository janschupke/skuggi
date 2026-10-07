"""
Django settings for the FernData customer-billing portal.

DELIBERATELY VULNERABLE practice target. DEBUG is off (realism), but the app
endpoints forget object-level authorization and trust user-controlled HTML.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "dev-insecure")

# Off for realism — error pages do not leak tracebacks. The flaws are in the
# views/templates, not in DEBUG.
DEBUG = False

# Lab-only: reachable as app.ferndata.lab and via the loopback publish.
ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "billing",
]

MIDDLEWARE = [
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
]

ROOT_URLCONF = "fernportal.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "django.template.context_processors.request",
            ],
        },
    },
]

WSGI_APPLICATION = "fernportal.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.environ.get("DB_NAME", "fernportal"),
        "USER": os.environ.get("DB_USER", "fern"),
        "PASSWORD": os.environ.get("DB_PASS", "fern-db-pw-2024"),
        "HOST": os.environ.get("DB_HOST", "db"),
        "PORT": "5432",
    }
}

# UnsaltedMD5PasswordHasher is listed so the legacy `svc_import` row (an old
# CSV import, stored as md5$$<hex>) can still authenticate alongside the normal
# pbkdf2 accounts — exactly the kind of weak legacy hash a dump exposes.
PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.UnsaltedMD5PasswordHasher",
]

AUTH_PASSWORD_VALIDATORS = []

LANGUAGE_CODE = "en-us"
TIME_ZONE = "UTC"
USE_I18N = True
USE_TZ = True

STATIC_URL = "static/"

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

LOGIN_URL = "/login/"
