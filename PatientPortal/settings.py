# Django settings for PatientPortal project.

from pathlib import Path
from decouple import config
import os



# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


SECRET_KEY = config('SECRET_KEY')

DEBUG = config('DEBUG', default=False, cast=bool)

ALLOWED_HOSTS = []


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    'rest_framework',
    'django_otp',
    'django_otp.plugins.otp_totp',

    'accounts',
    'auditlog',
    'records',
    'appointments',
    'openmrs_integration',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',

    'django_otp.middleware.OTPMiddleware',
]

ROOT_URLCONF = 'PatientPortal.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [BASE_DIR / 'templates'],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'PatientPortal.wsgi.application'


# Database
# https://docs.djangoproject.com/en/5.2/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': config('DB_NAME'),
        'USER': config('DB_USER'),
        'PASSWORD': config('DB_PASSWORD'),
        'HOST': config('DB_HOST'),
        'PORT': config('DB_PORT'),
    }
}



AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# URL d'accès public aux statiques
STATIC_URL = '/static/'

# Dossier source pour vos fichiers statiques globaux en développement
STATICFILES_DIRS = [
    BASE_DIR / 'static',
]

# Dossier de collecte pour la production (python manage.py collectstatic)
STATIC_ROOT = BASE_DIR / 'staticfiles'



DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'


SMS_BACKEND = config('SMS_BACKEND', default='console')

AUTH_USER_MODEL = 'accounts.PortalUser'

LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
        },
    },
    "loggers": {
        "accounts.otp": {
            "handlers": ["console"],
            "level": "INFO",
            "propagate": True,
        },
    },
}

NUM_TRUSTED_PROXIES = 0  # 0 en dev (runserver). En prod : 1 si nginx seul devant Gunicorn,
                          # 2 si un load balancer cloud est aussi devant nginx, etc.

# Nécessaire pour que request.is_secure() soit correct derrière un proxy
# qui termine le TLS — utilisé par login_view pour valider le paramètre `next`.
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')

PRIVACY_POLICY_VERSION = "2026-09"  # à incrémenter à chaque révision matérielle du texte

# REQ-03
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Strict"
CSRF_COOKIE_SAMESITE = "Strict"

# REQ-09 — active uniquement hors dev local en HTTP simple, sinon runserver casse
SESSION_COOKIE_SECURE = not DEBUG
CSRF_COOKIE_SECURE = not DEBUG
SECURE_SSL_REDIRECT = not DEBUG
SECURE_HSTS_SECONDS = 0 if DEBUG else 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = not DEBUG
SECURE_HSTS_PRELOAD = not DEBUG

# REQ-15
DATABASES["default"]["CONN_MAX_AGE"] = 60
DATABASES["default"].setdefault("OPTIONS", {})["options"] = "-c statement_timeout=5000"

#for Prod
# CACHES = {
#     "default": {
#         "BACKEND": "django.core.cache.backends.redis.RedisCache",
#         "LOCATION": "redis://127.0.0.1:6379/1",
#     }
# }

CA_BUNDLE_PATH = config('OPENMRS_CA_BUNDLE_PATH', default=None)
