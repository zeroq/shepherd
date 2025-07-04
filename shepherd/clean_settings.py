"""
Django settings for shepherd project.

Generated by 'django-admin startproject' using Django 4.1.4.

For more information on this file, see
https://docs.djangoproject.com/en/4.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.1/ref/settings/
"""

import os
from django.contrib import messages
from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/4.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = '<KEY HERE>'

# SECURITY WARNING: don't run with debug turned on in production!
ADMIN_ENABLED = True
DEBUG = True
ALLOWED_HOSTS = ['127.0.0.1']

# Enforce HTTPS
# SECURE_SSL_REDIRECT = True  # Redirect all HTTP requests to HTTPS
# SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')  # Use when behind a proxy/load balancer
# SESSION_COOKIE_SECURE = True  # Ensure cookies are only sent over HTTPS
# CSRF_COOKIE_SECURE = True  # Ensure CSRF cookies are only sent over HTTPS
# SECURE_HSTS_SECONDS = 31536000  # Enable HTTP Strict Transport Security (HSTS) for 1 year
# SECURE_HSTS_INCLUDE_SUBDOMAINS = True  # Apply HSTS to all subdomains
# SECURE_HSTS_PRELOAD = True  # Allow the domain to be preloaded in browsers
# SECURE_REFERRER_POLICY = 'strict-origin-when-cross-origin'  # Set a secure referrer policy

# Application definition

INSTALLED_APPS = [
    'django_extensions',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'rest_framework',
    'rest_framework.authtoken',
    'menu',
    'shepherd',
    'project',
    'keywords',
    'suggestions',
    'findings',
    'accounts',
    'jobs',
    'api',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'shepherd.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

#TEMPLATE_LOADERS = (
#    'django.template.loaders.filesystem.Loader',
#    'django.template.loaders.app_directories.Loader',
#     'django.template.loaders.eggs.Loader',
#)

WSGI_APPLICATION = 'shepherd.wsgi.application'


# Database
# https://docs.djangoproject.com/en/4.1/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# Password validation
# https://docs.djangoproject.com/en/4.1/ref/settings/#auth-password-validators

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


# Internationalization
# https://docs.djangoproject.com/en/4.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.1/howto/static-files/

STATIC_URL = 'static/'
STATIC_ROOT = os.path.join(BASE_DIR, "static/")

# Default primary key field type
# https://docs.djangoproject.com/en/4.1/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# REST Framework
REST_FRAMEWORK = {
    'DEFAULT_PAGINATION_CLASS': 'api.pagination.CustomPaginator',
    'PAGE_SIZE': 25,
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework.authentication.BasicAuthentication',
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.TokenAuthentication',
    ),
    'DEFAULT_PERMISSION_CLASSES': ( 'rest_framework.permissions.IsAuthenticated', ),
}

# DomainTools API
DOMAINTOOLS_KEY = ""
DOMAINTOOLS_USER = ""

# Shodan API
SHODAN_API_KEY = ""

# FOFA API
FOFA_EMAIL = ""
FOFA_KEY = ""

# Nucleus API
NUCLEUS_URL = ''
NUCLEUS_KEY = ''
NUCLEUS_PROJECT = ''

# Recent Findings Days
RECENT_DAYS = 5

# Cache
CACHES = {
    "default": {
        'BACKEND': 'django.core.cache.backends.dummy.DummyCache',
        # If you want to use caching uncomment the following and install: apt install memcached
        # "BACKEND": "django.core.cache.backends.memcached.PyMemcacheCache",
        # "LOCATION": "127.0.0.1:11211",
    }
}

RATELIMIT_USE_CACHE = 'default'

# For Nginx proxy to Gunicorn
# USE_X_FORWARDED_HOST = True
# SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
# RATELIMIT_IP_META_KEY = 'HTTP_X_FORWARDED_FOR'
# RATELIMIT_TRUSTED_PROXIES = ['127.0.0.1', '::1']


#### SSO
# # OpenID Connect (OIDC) settings
# AUTHENTICATION_BACKENDS = [
#     'accounts.auth.CustomOIDCBackend',
#     'django.contrib.auth.backends.ModelBackend',
# ]

# LOGIN_URL = '/oidc/authenticate/'
# LOGIN_REDIRECT_URL = '/'
# LOGOUT_REDIRECT_URL = '/'

# # OIDC provider settings for Microsoft (Azure AD)
# OIDC_RP_CLIENT_ID = 'your-azure-client-id'
# OIDC_RP_CLIENT_SECRET = 'your-azure-client-secret'
# OIDC_OP_AUTHORIZATION_ENDPOINT = 'https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/authorize'
# OIDC_OP_TOKEN_ENDPOINT = 'https://login.microsoftonline.com/<tenant-id>/oauth2/v2.0/token'
# OIDC_OP_USER_ENDPOINT = 'https://graph.microsoft.com/oidc/userinfo'
# OIDC_OP_JWKS_ENDPOINT = 'https://login.microsoftonline.com/<tenant-id>/discovery/v2.0/keys'
# OIDC_RP_SIGN_ALGO = 'RS256'
