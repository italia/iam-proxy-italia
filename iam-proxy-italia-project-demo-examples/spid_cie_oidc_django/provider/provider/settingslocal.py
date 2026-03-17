import aiohttp
import os

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# SECURITY WARNING: keep the secret key used in production secret!
# CHANGE THIS VALUE
SECRET_KEY = 'lrx(fg&+2e=$l=y8$!£$%$/£%412345234534543--345234-dfdfgsdf-myg%r3z!yjm(lg*l%-z'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

# the path corresponding the admin backend, default if not defined: admin/
# CHANGE THIS VALUE
ADMIN_PATH = 'admin/'
APPEND_SLASH = False

# required for onboarding checks and also for all the leafs
OIDCFED_DEFAULT_TRUST_ANCHOR = "http://trust-anchor.example.org:5002"
OIDCFED_TRUST_ANCHORS = [OIDCFED_DEFAULT_TRUST_ANCHOR]
OIDCFED_PROVIDER_PROFILE = "cie"
#OIDCFED_PROVIDER_MAX_REFRESH = 10 #used in SPID
OIDCFED_PROVIDER_MAX_CONSENT_TIMEFRAME = 3600 #used in CIE (seconds)

OIDCFED_REQUIRED_TRUST_MARKS = []

#OIDCFED_FEDERATION_TRUST_MARKS_PROFILES = {
#    "openid_relying_party__public": {},
#    "openid_relying_party__private": {},
#}

HTTPC_PARAMS = {
    "connection": {"ssl": False},
    "session": {"timeout": aiohttp.ClientTimeout(total=4)},
}

LOGIN_REDIRECT_URL = "/oidc/op/landing"
LOGOUT_REDIRECT_URL = "/oidc/op/landing"
LOGIN_URL = "/oidc/op/landing"

ALLOWED_HOSTS = ['*']
AUTH_USER_MODEL = 'spid_cie_oidc_accounts.User'

INSTALLED_APPS = [
    'spid_cie_oidc.accounts',
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    "bootstrap_italia_template",
    'spid_cie_oidc.entity',
    'spid_cie_oidc.authority',
    'spid_cie_oidc.provider',
    'djagger'
]

TEMPLATE_LOADERS = (
'django.template.loaders.eggs.Loader'
)

DJAGGER_DOCUMENT = {
    "app_names" : ['spid_cie_oidc'],
}

DATABASES = {
    # if you need more power
    # 'default': {
    # 'ENGINE': 'django.db.backends.mysql',
    # 'NAME': 'that-username',
    # 'HOST': 'localhost',
    # 'USER': 'that-user',
    # 'PASSWORD': 'that-password',
    # 'PORT': '',
    # 'OPTIONS': {'init_command': "SET sql_mode='STRICT_TRANS_TABLES'"}
    # },
    'default': {
       'ENGINE': 'django.db.backends.sqlite3',
       'NAME': os.path.join(BASE_DIR, 'db.sqlite3'),
    }
}

# https://docs.djangoproject.com/en/2.0/topics/i18n/

LANGUAGE_CODE = 'it-it'
TIME_ZONE = 'Europe/Rome'
USE_I18N = True
USE_L10N = True
USE_TZ = True

DATA_UPLOAD_MAX_NUMBER_FIELDS = 65000

# email notification on errors
# DEFAULT_FROM_EMAIL = 'fedauth-noreply@DOMAIN'
# SERVER_EMAIL = DEFAULT_FROM_EMAIL
# EMAIL_HOST = 'smtpservice.yourdomain.it'
# EMAIL_HOST_USER = 'myemail@hotmail.com'
# EMAIL_HOST_PASSWORD = 'mypassword'
# EMAIL_PORT = 587
# EMAIL_USE_TLS = True

ADMINS = [('name surname', 'user1@DOMAIN'),
          ('name surnale', 'user2@DOMAIN'),]

# LOGGING
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'default': {
            # exact format is not important, this is the minimum information
            'format': '%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
        },
        'detailed': {
            'format': '%(asctime)s %(name)-12s %(levelname)-8s %(message)s [%(pathname)s %(funcName)s:%(lineno)s]'
        },
    },
    'filters': {
        'require_debug_false': {
            '()': 'django.utils.log.RequireDebugFalse'
        }
    },
    'handlers': {
        'mail_admins': {
            'formatter': 'detailed',
            'level': 'ERROR',
            'filters': ['require_debug_false'],
            'class': 'django.utils.log.AdminEmailHandler'
        },
        'console': {
            'formatter': 'default',
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
        },
        "daily": {
          "class": "logging.handlers.TimedRotatingFileHandler",
          "level": "INFO",
          "formatter": "default",
          "filename": f"{BASE_DIR}/logs/provider.log",
          "when": "midnight",
          "backupCount": 96
        }
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'mail_admins'],
            'level': 'ERROR',
            'propagate': False,
        },
        'spid_cie_oidc': {
            'handlers': ['console', 'mail_admins', "daily"],
            'level': 'INFO',
            'propagate': False,
        }
    }
}
