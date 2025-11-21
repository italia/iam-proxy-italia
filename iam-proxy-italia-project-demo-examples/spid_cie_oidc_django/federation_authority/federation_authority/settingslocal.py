import aiohttp
import os

import sys
import logging

from spid_cie_oidc import __version__


if len(sys.argv) > 1 and sys.argv[1] == 'test':
    logging.disable(logging.CRITICAL)

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

OIDCFED_PROVIDER_PROFILE = "spid"
OIDCFED_PROVIDER_MAX_REFRESH = 10 #used in SPID

# OIDCFED_PROVIDER_MAX_CONSENT_TIMEFRAME = 3600 #used in CIE (seconds)

# for RP only
OIDCFED_IDENTITY_PROVIDERS = {
  "spid": {
    "http://trust-anchor.example.org:5002/oidc/op" : OIDCFED_DEFAULT_TRUST_ANCHOR,
  },
  "cie": {
    "http://cie-provider.example.org:8002/oidc/op" : OIDCFED_DEFAULT_TRUST_ANCHOR,
  }
}

OIDCFED_REQUIRED_TRUST_MARKS = []

OIDCFED_FEDERATION_TRUST_MARKS_PROFILES = {
    "openid_relying_party__public": {},
    "openid_relying_party__private": {},
}

HTTPC_PARAMS = {
    "connection": {"ssl": False},
    "session": {"timeout": aiohttp.ClientTimeout(total=4)},
}

LOGIN_REDIRECT_URL = "/oidc/rp/echo_attributes"
LOGOUT_REDIRECT_URL = "/oidc/rp/landing"
LOGIN_URL = "/oidc/rp/landing"


FEDERATION_DEFAULT_POLICY = {
    "openid_relying_party": {
      # TODO: to be customized for each entities, not somethinf to default!
      # "client_id": {"value":  "https://rp.example.it/spid"},
      # "redirect_uris": {
        # "subset_of": [
          # "https://rp.example.it/spid/cb1", 
          # "https://rp.example.it/spid/cb2"
        # ]
      # },
      # "organization_name": {"value": "Example RP organization name"},
      # "logo_uri": {
         # "one_of": [
            # "https://rp.example.it/logo_small.jpg",
            # "https://rp.example.it/logo_big.jpg"
         # ],
         # "default": "https://rp.example.it/logo_small.jpg"
      # },
       # "policy_uri": {
         # "value": "https://rp.example.it/policy.html"
       # },
       # "tos_uri": {
         # "value": "https://rp.example.it/tos.html"
      # },
      "grant_types": {
        "subset_of": [
          "authorization_code",
          "refresh_token"
         ]
      },
    # TODO: to be customized for each actor
    "constraints": {
      # "naming_constraints": {
        # "permitted": [
          # "https://rp.example.it"
      # ]
    # },

    # defines how many intermediaries are allowed to this trust anchor
    "max_path_length": 1
  },
  },
  # TODO: TBD
  "openid_provider": {},
  "federation_entity": {},
  "oauth_resource": {}
}

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
    # 'prettyjson',
    "bootstrap_italia_template",
    'spid_cie_oidc.entity',
    'spid_cie_oidc.authority',
    'spid_cie_oidc.onboarding',
    'spid_cie_oidc.relying_party',
    'spid_cie_oidc.relying_party_test',
    'spid_cie_oidc.provider',
    'djagger'
]

TEMPLATE_LOADERS = (
  'django.template.loaders.eggs.Loader'
)

DJAGGER_DOCUMENT = {
    "info": dict(
        title = "SPID/CIE OIDC OpenAPI 3.0 Documentation",
        description = "OpenAPI 3.0 Document Description",
        termsOfService = "",
        contact = {
            "email": "contatti@developers.italia.it",
            "url": "https://github.com/italia/spid-cie-oidc-django",
            "name" : "Developers Italia"
        },
        license = {
            "name": "CC BY 4.0",
            "url": "https://creativecommons.org/licenses/by/4.0/"
        },
        version = __version__,
        x_logo = {
            "name": "Developers italia",
            "url": "https://developers.italia.it/assets/icons/logo-it.svg"
        }
    ),
    "url_names": [
        # Federation Authority
        'oidcfed_fetch',
        'oidcfed_resolve',
        'oidcfed_list',
        'oidcfed_trust_mark_status',
        'oidcfed_advanced_entity_listing',

        # Provider
        'oidc_provider_authnrequest',
        'oidc_provider_token_endpoint',
        'oidc_provider_userinfo_endpoint',
        'introspection_endpoint',
        'oidc_provider_revoke_session',

        # Relying Party
        'spid_cie_rp_begin',
        'spid_cie_rp_callback',
        'spid_cie_rpinitiated_logout'
    ]
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
          "filename": f"{BASE_DIR}/logs/trust_anchor.log",
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
