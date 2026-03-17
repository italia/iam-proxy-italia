import base64
import logging
import saml2

from django.conf import settings
from django.contrib.auth.models import User
from django.dispatch import receiver
from django.http import HttpResponse
from django.shortcuts import render
from django.template import TemplateDoesNotExist
from djangosaml2.conf import get_config
from djangosaml2.cache import IdentityCache, OutstandingQueriesCache
from djangosaml2.cache import StateCache
from djangosaml2.conf import get_config
from djangosaml2.overrides import Saml2Client
from djangosaml2.signals import post_authenticated, pre_user_save
from djangosaml2.utils import (
    available_idps, get_custom_setting,
    get_idp_sso_supported_bindings, get_location
)
from saml2 import BINDING_HTTP_REDIRECT, BINDING_HTTP_POST
from saml2.authn_context import requested_authn_context
from saml2.metadata import entity_descriptor

from .utils import repr_saml


logger = logging.getLogger('djangosaml2')
attribute_display_names = {
        'last_login': 'Last Login',
        'username': 'Username',
        'email': 'Email',
        'matricola': 'Matricola',
        'first_name': 'First Name',
        'last_name': 'Last Name',
        'codice_fiscale': 'Codice Fiscale',
        'gender': 'Gender',
        'place_of_birth': 'Place of Birth',
        'birth_date': 'Birth Date',
    }
context = {
        "LOGOUT_URL" : settings.LOGOUT_URL,
        "LOGIN_URL" : settings.LOGIN_URL,
        "LOGIN_REDIRECT_URL" : settings.LOGIN_REDIRECT_URL
    }

def index(request):
    """ Barebone 'diagnostics' view, print user attributes if logged in + login/logout links.
    """
    return render(request, "base.html", context)


def amministrazione(request):
    return render(request, "amministrazione.html", context)


def echo_attributes(request):
    context['attribute_display_names'] = attribute_display_names
    return render(request, "echo_attributes.html", context)


@receiver(pre_user_save, sender=User)
def custom_update_user(sender, instance, attributes, user_modified, **kargs):
    """ Default behaviour does not play nice with booleans encoded in SAML as u'true'/u'false'.
        This will convert those attributes to real booleans when saving.
    """
    for k, v in attributes.items():
        u = set.intersection(set(v), set([u'true', u'false']))
        if u:
            setattr(instance, k, u.pop() == u'true')
    return True
