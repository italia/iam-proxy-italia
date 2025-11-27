from django.apps import AppConfig
from django.utils.translation import gettext_lazy as _


class Custom_AccountsConfig(AppConfig):
    name = 'custom_accounts'
    verbose_name = _("Autenticazione e Autorizzazione Utenti")
