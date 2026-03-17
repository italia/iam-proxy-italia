from django.conf import settings
from django.contrib.auth.models import AbstractUser
from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.utils.translation import gettext_lazy as _


class User(AbstractUser):
    GENDER= (
                ( 'male', _('Maschio')),
                ( 'female', _('Femmina')),
                ( 'other', _('Altro')),
            )

    # for NameID extreme lenghtness
    USERNAME_FIELD = 'username'
    username = models.CharField(_('Username'), max_length=254,
                                  blank=False, null=False, unique=True)
    is_active = models.BooleanField(_('attivo'), default=True)
    email = models.EmailField(_('email address'), blank=True, null=True)
    matricola = models.CharField(_('Matricola'), max_length=254,
                                 blank=True, null=True,
                                 help_text="come rappresentata su CSA")
    first_name = models.CharField(_('Nome'), max_length=30, blank=True, null=True)
    last_name = models.CharField(_('Cognome'), max_length=30,
                                 blank=True, null=True)
    codice_fiscale = models.CharField(_('Codice Fiscale'), max_length=16,
                                      blank=True, null=True)
    gender    = models.CharField(_('Genere'), choices=GENDER,
                                 max_length=12, blank=True, null=True)
    place_of_birth = models.CharField(_('Luogo di nascita'), max_length=30,
                                blank=True, null=True)
    birth_date = models.DateField(_('Data di nascita'), null=True, blank=True)

    class Meta:
        ordering = ['username']
        verbose_name_plural = _("Accounts")

    def attrs(self):
     for attr, value in self.__dict__.items():
        yield attr, value

    def __str__(self):
        return '{} - {} {}'.format(self.matricola,
                                   self.first_name, self.last_name)
