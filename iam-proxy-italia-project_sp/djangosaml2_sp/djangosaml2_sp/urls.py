from djangosaml2 import views
from django.conf import settings
from django.contrib import admin
from django.contrib.auth.views import LogoutView
from django.urls import include, path

from saml2_sp.views import amministrazione, index, echo_attributes

urlpatterns = [
    path('admin/', admin.site.urls),
]

if 'saml2_sp' in settings.INSTALLED_APPS:
    import saml2_sp.urls
    SAML2_URL_PREFIX = 'saml2'

    urlpatterns.extend([
        #path('', include((saml2_sp.urls, 'sp',))),
        path(f'', index, name='index'),
        path(f'amministrazione/', amministrazione, name='amministrazione'),
        path(f'echo_attributes/', echo_attributes, name='echo_attributes'),

        path(f'{SAML2_URL_PREFIX}/login/', views.LoginView.as_view(), name='saml2_login'),
        path(f'{SAML2_URL_PREFIX}/acs/', views.AssertionConsumerServiceView.as_view(), name='saml2_acs'),
        path(f'{SAML2_URL_PREFIX}/logout/', views.LogoutInitView.as_view(), name='saml2_logout'),
        path(f'{SAML2_URL_PREFIX}/ls/', views.LogoutView.as_view(), name='saml2_ls'),
        path(f'{SAML2_URL_PREFIX}/ls/post/', views.LogoutView.as_view(), name='saml2_ls_post'),
        path(f'{SAML2_URL_PREFIX}/metadata/', views.MetadataView.as_view(), name='saml2_metadata'),
        path(f'{SAML2_URL_PREFIX}/echo_attributes', views.EchoAttributesView.as_view(), name='saml2_echo_attributes'),
        path('logout/', LogoutView.as_view(), {'next_page': settings.LOGOUT_REDIRECT_URL}, name='logout')
    ])


if 'djangosaml2_spid' in settings.INSTALLED_APPS:
    import djangosaml2_spid.urls

    urlpatterns.extend([
        path('', include((djangosaml2_spid.urls, 'djangosaml2_spid',)))
    ])
