"""acsia_agent_proj URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.0/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf import settings
from django.contrib import admin
from django.urls import include, path, re_path
from django.views.static import serve

from spid_cie_oidc.entity.urls import urlpatterns as entity_urlpatterns
from spid_cie_oidc.authority.urls import urlpatterns as ta_urlpatterns
from spid_cie_oidc.onboarding.urls import urlpatterns as onb_urlpatterns
from spid_cie_oidc.provider.urls import urlpatterns as prov_urlpatterns

admin.site.site_header = "OIDC Federation Entity Administration"
admin.site.site_title = "OIDC Federation"
admin.site.index_title = "Welcome to OIDC Federation Entity Admin backend"

ADMIN_PATH = getattr(settings, 'ADMIN_PATH', 'admin/')

urlpatterns = []

urlpatterns.extend(entity_urlpatterns)
urlpatterns.extend(prov_urlpatterns)
urlpatterns.extend(ta_urlpatterns)
urlpatterns.extend(onb_urlpatterns)

urlpatterns.extend(
    (
        path(f"{ADMIN_PATH}", admin.site.urls),
        re_path('^static/(?P<path>.*)$',
            serve, {
                'document_root': settings.STATIC_ROOT,
                # 'show_indexes': True
            }
        ),
        
    )
)

if 'spid_cie_oidc.relying_party' in settings.INSTALLED_APPS:
    from spid_cie_oidc.relying_party.urls import urlpatterns as rp_urlpatterns
    urlpatterns.extend(rp_urlpatterns)

    from spid_cie_oidc.entity.views import entity_configuration, resolve_entity_statement

    urlpatterns.extend(
        [
            path(
                f"oidc/rp/.well-known/openid-federation",
                entity_configuration,
                name="rp_entity_configuration",
            ),
            path(
                "oidc/rp/resolve",
                resolve_entity_statement,
                name="rp_entity_resolve",
            ),
        ]
    )

if 'spid_cie_oidc.provider' in settings.INSTALLED_APPS:
    from spid_cie_oidc.provider.urls import urlpatterns as op_urlpatterns
    urlpatterns.extend(op_urlpatterns)

    from spid_cie_oidc.entity.views import entity_configuration

    urlpatterns.extend(
        [
            path(
                f"oidc/op/.well-known/openid-federation",
                entity_configuration,
                name="op_entity_configuration",
            ),
            path(
                "oidc/op/resolve",
                resolve_entity_statement,
                name="op_entity_resolve",
            ),
        ]
    )

if 'spid_cie_oidc.relying_party_test' in settings.INSTALLED_APPS:
    from spid_cie_oidc.relying_party_test.urls import urlpatterns as rp_urlpatterns_test
    urlpatterns.extend(rp_urlpatterns_test)

if 'djagger' in settings.INSTALLED_APPS:
    urlpatterns.append(path('rest/', include('djagger.urls')))
