"""
URL configuration for wallet_trust_anchor project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
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

admin.site.site_header = "OIDC Federation Trust Anchor Administration"
admin.site.site_title = "OIDC Federation"
admin.site.index_title = "Welcome to OIDC Federation Trust Anchor Admin backend"

ADMIN_PATH = getattr(settings, 'ADMIN_PATH', 'admin/')

urlpatterns = []
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

urlpatterns.extend(entity_urlpatterns)
urlpatterns.extend(ta_urlpatterns)
urlpatterns.extend(onb_urlpatterns)

if 'djagger' in settings.INSTALLED_APPS:
    urlpatterns.append(path('rest/', include('djagger.urls')))
