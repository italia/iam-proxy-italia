from django.conf import settings
from django.contrib import admin
from django.urls import include, path

from . import views

urlpatterns = [
    path('', views.index),
    path('amministrazione/',views.amministrazione),
    path("echo_attributes/",views.echo_attributes),
]
