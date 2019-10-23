from django.urls import re_path

from . import views

app_name = 'auth_backends'

urlpatterns = [
    re_path(r'^(?P<backend>[^/]+)/logout/callback/$', views.logout_view, name='logout_callback'),
    re_path(r'^(?P<backend>[^/]+)/metadata/$', views.saml_metadata_view, name='saml_metadata'),
]
