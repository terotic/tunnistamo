from django.urls import re_path

from . import views

app_name = 'auth_backends'

urlpatterns = [
    re_path(r'^(?P<backend>[^/]+)/logout/callback/$', views.logout_view, name='logout_callback'),
    # Suomi.fi specific endpoints
    re_path(r'^suomifi/metadata/$', views.suomifi_metadata_view, name='suomifi_metadata'),
]
