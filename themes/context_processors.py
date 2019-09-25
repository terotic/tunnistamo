from django.conf import settings


def theme_variables(request):
    return dict(tunnistamo_theme=settings.TUNNISTAMO_THEME)
