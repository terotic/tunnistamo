from django.conf import settings
from django.http import HttpResponse, HttpResponseServerError, Http404
from django.urls import reverse
from social_django.utils import load_backend, load_strategy
from django.views.decorators.csrf import csrf_exempt
from social_django.views import complete as social_django_complete
from social_core.exceptions import MissingBackend


def saml_metadata_view(request, backend):
    complete_url = reverse('social:complete', args=(backend,))
    try:
        saml_backend = load_backend(
            load_strategy(request),
            backend,
            redirect_uri=complete_url,
        )
    except MissingBackend:
        raise Http404()

    if not hasattr(saml_backend, 'generate_metadata_xml'):
        raise Http404()

    metadata, errors = saml_backend.generate_metadata_xml()
    if not errors:
        return HttpResponse(content=metadata, content_type='text/xml')
    return HttpResponseServerError(content=', '.join(errors))


@csrf_exempt
def logout_view(request, backend):
    backend_obj = load_backend(
        load_strategy(request),
        backend,
        redirect_uri=getattr(settings, 'LOGIN_URL'),
    )
    return backend_obj.logout_complete()


@csrf_exempt
def social_auth_complete(request, *args, **kwargs):
    """
    Call social_auth complete() view and set session expiration
    """
    resp = social_django_complete(request, *args, **kwargs)
    if not request.user or not request.user.is_authenticated:
        return resp

    session = request.session
    remember_me = session.get('remember_me', False)
    if not remember_me:
        # Session expires at browser close
        session.set_expiry(0)
    else:
        session.set_expiry(settings.SESSION_COOKIE_AGE_REMEMBER_ME)
    return resp
