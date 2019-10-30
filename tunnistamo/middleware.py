import logging
from datetime import timedelta

from django.conf import settings
from django.http import HttpResponseForbidden, HttpResponseRedirect
from django.utils import timezone
from django.utils.http import urlencode, is_safe_url
from django.utils.translation import ugettext_lazy as _
from django.urls import reverse
from django.shortcuts import redirect
from django.contrib import messages
from django.contrib.messages.api import MessageFailure
from social_core.exceptions import SocialAuthBaseException
from oidc_provider.lib.errors import BearerTokenError

from .exceptions import FriendlySocialAuthException


logger = logging.getLogger(__name__)


class InterruptedSocialAuthMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def get_redirect_uri(self, request, exception):
        strategy = request.social_strategy
        redirect_uri = reverse('login')
        next = strategy.session.get('next')
        if next and is_safe_url(url=next, allowed_hosts={request.get_host()}, require_https=request.is_secure()):
            redirect_uri += '?%s' % urlencode({next: next})
        return redirect_uri

    # Override raise_exception() to allow redirect also when debug is enabled
    def raise_exception(self, request, exception):
        strategy = request.social_strategy
        return strategy.setting('RAISE_EXCEPTIONS')

    def get_message(self, request, exception):
        # If we know that the exception will have a user-friendly,
        # translated message, we can confidently show that to the
        # user.
        if isinstance(exception, FriendlySocialAuthException):
            return str(exception)

        # Otherwise, a general message.
        return _('Authentication failed.')

    def process_exception(self, request, exception):
        strategy = getattr(request, 'social_strategy', None)
        if strategy is None or self.raise_exception(request, exception):
            return

        if not isinstance(exception, SocialAuthBaseException):
            return

        logger.info(str(exception), exc_info=exception)

        backend = getattr(request, 'backend', None)
        backend_name = getattr(backend, 'name', 'unknown-backend')

        url = self.get_redirect_uri(request, exception)
        message = self.get_message(request, exception)
        try:
            messages.error(request, message,
                           extra_tags='social-auth ' + backend_name)
        except MessageFailure:
            pass

        if url:
            return redirect(url)


class OIDCExceptionMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        return self.get_response(request)

    def process_exception(self, request, exception):
        if isinstance(exception, BearerTokenError):
            response = HttpResponseForbidden()
            auth_fields = [
                'error="{}"'.format(exception.code),
                'error_description="{}"'.format(exception.description)
            ]
            if 'scope' in request.POST:
                auth_fields = ['Bearer realm="{}"'.format(request.POST['scope'])] + auth_fields
            response.__setitem__('WWW-Authenticate', ', '.join(auth_fields))
            return response


class RestrictedAuthenticationMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        if getattr(request, 'user', None) and request.user.is_authenticated and \
           request.session.get('_auth_user_backend') in settings.RESTRICTED_AUTHENTICATION_BACKENDS:
            if request.user.last_login + timedelta(seconds=settings.RESTRICTED_AUTHENTICATION_TIMEOUT) < timezone.now():
                logger.info('Restricted session has timed out. Session started at {}'.format(request.user.last_login))
                response = HttpResponseRedirect(request.get_full_path())
                request.session.delete()
                return response
        return self.get_response(request)
