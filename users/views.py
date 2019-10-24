import re
from pydoc import locate
from urllib.parse import parse_qs, urlparse

from django.conf import settings
from django.contrib.auth import logout as auth_logout
from django.http import HttpResponse, HttpResponseBadRequest
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import translation
from django.utils.http import urlencode
from django.views.generic import View
from django.views.generic.base import TemplateView
from django.views.decorators.cache import never_cache
from jwkest.jws import JWT
from oauth2_provider.models import get_application_model
from oidc_provider.lib.endpoints.authorize import AuthorizeEndpoint
from oidc_provider.lib.endpoints.token import TokenEndpoint
from oidc_provider.lib import errors as oidc_errors
from oidc_provider.models import Client
from oidc_provider.views import AuthorizeView, EndSessionView
from social_django.models import UserSocialAuth
from social_django.utils import load_backend, load_strategy

from oidc_apis.models import ApiScope

from .models import LoginMethod, OidcClientOptions


# This is used to pass the request query dict to the OIDC endpoint
class DummyRequest:
    def __init__(self, query_dict):
        self.GET = query_dict
        self.method = 'GET'


def get_return_to_rp_uri(request, redirect_uri_params):
    """Returns an URI to redirect the browser to if user cancels authentication
    """

    params = {key: val[0] for key, val in redirect_uri_params.items()}
    dummy_request = DummyRequest(params)
    authorize = AuthorizeEndpoint(dummy_request)
    try:
        # This will make sure redirect URI is valid.
        authorize.validate_params()
    except (
        oidc_errors.ClientIdError, oidc_errors.RedirectUriError, oidc_errors.AuthorizeError
    ):
        return None

    cancel_error = oidc_errors.AuthorizeError(
        authorize.params['redirect_uri'], 'access_denied', authorize.grant_type
    )
    return_uri = cancel_error.create_uri(
        authorize.params['redirect_uri'],
        authorize.params['state']
    )
    return return_uri


class LoginView(TemplateView):
    template_name = "login.html"

    def get_login_methods(self, request, allowed_methods, redirect_uri):
        methods = []
        for m in allowed_methods:
            assert isinstance(m, LoginMethod)

            begin_url = reverse('social:begin', kwargs={'backend': m.provider_id})

            url_params = {}
            if redirect_uri:
                url_params['next'] = redirect_uri

            backend = load_backend(load_strategy(request), m.provider_id, redirect_uri=None)
            if hasattr(backend, 'get_allowed_idp_name'):
                idp_name = backend.get_allowed_idp_name(request)
                url_params['idp'] = idp_name

            if url_params:
                begin_url += '?' + urlencode(url_params)

            m.login_url = begin_url
            methods.append(m)

        return methods

    def get(self, request, *args, **kwargs):  # noqa  (too complex)
        # Log the user out first so that we don't end up in the PSA "connect"
        # flow.
        if self.request.user.is_authenticated:
            auth_logout(self.request)

        next_url = request.GET.get('next')
        app = None
        oidc_client = None
        authorize_uri_params = None
        self.return_to_rp_uri = None

        if next_url:
            # Determine application from the 'next' query argument.
            # FIXME: There should be a better way to get the app id.
            authorize_uri_params = parse_qs(urlparse(next_url).query)
            client_id = authorize_uri_params.get('client_id')

            if client_id and len(client_id):
                client_id = client_id[0].strip()

            if client_id:
                try:
                    app = get_application_model().objects.get(client_id=client_id)
                except get_application_model().DoesNotExist:
                    pass

                try:
                    oidc_client = Client.objects.get(client_id=client_id)
                except Client.DoesNotExist:
                    pass

        allowed_methods = None
        if app:
            allowed_methods = app.login_methods.all()
        elif oidc_client:
            try:
                client_options = OidcClientOptions.objects.get(oidc_client=oidc_client)
                allowed_methods = client_options.login_methods.all()
            except OidcClientOptions.DoesNotExist:
                pass

            self.return_to_rp_uri = get_return_to_rp_uri(request, authorize_uri_params)

        if allowed_methods is None:
            # Only allow the methods that do not require registered clients
            # (this might happen when a browser enters LoginView directly for
            # testing purposes).
            allowed_methods = LoginMethod.objects.filter(require_registered_client=False)

        login_methods = self.get_login_methods(request, allowed_methods, next_url)

        if len(login_methods) == 1:
            return redirect(login_methods[0].login_url)

        self.login_methods = login_methods
        return super(LoginView, self).get(request, *args, **kwargs)

    def get_context_data(self, **kwargs):
        context = super(LoginView, self).get_context_data(**kwargs)
        context['login_methods'] = self.login_methods
        context['return_to_rp_uri'] = self.return_to_rp_uri
        return context


def create_logout_response(request, user, backend_name, redirect_uri):
    backend = load_backend(load_strategy(request), backend_name, redirect_uri=None)

    # social_auth creates a new user for each (provider, uid) pair so
    # we don't need to worry about duplicates
    try:
        social_user = UserSocialAuth.objects.get(user=user, provider=backend_name)
    except UserSocialAuth.DoesNotExist:
        return None

    if not hasattr(backend, 'create_logout_response'):
        return None

    return backend.create_logout_response(social_user, redirect_uri)


class LogoutView(TemplateView):
    template_name = 'logout_done.html'

    def get(self, *args, **kwargs):
        user = self.request.user
        backend_name = None
        if user.is_authenticated:
            backend_name = self.request.session.get('social_auth_last_login_backend', None)

        if self.request.user.is_authenticated:
            auth_logout(self.request)

        redirect_uri = self.request.GET.get('next')
        if redirect_uri and not re.match(r'http[s]?://', redirect_uri):
            redirect_uri = None

        if backend_name:
            logout_response = create_logout_response(
                self.request, user, backend_name, redirect_uri
            )
            if logout_response is not None:
                return logout_response

        if redirect_uri:
            return redirect(redirect_uri)
        return super(LogoutView, self).get(*args, **kwargs)


class EmailNeededView(TemplateView):
    template_name = 'email_needed.html'

    def get_context_data(self, **kwargs):
        context = super(EmailNeededView, self).get_context_data(**kwargs)
        reauth_uri = self.request.GET.get('reauth_uri', '')
        if '//' in reauth_uri:  # Prevent open redirect
            reauth_uri = ''
        context['reauth_uri'] = reauth_uri
        return context


class AuthenticationErrorView(TemplateView):
    template_name = 'account/signup_closed.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        return context


class TunnistamoOidcAuthorizeView(AuthorizeView):
    def get(self, request, *args, **kwargs):
        request.GET = _extend_scope_in_query_params(request.GET)
        request_locales = [l.strip() for l in request.GET.get('ui_locales', '').split(' ') if l]
        available_locales = [l[0] for l in settings.LANGUAGES]

        for locale in request_locales:
            if locale in available_locales:
                break
        else:
            locale = None

        if locale:
            translation.activate(locale)

        resp = super().get(request, *args, **kwargs)
        if locale:
            # Save the UI language in a dedicated cookie, because the
            # session will be nuked if we go through the login view.
            resp.set_cookie(
                settings.LANGUAGE_COOKIE_NAME, locale,
                max_age=settings.LANGUAGE_COOKIE_AGE,
                path=settings.LANGUAGE_COOKIE_PATH,
                domain=settings.LANGUAGE_COOKIE_DOMAIN,
            )
        return resp

    def post(self, request, *args, **kwargs):
        request.POST = _extend_scope_in_query_params(request.POST)
        return super().post(request, *args, **kwargs)


class TunnistamoOidcEndSessionView(EndSessionView):
    def dispatch(self, request, *args, **kwargs):
        backend_name = None
        user = request.user
        if user.is_authenticated:
            backend_name = self.request.session.get('social_auth_last_login_backend', None)

        # clear Django session and get redirect URL
        response = super().dispatch(request, *args, **kwargs)

        if backend_name is not None:
            # If the backend supports logout, ask it to generate a logout
            # response to pass to the browser.
            backend_response = create_logout_response(request, user, backend_name, response.url)
            if backend_response is not None:
                response = backend_response

        return response


class TunnistamoOidcTokenView(View):
    def post(self, request, *args, **kwargs):
        token = TokenEndpoint(request)

        try:
            token.validate_params()

            dic = token.create_response_dic()

            # Django OIDC Provider doesn't support refresh token expiration (#230).
            # We don't supply refresh tokens when using restricted authentication methods.
            amr = JWT().unpack(dic['id_token']).payload().get('amr', '')
            for restricted_auth in settings.RESTRICTED_AUTHENTICATION_BACKENDS:
                if amr == locate(restricted_auth).name:
                    dic.pop('refresh_token')
                    break

            response = TokenEndpoint.response(dic)
            return response
        except oidc_errors.TokenError as error:
            return TokenEndpoint.response(error.create_dict(), status=400)
        except oidc_errors.UserAuthError as error:
            return TokenEndpoint.response(error.create_dict(), status=403)


def _extend_scope_in_query_params(query_params):
    scope = query_params.get('scope')
    if scope:
        query_params = query_params.copy()
        query_params['scope'] = _add_api_scopes(scope)
    return query_params


def _add_api_scopes(scope_string):
    scopes = scope_string.split()
    extended_scopes = ApiScope.extend_scope(scopes)
    return ' '.join(extended_scopes)


def show_profile(request):
    ATTR_NAMES = ['first_name', 'last_name', 'email', 'birthdate']

    user = request.user
    if user.is_authenticated:
        attrs = {user._meta.get_field(x).verbose_name: getattr(user, x) for x in ATTR_NAMES}
    else:
        attrs = {}
    return render(request, 'account/profile.html', context=dict(attrs=attrs))


class RememberMeView(View):
    @never_cache
    def post(self, request, *args, **kwargs):
        remember_me = request.POST.get('remember_me', '')
        if not remember_me:
            return HttpResponseBadRequest()
        if remember_me.strip().lower() == 'true':
            remember_me = True
        else:
            remember_me = False

        session = request.session
        session['remember_me'] = remember_me

        return HttpResponse()
