import re
import logging
import requests
from urllib.parse import urlencode

from datetime import date
from django import forms
from django.core.exceptions import ImproperlyConfigured
from django.utils.translation import ugettext_lazy as _
from django.urls import reverse
from django.shortcuts import render
from social_core.backends.legacy import LegacyAuth
from social_core.exceptions import AuthMissingParameter
from social_django.views import complete as complete_view


logger = logging.getLogger(__name__)


class APIError(Exception):
    pass


class AuthenticationFailed(Exception):
    pass


class AuroraLoginForm(forms.Form):
    borrower_card_id = forms.CharField(label=_("Library card identifier"), max_length=32)
    borrower_pin = forms.CharField(
        label=_("Card PIN"),
        max_length=4,
        widget=forms.TextInput(attrs={'type': 'password'})
    )


class AuroraAuth(LegacyAuth):
    name = 'axiell_aurora'
    ID_KEY = 'borrower_card_id'
    PIN_KEY = 'borrower_pin'
    FORM_HTML = 'axiell_aurora/login.html'

    def get_user_id(self, details, response):
        return response['PersonalInfo']['IdBorrower']

    def uses_redirect(self):
        return False

    def api_post(self, path, **kwargs):
        url = '%s/API/%s' % (self.setting('API_URL'), path)
        try:
            resp = requests.post(url, **kwargs)
            resp.raise_for_status()

        except requests.exceptions.RequestException as err:
            logger.exception('API call to %s failed' % path, exc_info=err)
            raise APIError('API call to %s failed: %s' % str(err))

        try:
            ret = resp.json()
        except TypeError as err:
            logger.exception('API returned invalid data', exc_info=err)
            raise APIError('API returned invalid JSON data: %s' % str(err))
        return ret

    def is_email_needed(self, **kwargs):
        return False

    def get_user_details(self, response):
        out = {}

        contact_info = response.get('ContactInfo', {})
        email = contact_info.get('Email', '').strip().lower() or None
        out['email'] = email

        personal_info = response.get('PersonalInfo', {})
        out['first_name'] = personal_info.get('FirstName', '').strip()
        out['last_name'] = personal_info.get('LastName', '').strip()

        birthdate = personal_info.get('BirthDate')
        if birthdate:
            m = re.match(r'([0-9]{4})([0-9]{2})([0-9]{2})', birthdate)
            if m:
                year, month, day = m.groups()
                out['birthdate'] = date(int(year), int(month), int(day))
            else:
                logger.error('Invalid birth date: %s' % birthdate)

        return out

    def start(self):
        request = self.strategy.request
        if request.method == 'POST':
            form = AuroraLoginForm(request.POST)
            if form.is_valid():
                try:
                    borrower_info = self.get_borrower_info(form.cleaned_data)
                    return complete_view(request, self.name, borrower_info=borrower_info)
                except APIError as err:
                    # Log to sentry
                    logger.exception('Unable to get borrower info', exc_info=err)
                    form.add_error(None, _('Library card login unavailable. Please try again later.'))
                except AuthenticationFailed:
                    form.add_error(None, _('Invalid card number or PIN'))
        else:
            form = AuroraLoginForm()

        login_method_uri = reverse('login')
        if 'next' in self.data:
            login_method_uri += '?' + urlencode({'next': self.data['next']})

        return render(request, self.FORM_HTML, {'form': form, 'login_method_uri': login_method_uri})

    def _validate_settings(self):
        REQUIRED_SETTINGS = ['API_URL', 'API_USERNAME', 'API_PASSWORD']
        for setting_name in REQUIRED_SETTINGS:
            if not self.setting(setting_name):
                raise ImproperlyConfigured('Required setting %s not found' % setting_name)

    def get_borrower_info(self, data):
        self._validate_settings()

        resp = self.api_post('StartApiSession', data=dict(
            Username=self.setting('API_USERNAME'),
            Password=self.setting('API_PASSWORD'))
        )

        message = resp.get('Message', '').strip()
        if message.lower() != 'logon done':
            # FIXME: Send to Sentry
            raise APIError('Unable to login to the Axiell API')
        guid = resp['Guid']

        data = dict(
            Guid=guid,
            BorrowerCard=self.data[self.ID_KEY].strip(),
            BorrowerPassword=self.data[self.PIN_KEY].strip(),
            IncludeInfo='true',
        )
        resp = self.api_post('BorrowerLogin', data=data)
        result = int(resp.get('Result'))
        if result != 1:
            raise AuthenticationFailed('BorrowerLogin returned %d: %s' % (result, resp.get('Message')))

        login_info = resp.get('LoginInfo', {})
        if not login_info:
            raise APIError('Missing data: LoginInfo')

        login_result = login_info.get('LoginResult')
        if not login_result:
            raise APIError('Missing data: LoginResult')

        borrower_info = resp.get('BorrowerInfo')
        if not borrower_info:
            raise APIError('Missing data: BorrowerInfo')

        personal_info = borrower_info.get('PersonalInfo', {})
        if not personal_info:
            raise APIError('Missing data: PersonalInfo')
        if not personal_info.get('IdBorrower'):
            raise APIError('Missing data: IdBorrower')

        return borrower_info

    def auth_complete(self, *args, **kwargs):
        borrower_info = kwargs.get('borrower_info')
        if not borrower_info:
            raise AuthMissingParameter(self, 'borrower_info')

        kwargs.update({'response': borrower_info, 'backend': self})
        return self.strategy.authenticate(*args, **kwargs)
