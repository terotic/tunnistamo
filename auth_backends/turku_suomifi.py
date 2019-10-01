import re
import base64
import json
import uuid
import hashlib
from urllib.parse import urlencode
from datetime import datetime, date

import requests
from django.http import HttpResponse
from django.core.exceptions import ImproperlyConfigured
from django.urls import reverse
from social_core.backends.legacy import LegacyAuth
from social_core.exceptions import AuthMissingParameter, AuthFailed


class TurkuSuomiFiAuth(LegacyAuth):
    name = 'turku_suomifi'

    def uses_redirect(self):
        return False

    def is_email_needed(self, **kwargs):
        return False

    def get_user_id(self, details, response):
        return response['oid']

    def get_user_details(self, response):
        out = {}
        attrs = response['attributes']
        out['first_name'] = attrs.get('firstName', None)
        out['last_name'] = attrs.get('sn', None)
        birthdate = attrs.get('nationalIdentificationNumber', '')
        if birthdate:
            m = re.match(r'([0-9]{2})([0-9]{2})([0-9]{2})([+-])', birthdate)
            if not m:
                raise AuthFailed(self, 'Invalid birth date: %s' % birthdate)
            day, month, year, century = m.groups()
            if century == '+':
                year = '20' + year
            else:
                year = '19' + year
            out['birthdate'] = date(int(year), int(month), int(day))
        return out

    def api_post(self, path):
        url = '%s/%s' % (self.setting('API_URL'), path)
        now = datetime.utcnow().isoformat().split('.')[0] + 'Z'
        message_id = 'T' + str(uuid.uuid4())
        sp_name = self.setting('SP_NAME')

        callback_url = reverse('social:complete', kwargs=dict(backend=self.name))
        callback_url = self.strategy.build_absolute_uri(callback_url)

        data = {
            'message_id': message_id,
            'callback_url': callback_url,
            'timestamp': now,
            'language': 'fi',
        }
        msg = json.dumps(data)
        msg_body = urlencode({
            'SAMLRequest': base64.b64encode(msg.encode('utf8')).decode('utf8'),
            'RelayState': 'abdefg',
        })
        auth_line = (sp_name + now + msg_body + self.setting('API_KEY')).encode('utf8')
        auth = hashlib.sha256(auth_line).hexdigest()
        headers = {
            'X-TURKU-SP': sp_name,
            'X-TURKU-TS': now,
            'Authorization': auth,
            'Content-Type': 'application/x-www-form-urlencoded'
        }

        resp = requests.post(url, headers=headers, data=msg_body)
        return resp

    def auth_html(self):
        REQUIRED_SETTINGS = ['API_URL', 'API_KEY', 'SP_NAME']
        for setting_name in REQUIRED_SETTINGS:
            if not self.setting(setting_name):
                raise ImproperlyConfigured('Required setting %s not found' % setting_name)

        resp = self.api_post('esuomifi/v1/authnrequest/simple')
        resp.raise_for_status()

        return HttpResponse(resp.content)

    def auth_complete(self, *args, **kwargs):
        if 'SAMLResponse' not in self.data:
            raise AuthMissingParameter(self, 'SAMLResponse')

        resp = base64.b64decode(self.data['SAMLResponse']).decode('utf8')
        data = json.loads(resp)
        status_code = data.get('status_code', '')
        if status_code.lower() != 'success':
            raise AuthFailed(self, 'Authentication unsuccessful: %s' % status_code)

        oid = data.get('oid', '')
        if not oid:
            raise AuthMissingParameter(self, 'oid')

        response = {
            'oid': oid,
            'attributes': data.get('attributes', {}),
            'session_index': data.get('session_index', ''),
        }
        kwargs.update({'response': response, 'backend': self})
        return self.strategy.authenticate(*args, **kwargs)
