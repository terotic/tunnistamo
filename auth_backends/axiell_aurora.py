from social_core.backends.legacy import LegacyAuth
from social_core.exceptions import AuthMissingParameter, AuthFailed


class AuroraAuth(LegacyAuth):
    name = 'axiell_aurora'
    ID_KEY = 'borrower_card_id'
    PIN_KEY = 'borrower_pin'
    FORM_HTML = 'axiell_aurora/login.html'

    def get_user_id(self, details, response):
        return response.get('borrower_id')

    def auth_html(self):
        return self.strategy.render_html(tpl=self.FORM_HTML)

    def uses_redirect(self):
        return False

    def auth_complete(self, *args, **kwargs):
        """Completes login process, must return user instance"""
        if self.ID_KEY not in self.data:
            raise AuthMissingParameter(self, self.ID_KEY)
        if self.PIN_KEY not in self.data:
            raise AuthMissingParameter(self, self.PIN_KEY)

        #
        # FIXME: Do the POST
        #

        personal_info = {
            'IdBorrower': 1235575,
            'FirstName': 'Veijo',
            'LastName': 'Lainaaja',
            'BirthDate': '19520505',
        }
        contact_info = {
            'Email': 'veijo.lainaaja@example.com',
        }

        resp = dict(PersonalInfo=personal_info, ContactInfo=contact_info)

        if 'PersonalInfo' not in resp:
            raise AuthFailed(self, 'Invalid response from Aurora')
        kwargs.update({
            'borrower_id': self.data, 'backend': self
        })

        raise AuthFailed(self, 'moi')
