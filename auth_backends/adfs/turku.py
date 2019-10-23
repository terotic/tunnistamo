from social_core.backends.saml import SAMLAuth


class TurkuADFS(SAMLAuth):
    name = 'turku_adfs'
