from django.db import models
from django.utils.translation import ugettext_lazy as _
from parler.models import TranslatableModel, TranslatedFields


class GeneralContent(TranslatableModel):
    translations = TranslatedFields(
        site_owner_name=models.CharField(max_length=100, verbose_name=_('site owner name')),
        privacy_policy_url=models.URLField(blank=True, verbose_name=_('privacy policy URL'))
    )

    def __str__(self):
        return self.site_owner_name

    class Meta:
        verbose_name = _('general content')
        verbose_name_plural = _('general contents')
