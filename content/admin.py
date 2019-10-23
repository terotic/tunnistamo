from django.contrib import admin
from parler.admin import TranslatableAdmin

from .models import GeneralContent


@admin.register(GeneralContent)
class GeneralContentAdmin(TranslatableAdmin):
    def has_delete_permission(self, request, obj=None):
        # Currently allow only one instance to exist, so deletion
        # is disallowed.
        return False

    def has_add_permission(self, request):
        # Currently allow only one instance to exist
        if GeneralContent.objects.exists():
            return False
        return super().has_add_permission(request)
