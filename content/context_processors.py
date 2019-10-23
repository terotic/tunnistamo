from .models import GeneralContent


def general_content(request):
    # Only one instance of GeneralContent is allowed for now
    general_content = GeneralContent.objects.first()
    return dict(general_content=general_content)
