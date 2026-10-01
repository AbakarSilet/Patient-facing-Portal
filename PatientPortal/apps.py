from django.contrib.admin.apps import AdminConfig


class PortalAdminConfig(AdminConfig):
    """
    À mettre dans INSTALLED_APPS à la place de "django.contrib.admin".
    Ce fichier va dans le package principal du projet (celui de settings.py).
    """

    default_site = f"{__package__}.admin_site.PortalAdminSite"
