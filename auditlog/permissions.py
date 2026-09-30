from django.contrib.auth.mixins import UserPassesTestMixin
from django.utils.cache import add_never_cache_headers


def is_site_admin(user):
    """
    Point unique de définition du « rôle admin ».
    Fail-closed : superuser uniquement. Si vous avez un champ de rôle
    personnalisé, remplacez par ex. par `user.role == "ADMIN"`.
    """
    return user.is_authenticated and user.is_active and user.is_superuser


class AdminRequiredMixin(UserPassesTestMixin):
    """
    Anonyme -> redirection vers le login ; connecté non-admin -> 403.
    Doit être placé en PREMIER dans les bases de la vue.
    """

    def test_func(self):
        return is_site_admin(self.request.user)

    def dispatch(self, request, *args, **kwargs):
        response = super().dispatch(request, *args, **kwargs)
        # Données sensibles : jamais de cache navigateur/proxy.
        add_never_cache_headers(response)
        return response