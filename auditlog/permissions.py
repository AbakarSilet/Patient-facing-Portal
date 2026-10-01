from django.contrib.auth.mixins import UserPassesTestMixin
from django.contrib.auth.views import redirect_to_login
from django.urls import reverse
from django.utils.cache import add_never_cache_headers


def is_site_admin(user):
    """
    Point unique de définition du « rôle admin » : superuser ET session
    vérifiée par un second facteur (django-otp).
    Fail-closed : sans OTPMiddleware, `is_verified` n'existe pas -> refus.
    """
    is_verified = getattr(user, "is_verified", None)
    return bool(
        user.is_authenticated
        and user.is_active
        and user.is_superuser
        and callable(is_verified)
        and is_verified()
    )


class AdminRequiredMixin(UserPassesTestMixin):
    """
    Anonyme -> login ; non-admin connecté -> 403 ;
    superuser sans second facteur vérifié -> login admin (avec retour ici).
    Doit être placé en PREMIER dans les bases de la vue.
    """

    def test_func(self):
        return is_site_admin(self.request.user)

    def handle_no_permission(self):
        user = self.request.user
        if user.is_authenticated and user.is_superuser:
            return redirect_to_login(self.request.get_full_path(), reverse("admin:login"))
        return super().handle_no_permission()

    def dispatch(self, request, *args, **kwargs):
        response = super().dispatch(request, *args, **kwargs)
        # Données sensibles : jamais de cache navigateur/proxy.
        add_never_cache_headers(response)
        return response