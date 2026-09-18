#accounts/decorators.py

from django.contrib.auth.decorators import login_required
from django_otp.decorators import otp_required


def portal_login_required(view_func):
    """
    Combine authentication + MFA enforcement (REQ-01) en un seul décorateur.

    À utiliser sur TOUTE vue touchant aux données du portail — jamais
    @login_required seul. Empiler deux décorateurs sur chaque vue, c'est
    exactement le genre de chose qu'on oublie sur la 5e vue en se
    dépêchant ; ça élimine le risque en le rendant impossible à
    appliquer à moitié.

    Ordre important : login_required s'exécute en premier (redirige
    l'anonyme vers login), otp_required ensuite (redirige le non-vérifié).
    """
    return login_required(otp_required(view_func, login_url='login'))