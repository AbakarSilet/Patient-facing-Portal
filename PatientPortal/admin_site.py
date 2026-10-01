from django_otp.admin import OTPAdminSite


class PortalAdminSite(OTPAdminSite):
    """
    Site d'administration qui exige un second facteur (OTP) en plus du mot de
    passe : un compte sans appareil OTP vérifié est traité comme non-staff.
    """

    # OTPAdminSite utilise 'otpadmin' par défaut, ce qui casse le namespace
    # 'admin' (reverse(), thème, liens). On le conserve.
    name = "admin"

    def __init__(self, name="admin"):
        super().__init__(name)
