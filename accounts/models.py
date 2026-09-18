from django.contrib.auth.models import AbstractUser
from django.conf import settings
from django.db import models


class PortalUser(AbstractUser):
    class Role(models.TextChoices):
        PATIENT = "patient", "Patient"
        ADMIN = "admin", "Administrateur"

    role = models.CharField(max_length=10, choices=Role.choices)

    def is_patient_role(self) -> bool:
        return self.role == self.Role.PATIENT

    def is_admin_role(self) -> bool:
        return self.role == self.Role.ADMIN


class PatientProfile(models.Model):
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    openmrs_patient_uuid = models.CharField(max_length=36, unique=True)
    phone_number = models.CharField(max_length=20)
    created_at = models.DateTimeField(auto_now_add=True)

    # Preuve de consentement NDPA — capturée à l'instant de la case cochée,
    # pas à la création du compte (qui arrive après l'OTP, plus tard).
    consented_at = models.DateTimeField(null=True, blank=True)
    consent_ip_address = models.GenericIPAddressField(null=True, blank=True)
    privacy_policy_version = models.CharField(max_length=20, blank=True)

    def __str__(self):
        return f"{self.user.username} -> OpenMRS {self.openmrs_patient_uuid}"


class AccountErasureRequest(models.Model):
    """
    Trace la demande d'effacement NDPA elle-même — indépendamment des
    AuditLogEntry, jamais modifiées. C'est la preuve de conformité :
    quand la demande a été faite, quand elle a été exécutée.
    """
    user = models.OneToOneField(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="erasure_request")
    requested_at = models.DateTimeField(auto_now_add=True)
    scheduled_for = models.DateTimeField()
    executed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        status = "exécutée" if self.executed_at else "en attente"
        return f"Effacement {status} — {self.user_id} (prévu {self.scheduled_for:%Y-%m-%d})"