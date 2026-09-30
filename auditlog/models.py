# auditlog/models.py

from django.conf import settings
from django.db import models


class AuditLogEntry(models.Model):
    class ActionType(models.TextChoices):
        LOGIN = "LOGIN", "Login"
        LOGIN_FAILED = "LOGIN_FAILED", "Failed login attempt"
        VIEW_RECORD = "VIEW_RECORD", "Viewed health record"
        REQUEST_APPOINTMENT = "REQUEST_APPOINTMENT", "Requested appointment"
        ACCOUNT_LINKED = "ACCOUNT_LINKED", "Account linked to OpenMRS patient"
        REGISTRATION_IDENTITY_FAILED = "REGISTRATION_IDENTITY_FAILED", "Registration identity check failed"
        REGISTRATION_OTP_SENT = "REGISTRATION_OTP_SENT", "Registration OTP sent"
        REGISTRATION_OTP_FAILED = "REGISTRATION_OTP_FAILED", "Registration OTP verification failed"
        REGISTRATION_OTP_LOCKED = "REGISTRATION_OTP_LOCKED", "Registration OTP attempts exhausted"
        MFA_ENROLLED = "MFA_ENROLLED", "MFA device enrolled"
        PASSWORD_RESET_REQUESTED = "PASSWORD_RESET_REQUESTED", "Password reset requested"
        PASSWORD_RESET_OTP_FAILED = "PASSWORD_RESET_OTP_FAILED", "Password reset OTP failed"
        PASSWORD_RESET_LOCKED = "PASSWORD_RESET_LOCKED", "Password reset OTP attempts exhausted"
        PASSWORD_RESET_SUCCESS = "PASSWORD_RESET_SUCCESS", "Password reset succeeded"
        PASSWORD_RESET_IDENTITY_FAILED = "PASSWORD_RESET_IDENTITY_FAILED", "Password reset identity check failed"
        USERNAME_CHANGED = "USERNAME_CHANGED", "Username changed"
        PASSWORD_CHANGED = "PASSWORD_CHANGED", "Password changed from profile"
        PROFILE_UPDATED = "PROFILE_UPDATED", "Profile information updated"
        DATA_ERASURE_REQUESTED = "DATA_ERASURE_REQUESTED", "Account deletion requested (NDPA)"
        DATA_ERASURE_COMPLETED = "DATA_ERASURE_COMPLETED", "Account anonymized after grace period"
        DATA_ERASURE_CANCELLED = "DATA_ERASURE_CANCELLED", "Deletion request cancelled"
        MFA_RECOVERY_OTP_SENT = "MFA_RECOVERY_OTP_SENT", "MFA recovery code sent"
        MFA_RECOVERY_OTP_FAILED = "MFA_RECOVERY_OTP_FAILED", "Invalid MFA recovery code"
        MFA_RECOVERY_OTP_LOCKED = "MFA_RECOVERY_OTP_LOCKED", "MFA recovery locked (attempts exhausted)"
        MFA_DEVICE_RESET = "MFA_DEVICE_RESET", "TOTP device reset after loss"
        LOGIN_OTP_LOCKED = "LOGIN_OTP_LOCKED", "TOTP login locked (attempts exhausted)"
        CONSENT_RECORDED = "CONSENT_RECORDED", "Privacy policy consent recorded"
        MFA_ENROLLMENT_FAILED = "MFA_ENROLLMENT_FAILED", "Invalid TOTP code during enrollment"
        AUDIT_LOG_EXPORTED = "AUDIT_LOG_EXPORTED", "Audit logs exported"
        AUDIT_LOG_VIEWED = "AUDIT_LOG_VIEWED", "Audit logs viewed"
        VIEW_APPOINTMENTS = "VIEW_APPOINTMENTS", "Viewed appointment requests"
        CANCEL_APPOINTMENT_REQUEST = "CANCEL_APPOINTMENT_REQUEST", "Cancelled appointment request"



    class Status(models.TextChoices):
        SUCCESS = "SUCCESS", "Success"
        FAILURE = "FAILURE", "Failure"

    # CASCADE -> PROTECT : supprimer un compte ne doit jamais supprimer
    # silencieusement son propre historique d'audit.
    # null=True : nécessaire pour ce correctif — les événements
    # pré-compte (échec identité, OTP envoyé/raté) n'ont pas encore
    # d'utilisateur à qui les rattacher.
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.PROTECT, null=True, blank=True,
    )
    action_type = models.CharField(max_length=30, choices=ActionType.choices)
    target_reference = models.CharField(max_length=255, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField()
    status = models.CharField(max_length=10, choices=Status.choices)
    username_snapshot = models.CharField(max_length=150, blank=True)


    def __str__(self):
        return f"{self.timestamp} - {self.user} - {self.action_type} - {self.status}"

    def save(self, *args, **kwargs):
        # Rempli automatiquement : aucun point d'appel existant à modifier.
        if self._state.adding and self.user_id and not self.username_snapshot:
            self.username_snapshot = self.user.get_username()
        super().save(*args, **kwargs)

    class Meta:
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["user", "-timestamp"]),
            models.Index(fields=["action_type", "-timestamp"]),
        ]


class OpenMRSRequestLog(models.Model):
    """
    REQ-14 : trace chaque appel sortant vers OpenMRS — jamais le payload
    patient lui-même (éviterait de dupliquer le stockage de PHI).
    """
    timestamp = models.DateTimeField(auto_now_add=True)
    method = models.CharField(max_length=10)
    endpoint = models.CharField(max_length=255)
    status_code = models.PositiveSmallIntegerField(null=True, blank=True)  # null si exception réseau avant réponse
    duration_ms = models.PositiveIntegerField(null=True, blank=True)
    triggered_by_ip = models.GenericIPAddressField(null=True, blank=True)  # IP du visiteur à l'origine de l'appel, si connue

    class Meta:
        ordering = ["-timestamp"]

    def __str__(self):
        return f"{self.timestamp} {self.method} {self.endpoint} -> {self.status_code}"



