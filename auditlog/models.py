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
        USERNAME_CHANGED = "USERNAME_CHANGED", "Nom d'utilisateur modifié"
        PASSWORD_CHANGED = "PASSWORD_CHANGED", "Mot de passe modifié depuis le profil"
        PROFILE_UPDATED = "PROFILE_UPDATED", "Informations de profil modifiées"
        DATA_ERASURE_REQUESTED = "DATA_ERASURE_REQUESTED", "Suppression de compte demandée (NDPA)"
        DATA_ERASURE_COMPLETED = "DATA_ERASURE_COMPLETED", "Compte anonymisé après délai de grâce"
        DATA_ERASURE_CANCELLED = "DATA_ERASURE_CANCELLED", "Demande de suppression annulée"
        MFA_RECOVERY_OTP_SENT = "MFA_RECOVERY_OTP_SENT", "Code de récupération MFA envoyé"
        MFA_RECOVERY_OTP_FAILED = "MFA_RECOVERY_OTP_FAILED", "Code de récupération MFA invalide"
        MFA_RECOVERY_OTP_LOCKED = "MFA_RECOVERY_OTP_LOCKED", "Récupération MFA verrouillée (tentatives épuisées)"
        MFA_DEVICE_RESET = "MFA_DEVICE_RESET", "Device TOTP réinitialisé après perte"
        LOGIN_OTP_LOCKED = "LOGIN_OTP_LOCKED", "Verrouillage TOTP au login (tentatives épuisées)"
        CONSENT_RECORDED = "CONSENT_RECORDED", "Consentement à la politique de confidentialité enregistré"
        

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

    def __str__(self):
        return f"{self.timestamp} - {self.user} - {self.action_type} - {self.status}"