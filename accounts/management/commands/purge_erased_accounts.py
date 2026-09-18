from django.core.management.base import BaseCommand
from django.utils import timezone
from django_otp.plugins.otp_totp.models import TOTPDevice

from accounts.models import AccountErasureRequest, PatientProfile
from auditlog.models import AuditLogEntry

SYSTEM_IP = "0.0.0.0"  # même sentinelle que _get_client_ip pour "pas de client réel"


class Command(BaseCommand):
    help = "Anonymise définitivement les comptes dont le délai de grâce NDPA est écoulé."

    def handle(self, *args, **options):
        due = list(
            AccountErasureRequest.objects.filter(
                executed_at__isnull=True, scheduled_for__lte=timezone.now()
            ).select_related("user")
        )

        for erasure_request in due:
            user = erasure_request.user

            TOTPDevice.objects.filter(user=user).delete()

            try:
                profile = user.patientprofile
                profile.phone_number = ""  # openmrs_patient_uuid conservé (décision produit)
                profile.save(update_fields=["phone_number"])
            except PatientProfile.DoesNotExist:
                pass

            user.username = f"deleted-user-{user.pk}"
            user.first_name = ""
            user.last_name = ""
            user.email = ""
            user.set_unusable_password()
            user.is_erased = True
            user.save()

            erasure_request.executed_at = timezone.now()
            erasure_request.save(update_fields=["executed_at"])

            # Ajout d'un événement, jamais une modification des logs existants.
            AuditLogEntry.objects.create(
                user=user, action_type=AuditLogEntry.ActionType.DATA_ERASURE_COMPLETED,
                target_reference=f"erasure_request_id={erasure_request.pk}",
                ip_address=SYSTEM_IP, status=AuditLogEntry.Status.SUCCESS,
            )

        self.stdout.write(self.style.SUCCESS(f"{len(due)} compte(s) anonymisé(s)."))