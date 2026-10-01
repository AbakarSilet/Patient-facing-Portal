import sys
from base64 import b32encode

import qrcode
from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django_otp.plugins.otp_totp.models import TOTPDevice

from auditlog.models import AuditLogEntry

A = AuditLogEntry.ActionType
CLI_IP = "127.0.0.1"   # AuditLogEntry.ip_address est obligatoire ; ici l'action vient du shell
MAX_ATTEMPTS = 3


class Command(BaseCommand):
    help = (
        "Enrôle un authentificateur TOTP pour un compte admin (superuser créé "
        "depuis le terminal). L'accès shell au serveur tient lieu de preuve d'identité."
    )

    def add_arguments(self, parser):
        parser.add_argument("username")
        parser.add_argument(
            "--reset", action="store_true",
            help="Remplace l'appareil existant (téléphone perdu ou changé).",
        )
        parser.add_argument(
            "--light-terminal", action="store_true",
            help="QR code pour terminal à fond clair (par défaut : fond sombre).",
        )

    def handle(self, *args, username, reset, light_terminal, **options):
        if not sys.stdin.isatty():
            raise CommandError(
                "Terminal interactif requis : le secret ne doit être ni redirigé ni journalisé."
            )

        User = get_user_model()
        try:
            user = User.objects.get(**{User.USERNAME_FIELD: username})
        except User.DoesNotExist:
            raise CommandError("Utilisateur inconnu.")
        if not (user.is_active and user.is_staff):
            raise CommandError(
                "Réservé aux comptes staff/superuser actifs. "
                "Les patients s'enrôlent via le portail."
            )

        had_device = TOTPDevice.objects.filter(user=user, confirmed=True).exists()
        if had_device and not reset:
            raise CommandError(
                "Ce compte a déjà un appareil TOTP. Utilisez --reset s'il est perdu ou à remplacer."
            )

        # Aucun reliquat d'un enrôlement interrompu.
        TOTPDevice.objects.filter(user=user, confirmed=False).delete()
        device = TOTPDevice.objects.create(user=user, name="admin-cli", confirmed=False)

        self.stdout.write("\nScannez ce QR code avec votre application d'authentification :\n")
        qr = qrcode.QRCode(border=1)
        qr.add_data(device.config_url)
        qr.make(fit=True)
        # sys.stdout et non self.stdout : OutputWrapper ajoute un saut de ligne à chaque write().
        qr.print_ascii(out=sys.stdout, invert=not light_terminal)

        key = b32encode(device.bin_key).decode()
        groups = " ".join(key[i:i + 4] for i in range(0, len(key), 4))
        self.stdout.write(f"\nSaisie manuelle : {groups}\n")
        self.stdout.write(
            self.style.WARNING(
                "Ce secret n'est affiché qu'une fois. Effacez le terminal après l'enrôlement.\n"
            )
        )

        for _ in range(MAX_ATTEMPTS):
            token = input("Code à 6 chiffres affiché par l'application : ").strip()
            if device.verify_token(token):
                device.confirmed = True
                device.save()
                TOTPDevice.objects.filter(user=user).exclude(pk=device.pk).delete()
                if had_device:
                    self._log(user, A.MFA_DEVICE_RESET, device, AuditLogEntry.Status.SUCCESS)
                self._log(user, A.MFA_ENROLLED, device, AuditLogEntry.Status.SUCCESS)
                self.stdout.write(self.style.SUCCESS(
                    "Appareil enrôlé. Vous pouvez vous connecter à l'administration."
                ))
                return
            self._log(user, A.MFA_ENROLLMENT_FAILED, device, AuditLogEntry.Status.FAILURE)
            self.stderr.write("Code invalide.")

        device.delete()
        raise CommandError("Échec de l'enrôlement : trop de codes invalides. Relancez la commande.")

    @staticmethod
    def _log(user, action, device, status):
        AuditLogEntry.objects.create(
            user=user,
            action_type=action,
            target_reference=f"cli device={device.pk}",
            ip_address=CLI_IP,
            status=status,
        )
