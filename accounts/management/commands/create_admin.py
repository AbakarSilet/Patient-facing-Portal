from django.contrib.auth.hashers import make_password
from django.core.management.base import BaseCommand, CommandError

from accounts.models import PortalUser


class Command(BaseCommand):
    help = "Crée un compte administrateur (jamais via le formulaire d'inscription patient)."

    def add_arguments(self, parser):
        parser.add_argument("username")
        parser.add_argument("password")

    def handle(self, *args, **options):
        username = options["username"]
        if PortalUser.objects.filter(username=username).exists():
            raise CommandError(f"'{username}' existe déjà.")

        user = PortalUser.objects.create(
            username=username,
            password=make_password(options["password"]),
            role=PortalUser.Role.ADMIN,
        )
        self.stdout.write(self.style.SUCCESS(
            f"Compte admin '{username}' créé (id={user.id}). "
            f"Le MFA sera exigé à la première connexion via /mfa-setup/, comme pour un patient."
        ))