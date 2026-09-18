# auditlog/admin.py

from django.contrib import admin
from .models import AuditLogEntry


@admin.register(AuditLogEntry)
class AuditLogEntryAdmin(admin.ModelAdmin):
    list_display = ("timestamp", "user", "action_type", "status", "target_reference", "ip_address")
    list_filter = ("action_type", "status")
    search_fields = ("user__username", "target_reference", "ip_address")
    date_hierarchy = "timestamp"
    readonly_fields = [f.name for f in AuditLogEntry._meta.fields]

    # Un journal d'audit ne se modifie ni ne se supprime depuis l'admin —
    # cohérent avec on_delete=PROTECT sur `user` dans le modèle.
    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


