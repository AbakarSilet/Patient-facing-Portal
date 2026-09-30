from django.contrib import admin

from .models import AuditLogEntry, OpenMRSRequestLog


class ReadOnlyAdmin(admin.ModelAdmin):
    """Un journal d'audit ne se modifie ni ne se supprime, même depuis l'admin."""

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def has_delete_permission(self, request, obj=None):
        return False


@admin.register(AuditLogEntry)
class AuditLogEntryAdmin(ReadOnlyAdmin):
    list_display = ("timestamp", "user", "username_snapshot", "action_type", "status", "ip_address")
    list_filter = ("action_type", "status")
    search_fields = ("user__username", "username_snapshot", "ip_address", "target_reference")
    date_hierarchy = "timestamp"
    list_select_related = ("user",)


@admin.register(OpenMRSRequestLog)
class OpenMRSRequestLogAdmin(ReadOnlyAdmin):
    list_display = ("timestamp", "method", "endpoint", "status_code", "duration_ms")
    list_filter = ("method", "status_code")
    search_fields = ("endpoint",)
    date_hierarchy = "timestamp"