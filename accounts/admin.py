# accounts/admin.py

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin

from auditlog.models import AuditLogEntry
from .models import AccountErasureRequest, PortalUser, PatientProfile


@admin.register(PortalUser)
class PortalUserAdmin(UserAdmin):
    list_display = ("username", "email", "role", "is_staff", "is_active")
    list_filter = ("role", "is_staff", "is_active")
    fieldsets = UserAdmin.fieldsets + (
        ("Rôle", {"fields": ("role",)}),
    )
    add_fieldsets = UserAdmin.add_fieldsets + (
        ("Rôle", {"fields": ("role",)}),
    )


@admin.register(PatientProfile)
class PatientProfileAdmin(admin.ModelAdmin):
    list_display = ("user", "openmrs_patient_uuid", "phone_number", "created_at", "consented_at", "privacy_policy_version")
    search_fields = ("user__username", "openmrs_patient_uuid", "phone_number")
    readonly_fields = ("created_at", "consented_at", "consent_ip_address", "privacy_policy_version")



@admin.register(AccountErasureRequest)
class AccountErasureRequestAdmin(admin.ModelAdmin):
    list_display = ("user", "requested_at", "scheduled_for", "executed_at")
    list_filter = ("executed_at",)
    actions = ["cancel_erasure"]

    def cancel_erasure(self, request, queryset):
        cancelled = 0
        for erasure_request in queryset.filter(executed_at__isnull=True):
            user = erasure_request.user
            user.is_active = True
            user.save(update_fields=["is_active"])
            AuditLogEntry.objects.create(
                user=user, action_type=AuditLogEntry.ActionType.DATA_ERASURE_CANCELLED,
                ip_address=request.META.get("REMOTE_ADDR", "0.0.0.0"), status=AuditLogEntry.Status.SUCCESS,
            )
            erasure_request.delete()
            cancelled += 1
        self.message_user(request, f"{cancelled} demande(s) annulée(s).")
    cancel_erasure.short_description = "Annuler la demande de suppression (réactive le compte)"