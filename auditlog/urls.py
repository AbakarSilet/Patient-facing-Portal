from django.urls import path

from . import views

app_name = "auditlog"

urlpatterns = [
    path("", views.DashboardView.as_view(), name="dashboard"),
    path("logs/", views.AuditLogListView.as_view(), name="entry_list"),
    path("logs/export/", views.AuditLogExportView.as_view(), name="entry_export"),
    path("users/<str:username>/", views.AuditLogListView.as_view(), name="user_entry_list"),
    path("users/<str:username>/export/", views.AuditLogExportView.as_view(), name="user_entry_export"),
    path("openmrs/", views.OpenMRSLogListView.as_view(), name="openmrs_list"),
    path("openmrs/export/", views.OpenMRSLogExportView.as_view(), name="openmrs_export"),
]

# Projet : path("audit/", include("auditlog.urls")),
