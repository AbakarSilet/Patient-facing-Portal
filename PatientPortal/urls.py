from django.contrib import admin
from django.urls import path, include

admin.site.site_header = "Patient Portal Administration"
admin.site.site_title = "Patient Portal Admin"
admin.site.index_title = "Administration"

urlpatterns = [
    path("admin/", admin.site.urls),
    path("accounts/", include("accounts.urls")),
    path("records/", include("records.urls")),
    path("appointments/", include("appointments.urls")),
    path("audit/", include("auditlog.urls")),

]