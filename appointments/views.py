#appointments/views.py

from django import forms
from django.shortcuts import render

from accounts.decorators import patient_required
from accounts.models import PatientProfile
from auditlog.models import AuditLogEntry
from auditlog.utils import get_client_ip
from openmrs_integration.client import OpenMRSClient, OpenMRSUnavailableError


class AppointmentRequestForm(forms.Form):
    appointment_type = forms.ChoiceField(label="Type de consultation")
    notes = forms.CharField(label="Motif", widget=forms.Textarea, required=False, max_length=500)

    def __init__(self, *args, appointment_types=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["appointment_type"].choices = [
            (t["uuid"], t["display"]) for t in (appointment_types or [])
        ]


@patient_required
def request_appointment(request):
    profile = PatientProfile.objects.get(user=request.user)
    client = OpenMRSClient(client_ip=get_client_ip(request))

    try:
        appointment_types = client.get_appointment_types().get("results", [])
    except OpenMRSUnavailableError:
        return render(request, "appointments/request_appointment.html", {
            "form": None,
            "error": "Le service de rendez-vous est temporairement indisponible. Réessaie dans quelques instants.",
        })

    if request.method == "POST":
        form = AppointmentRequestForm(request.POST, appointment_types=appointment_types)
        if form.is_valid():
            try:
                # REQ-05 : patient_uuid résolu côté serveur, jamais depuis le formulaire
                client.create_appointment_request(
                    patient_uuid=profile.openmrs_patient_uuid,
                    appointment_type_uuid=form.cleaned_data["appointment_type"],
                    notes=form.cleaned_data["notes"],
                )
            except OpenMRSUnavailableError:
                AuditLogEntry.objects.create(
                    user=request.user, action_type=AuditLogEntry.ActionType.REQUEST_APPOINTMENT,
                    target_reference=profile.openmrs_patient_uuid, ip_address=get_client_ip(request),
                    status=AuditLogEntry.Status.FAILURE,
                )
                return render(request, "appointments/request_appointment.html", {
                    "form": form, "appointment_types": appointment_types,
                    "error": "Le service de rendez-vous est temporairement indisponible. Réessaie dans quelques instants.",
                })

            AuditLogEntry.objects.create(
                user=request.user, action_type=AuditLogEntry.ActionType.REQUEST_APPOINTMENT,
                target_reference=profile.openmrs_patient_uuid, ip_address=get_client_ip(request),
                status=AuditLogEntry.Status.SUCCESS,
            )
            return render(request, "appointments/request_appointment.html", {
                "form": AppointmentRequestForm(appointment_types=appointment_types), "success": True,
            })
    else:
        form = AppointmentRequestForm(appointment_types=appointment_types)

    return render(request, "appointments/request_appointment.html", {"form": form})


