#appointments/views.py

from django import forms
from django.core.exceptions import PermissionDenied
from django.http import HttpResponseNotAllowed
from django.urls import reverse
from django.shortcuts import render, redirect
from django.contrib import messages

from accounts.decorators import patient_required
from accounts.models import PatientProfile
from auditlog.models import AuditLogEntry
from auditlog.utils import get_client_ip
from openmrs_integration.client import OpenMRSClient, OpenMRSUnavailableError


class AppointmentRequestForm(forms.Form):
    TIMEFRAME_UNIT_CHOICES = [
        ("", "---------"),
        ("DAYS", "Day(s)"),
        ("WEEKS", "Week(s)"),
        ("MONTHS", "Month(s)"),
        ("YEARS", "Year(s)"),
    ]

    appointment_type = forms.ChoiceField(label="Consultation type")
    notes = forms.CharField(label="Reason for visit", widget=forms.Textarea, required=False, max_length=500)
    min_timeframe_value = forms.IntegerField(label="Minimum timeframe", required=False, min_value=0)
    min_timeframe_units = forms.ChoiceField(label="Unit (minimum)", choices=TIMEFRAME_UNIT_CHOICES, required=False)
    max_timeframe_value = forms.IntegerField(label="Maximum timeframe", required=False, min_value=0)
    max_timeframe_units = forms.ChoiceField(label="Unit (maximum)", choices=TIMEFRAME_UNIT_CHOICES, required=False)

    def __init__(self, *args, appointment_types=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["appointment_type"].choices = [
            (t["uuid"], t["display"]) for t in (appointment_types or [])
        ]

    def clean(self):
        cleaned = super().clean()
        for prefix in ("min", "max"):
            value = cleaned.get(f"{prefix}_timeframe_value")
            units = cleaned.get(f"{prefix}_timeframe_units")
            if value and not units:
                self.add_error(f"{prefix}_timeframe_units", "Please specify a unit if you provide a value.")
            if units and value is None:
                self.add_error(f"{prefix}_timeframe_value", "Please specify a value if you provide a unit.")
        return cleaned

@patient_required
def request_appointment(request):
    profile = PatientProfile.objects.get(user=request.user)
    client = OpenMRSClient(client_ip=get_client_ip(request))

    try:
        appointment_types = client.get_appointment_types().get("results", [])
    except OpenMRSUnavailableError:
        return render(request, "appointments/request_appointment.html", {
            "form": None,
            "error": "The appointment service is temporarily unavailable. Please try again in a few moments.",
        })

    if request.method == "POST":
        form = AppointmentRequestForm(request.POST, appointment_types=appointment_types)
        if form.is_valid():
            try:
                # REQ-05: patient_uuid resolved server-side, never from the form
                client.create_appointment_request(
                    patient_uuid=profile.openmrs_patient_uuid,
                    appointment_type_uuid=form.cleaned_data["appointment_type"],
                    notes=form.cleaned_data["notes"],
                    min_timeframe_value=form.cleaned_data.get("min_timeframe_value"),
                    min_timeframe_units=form.cleaned_data.get("min_timeframe_units") or None,
                    max_timeframe_value=form.cleaned_data.get("max_timeframe_value"),
                    max_timeframe_units=form.cleaned_data.get("max_timeframe_units") or None,
                )
            except OpenMRSUnavailableError:
                AuditLogEntry.objects.create(
                    user=request.user,
                    action_type=AuditLogEntry.ActionType.REQUEST_APPOINTMENT,
                    target_reference=profile.openmrs_patient_uuid,
                    ip_address=get_client_ip(request),
                    status=AuditLogEntry.Status.FAILURE,
                )
                return render(request, "appointments/request_appointment.html", {
                    "form": form,
                    "appointment_types": appointment_types,
                    "error": "The appointment service is temporarily unavailable. Please try again in a few moments.",
                })

            AuditLogEntry.objects.create(
                user=request.user,
                action_type=AuditLogEntry.ActionType.REQUEST_APPOINTMENT,
                target_reference=profile.openmrs_patient_uuid,
                ip_address=get_client_ip(request),
                status=AuditLogEntry.Status.SUCCESS,
            )

            messages.success(request, "Your appointment request was submitted successfully — pending staff confirmation.")
            return redirect("my_appointment_requests")
    else:
        form = AppointmentRequestForm(appointment_types=appointment_types)

    return render(request, "appointments/request_appointment.html", {"form": form})

STATUS_LABELS = {
    "PENDING": "Pending",
    "FULFILLED": "Fulfilled",
    "CANCELLED": "Cancelled",
}


def _extract_appointment_request(resource):
    appointment_type = resource.get("appointmentType", {}).get("display", "Unknown")

    min_value = resource.get("minTimeFrameValue")
    min_units = resource.get("minTimeFrameUnits")
    max_value = resource.get("maxTimeFrameValue")
    max_units = resource.get("maxTimeFrameUnits")
    if min_value and max_value:
        timeframe = f"{min_value} {min_units} – {max_value} {max_units}"
    elif max_value:
        timeframe = f"Avant {max_value} {max_units}"
    else:
        timeframe = ""
    
    return {
        "uuid": resource.get("uuid", ""),
        "appointment_type": appointment_type,
        "status": resource.get("status", ""),
        "requested_on": resource.get("requestedOn", ""),
        "notes": resource.get("notes", ""),
        "timeframe": timeframe,
    }


@patient_required
def my_appointment_requests(request):
    profile = PatientProfile.objects.get(user=request.user)
    client = OpenMRSClient(client_ip=get_client_ip(request))

    try:
        raw_requests = client.get_appointment_requests_for_patient(profile.openmrs_patient_uuid)
    except OpenMRSUnavailableError:
        return render(request, "appointments/my_requests.html", {
            "requests": [],
            "error": "The appointment service is temporarily unavailable. Please try again in a few moments.",
        })

    requests_list = sorted(
        (_extract_appointment_request(r) for r in raw_requests),
        key=lambda r: r["requested_on"], reverse=True,
    )

    AuditLogEntry.objects.create(
        user=request.user, action_type=AuditLogEntry.ActionType.VIEW_APPOINTMENTS,
        target_reference=profile.openmrs_patient_uuid, ip_address=get_client_ip(request),
        status=AuditLogEntry.Status.SUCCESS,
    )

    return render(request, "appointments/my_requests.html", {"requests": requests_list})


@patient_required
def cancel_appointment_request(request, request_uuid):
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    request_uuid = str(request_uuid)
    profile = PatientProfile.objects.get(user=request.user)
    client = OpenMRSClient(client_ip=get_client_ip(request))

    try:
        own_requests = client.get_appointment_requests_for_patient(profile.openmrs_patient_uuid)
    except OpenMRSUnavailableError:
        return redirect(f"{reverse('my_appointment_requests')}?error=unavailable")

    # REQ-05 : on ne fait jamais confiance à l'UUID fourni dans l'URL —
    # on vérifie qu'il appartient au patient authentifié avant d'agir.
    matching = next((r for r in own_requests if r["uuid"] == request_uuid), None)
    if matching is None:
        raise PermissionDenied
    if matching.get("status") != "PENDING":
        return redirect(f"{reverse('my_appointment_requests')}?error=not_pending")

    try:
        client.cancel_appointment_request(request_uuid)
    except OpenMRSUnavailableError:
        return redirect(f"{reverse('my_appointment_requests')}?error=unavailable")

    AuditLogEntry.objects.create(
        user=request.user, action_type=AuditLogEntry.ActionType.CANCEL_APPOINTMENT_REQUEST,
        target_reference=request_uuid, ip_address=get_client_ip(request),
        status=AuditLogEntry.Status.SUCCESS,
    )
    return redirect("my_appointment_requests")



