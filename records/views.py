import requests
from django.shortcuts import render

from accounts.decorators import portal_login_required, patient_required
from accounts.models import PatientProfile
from auditlog.models import AuditLogEntry
from openmrs_integration.client import OpenMRSClient
from auditlog.utils import get_client_ip


def _extract_lab_result(observation):
    coding = observation.get("code", {}).get("coding", [{}])
    code = observation.get("code", {}).get("text") or (coding[0].get("display", "Unknown") if coding else "Unknown")

    if "valueQuantity" in observation:
        value = observation["valueQuantity"].get("value")
        unit = observation["valueQuantity"].get("unit", "")
    elif "valueCodeableConcept" in observation:
        vcc = observation["valueCodeableConcept"]
        vcc_coding = vcc.get("coding", [{}])
        value = vcc.get("text") or (vcc_coding[0].get("display", "N/A") if vcc_coding else "N/A")
        unit = ""
    elif "valueString" in observation:
        value = observation["valueString"]
        unit = ""
    else:
        value = "N/A"
        unit = ""

    return {
        "code": code,
        "value": value,
        "unit": unit,
        "effective_datetime": observation.get("effectiveDateTime", ""),
        "status": observation.get("status", ""),
    }


def _extract_allergy(resource):
    coding = resource.get("code", {}).get("coding", [{}])
    substance = coding[0].get("display", "Unknown") if coding else "Unknown"

    clinical_status = resource.get("clinicalStatus", {}).get("text") or (
        resource.get("clinicalStatus", {}).get("coding", [{}])[0].get("display", "")
    )

    reactions = resource.get("reaction", [])
    manifestations = []
    severity = ""
    if reactions:
        severity = reactions[0].get("severity", "")
        for m in reactions[0].get("manifestation", []):
            m_coding = m.get("coding", [{}])
            if m_coding:
                manifestations.append(m_coding[0].get("display", ""))

    return {
        "substance": substance,
        "clinical_status": clinical_status,
        "criticality": resource.get("criticality", ""),
        "manifestations": ", ".join(manifestations),
        "severity": severity,
        "recorded_date": resource.get("recordedDate", ""),
    }


@patient_required
def health_records(request):
    profile = PatientProfile.objects.get(user=request.user)
    client = OpenMRSClient()

    try:
        lab_bundle = client.get_lab_results_for_patient(profile.openmrs_patient_uuid)
        allergy_bundle = client.get_allergies_for_patient(profile.openmrs_patient_uuid)
    except requests.exceptions.RequestException:
        AuditLogEntry.objects.create(
            user=request.user,
            action_type=AuditLogEntry.ActionType.VIEW_RECORD,
            target_reference=profile.openmrs_patient_uuid,
            ip_address=get_client_ip(request),
            status=AuditLogEntry.Status.FAILURE,
        )
        return render(request, "records/health_records.html", {
            "lab_results": [],
            "allergies": [],
            "error": "Le service de dossiers médicaux est temporairement indisponible. Réessaie dans quelques instants.",
        })

    lab_results = [_extract_lab_result(e["resource"]) for e in lab_bundle.get("entry", [])]
    allergies = [_extract_allergy(e["resource"]) for e in allergy_bundle.get("entry", [])]

    AuditLogEntry.objects.create(
        user=request.user,
        action_type=AuditLogEntry.ActionType.VIEW_RECORD,
        target_reference=profile.openmrs_patient_uuid,
        ip_address=get_client_ip(request),
        status=AuditLogEntry.Status.SUCCESS,
    )

    return render(request, "records/health_records.html", {
        "lab_results": lab_results,
        "allergies": allergies,
    })