import requests
from django.shortcuts import render
import requests
from django.shortcuts import render, get_object_or_404


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


def _display(codeable, default="Unknown"):
    """Safe text from a FHIR CodeableConcept; never raises on missing/empty coding."""
    if not codeable:
        return default
    if codeable.get("text"):
        return codeable["text"]
    codings = codeable.get("coding") or []
    return (codings[0].get("display") or default) if codings else default


def _is_displayable(resource):
    """Whitelist gate: never show OperationOutcome or entered-in-error records to a patient."""
    if resource.get("resourceType") == "OperationOutcome":
        return False
    if resource.get("status") == "entered-in-error":
        return False
    codings = (resource.get("verificationStatus") or {}).get("coding") or []
    return not any(c.get("code") == "entered-in-error" for c in codings)


def _extract_allergy(resource):
    reactions = resource.get("reaction") or []
    severity, manifestations = "", []
    if reactions:
        severity = reactions[0].get("severity", "")
        manifestations = [_display(m, "") for m in reactions[0].get("manifestation", [])]
    return {
        "substance": _display(resource.get("code")),
        "clinical_status": _display(resource.get("clinicalStatus"), ""),
        "criticality": resource.get("criticality", ""),
        "manifestations": ", ".join(m for m in manifestations if m),
        "severity": severity,
        "recorded_date": resource.get("recordedDate", ""),
    }


def _extract_condition(resource):
    return {
        "name": _display(resource.get("code")),
        "clinical_status": _display(resource.get("clinicalStatus"), ""),
        "onset": resource.get("onsetDateTime", ""),
        "recorded_date": resource.get("recordedDate", ""),
    }


def _extract_medication(resource):
    med = (resource.get("medicationReference") or {}).get("display") \
        or _display(resource.get("medicationCodeableConcept"))
    dosage = (resource.get("dosageInstruction") or [{}])[0].get("text", "")
    return {
        "medication": med,
        "status": resource.get("status", ""),
        "dosage": dosage,
        "authored_on": resource.get("authoredOn", ""),
    }


def _extract_encounter(resource):
    period = resource.get("period") or {}
    locations = resource.get("location") or []
    location = (locations[0].get("location") or {}).get("display", "") if locations else ""
    types = resource.get("type") or [{}]
    return {
        "type": _display(types[0], "Visit"),
        "start": period.get("start", ""),
        "end": period.get("end", ""),
        "location": location,
        "status": resource.get("status", ""),
    }
    # Provider names deliberately omitted (data minimisation). Add if your supervisor wants them.


SECTIONS = [
    # (template context key, OpenMRSClient method, extractor)
    ("lab_results", "get_lab_results_for_patient", _extract_lab_result),
    ("allergies",   "get_allergies_for_patient",   _extract_allergy),
    ("conditions",  "get_conditions_for_patient",  _extract_condition),
    ("medications", "get_medication_requests_for_patient", _extract_medication),
    ("encounters",  "get_encounters_for_patient",  _extract_encounter),
]


@patient_required
def health_records(request):
    profile = get_object_or_404(PatientProfile, user=request.user)
    client = OpenMRSClient(client_ip=get_client_ip(request))
    context = {"unavailable": [], "truncated": []}
    loaded = []

    for key, method_name, extractor in SECTIONS:
        try:
            bundle = getattr(client, method_name)(profile.openmrs_patient_uuid)
        except requests.exceptions.RequestException:
            context[key] = []
            context["unavailable"].append(key)      # vuln19, per section
            continue
        resources = [e["resource"] for e in bundle.get("entry", []) if "resource" in e]
        context[key] = [extractor(r) for r in resources if _is_displayable(r)]
        if bundle.get("truncated"):
            context["truncated"].append(key)
        loaded.append(key)

    AuditLogEntry.objects.create(
        user=request.user,
        action_type=AuditLogEntry.ActionType.VIEW_RECORD,
        # which categories were actually disclosed, useful for NDPA s.40 traceability
        target_reference=f"{profile.openmrs_patient_uuid}|{','.join(loaded)}"[:255],
        ip_address=get_client_ip(request),
        status=AuditLogEntry.Status.SUCCESS if loaded else AuditLogEntry.Status.FAILURE,
    )
    return render(request, "records/health_records.html", context)



