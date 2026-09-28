#openmrs_integration/client.py

import logging
import time
from datetime import datetime, timezone

import requests
from decouple import config

from PatientPortal.settings import CA_BUNDLE_PATH
from auditlog.models import OpenMRSRequestLog

logger = logging.getLogger("openmrs_integration")

BASE_URL = config('OPENMRS_BASE_URL')
AUTH = (config('OPENMRS_API_USER'), config('OPENMRS_API_PASSWORD'))
TIMEOUT = 10


class OpenMRSClient:
    def __init__(self, client_ip=None):
        self.session = requests.Session()
        self.session.auth = AUTH
        self.client_ip = client_ip  # IP du visiteur à l'origine de l'appel — REQ-14
        # REQ-10 : épingle un CA spécifique quand OpenMRS est joint en HTTPS
        # et qu'un bundle est configuré — jamais verify=False. Non exercé
        # dans l'environnement de dev actuel (OpenMRS tourne en HTTP simple,
        # cf. limite Section 3.3).
        if BASE_URL.startswith("https://") and CA_BUNDLE_PATH:
            self.session.verify = CA_BUNDLE_PATH

    def _request(self, method, url, **kwargs):
        start = time.monotonic()
        status_code = None
        try:
            try:
                response = self.session.request(method, url, timeout=TIMEOUT, **kwargs)
            except requests.exceptions.RequestException as exc:
                raise OpenMRSUnavailableError(f"{method} {url}: {exc}") from exc
            status_code = response.status_code
            try:
                response.raise_for_status()
            except requests.exceptions.HTTPError as exc:
                raise requests.exceptions.HTTPError(
                    f"{exc} — body: {response.text[:500]}", response=response
                ) from exc
            return response
        finally:
            duration_ms = int((time.monotonic() - start) * 1000)
            try:
                OpenMRSRequestLog.objects.create(
                    method=method, endpoint=url, status_code=status_code,
                    duration_ms=duration_ms, triggered_by_ip=self.client_ip,
                )
            except Exception:
                logger.exception("Échec d'écriture OpenMRSRequestLog pour %s %s", method, url)

    def get_patient_by_uuid(self, uuid):
        url = f"{BASE_URL}/ws/fhir2/R4/Patient/{uuid}"
        return self._request("GET", url).json()

    def find_patient_by_identifier(self, identifier):
        url = f"{BASE_URL}/ws/fhir2/R4/Patient"
        return self._request("GET", url, params={"identifier": identifier}).json()

    def _search_for_patient(self, resource_type, patient_uuid, max_pages=5, **extra_params):
        """
        Paginated FHIR search scoped to one patient, routed through
        _request() so REQ-14 logging applies uniformly. Replaces direct
        self.session.get() calls that were invisible to the audit trail
        and silently truncated results beyond the first page.
        """
        url = f"{BASE_URL}/ws/fhir2/R4/{resource_type}"
        params = {"patient": patient_uuid, "_count": 100, **extra_params}
        entries, pages, truncated = [], 0, False
        while url and pages < max_pages:
            response = self._request("GET", url, params=params if pages == 0 else None)
            bundle = response.json()
            entries.extend(bundle.get("entry", []))
            next_link = next((l["url"] for l in bundle.get("link", [])
                               if l.get("relation") == "next"), None)
            if next_link and not next_link.startswith(BASE_URL):
                truncated = True  # never follow a next-link outside the configured host
                break
            url, params = next_link, None
            pages += 1
            if url:
                truncated = pages >= max_pages
        return {"entry": entries, "truncated": truncated}

    def get_observations_for_patient(self, patient_uuid):
        return self._search_for_patient("Observation", patient_uuid)

    def get_lab_results_for_patient(self, patient_uuid):
        return self._search_for_patient("Observation", patient_uuid, category="laboratory")

    def get_allergies_for_patient(self, patient_uuid):
        return self._search_for_patient("AllergyIntolerance", patient_uuid)

    def get_encounters_for_patient(self, patient_uuid):
        return self._search_for_patient("Encounter", patient_uuid)

    def get_conditions_for_patient(self, patient_uuid):
        return self._search_for_patient("Condition", patient_uuid)

    def get_medication_requests_for_patient(self, patient_uuid):
        return self._search_for_patient("MedicationRequest", patient_uuid)


####### Appointment #######

    def get_appointment_types(self):
        url = f"{BASE_URL}/ws/rest/v1/appointmentscheduling/appointmenttype"
        return self._request("GET", url).json()


    def create_appointment_request(self, patient_uuid, appointment_type_uuid, notes=""):
        url = f"{BASE_URL}/ws/rest/v1/appointmentscheduling/appointmentrequest"
        now = datetime.now(timezone.utc)
        requested_on = now.strftime('%Y-%m-%dT%H:%M:%S.') + f'{now.microsecond // 1000:03d}' + now.strftime('%z')
        payload = {
            "patient": patient_uuid,
            "appointmentType": appointment_type_uuid,
            "status": "PENDING",
            "requestedOn": requested_on,
            "notes": notes,
        }
        return self._request("POST", url, json=payload).json()

    def get_appointment_requests_for_patient(self, patient_uuid):
        url = f"{BASE_URL}/ws/rest/v1/appointmentscheduling/appointmentrequest"
        response = self._request("GET", url, params={"v": "full"})
        all_requests = response.json().get("results", [])
        return [r for r in all_requests if r.get("patient", {}).get("uuid") == patient_uuid]


class OpenMRSUnavailableError(Exception):
    """
    Levée uniquement sur échec réseau (timeout, connexion refusée) —
    jamais sur une réponse HTTP d'erreur d'OpenMRS (4xx/5xx), qui reste
    une HTTPError normale pour que l'appelant distingue "OpenMRS a
    répondu non" de "OpenMRS est injoignable".
    """
    pass