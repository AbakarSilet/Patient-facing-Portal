#openmrs_integration/client.py

import logging
import time

import requests
from decouple import config

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

    def _request(self, method, url, **kwargs):
        """
        REQ-14 : chaque appel sortant est loggé — méthode, endpoint,
        statut, durée — qu'il réussisse, échoue en HTTP (4xx/5xx) ou
        échoue au niveau réseau (timeout, connexion). Jamais le corps
        de la réponse : on ne duplique pas le stockage de PHI ici.
        """
        start = time.monotonic()
        status_code = None
        try:
            response = self.session.request(method, url, timeout=TIMEOUT, **kwargs)
            status_code = response.status_code
            response.raise_for_status()
            return response
        finally:
            duration_ms = int((time.monotonic() - start) * 1000)
            try:
                OpenMRSRequestLog.objects.create(
                    method=method,
                    endpoint=url,
                    status_code=status_code,
                    duration_ms=duration_ms,
                    triggered_by_ip=self.client_ip,
                )
            except Exception:
                # Un échec d'écriture du log ne doit jamais masquer une
                # vraie exception réseau/HTTP déjà en cours de propagation.
                logger.exception("Échec d'écriture OpenMRSRequestLog pour %s %s", method, url)

    def get_patient_by_uuid(self, uuid):
        url = f"{BASE_URL}/ws/fhir2/R4/Patient/{uuid}"
        return self._request("GET", url).json()

    def find_patient_by_identifier(self, identifier):
        url = f"{BASE_URL}/ws/fhir2/R4/Patient"
        return self._request("GET", url, params={"identifier": identifier}).json()

    def get_observations_for_patient(self, patient_uuid):
        url = f"{BASE_URL}/ws/fhir2/R4/Observation"
        response = self.session.get(url, params={"patient": patient_uuid}, timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()

    def get_lab_results_for_patient(self, patient_uuid):
        url = f"{BASE_URL}/ws/fhir2/R4/Observation"
        response = self.session.get(
            url, params={"patient": patient_uuid, "category": "laboratory"}, timeout=TIMEOUT
        )
        response.raise_for_status()
        return response.json()

    def get_allergies_for_patient(self, patient_uuid):
        url = f"{BASE_URL}/ws/fhir2/R4/AllergyIntolerance"
        response = self.session.get(url, params={"patient": patient_uuid}, timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()

    def get_encounters_for_patient(self, patient_uuid):
        url = f"{BASE_URL}/ws/fhir2/R4/Encounter"
        response = self.session.get(url, params={"patient": patient_uuid}, timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()

    def get_conditions_for_patient(self, patient_uuid):
        url = f"{BASE_URL}/ws/fhir2/R4/Condition"
        response = self.session.get(url, params={"patient": patient_uuid}, timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()

    def get_medication_requests_for_patient(self, patient_uuid):
        url = f"{BASE_URL}/ws/fhir2/R4/MedicationRequest"
        response = self.session.get(url, params={"patient": patient_uuid}, timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()