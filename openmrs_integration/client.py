#openmrs_integration/client.py

import requests
from decouple import config

BASE_URL = config('OPENMRS_BASE_URL')
AUTH = (config('OPENMRS_API_USER'), config('OPENMRS_API_PASSWORD'))
TIMEOUT = 10


class OpenMRSClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.auth = AUTH

    def get_patient_by_uuid(self, uuid):
        url = f"{BASE_URL}/ws/fhir2/R4/Patient/{uuid}"
        response = self.session.get(url, timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()

    def find_patient_by_identifier(self, identifier):
        url = f"{BASE_URL}/ws/fhir2/R4/Patient"
        response = self.session.get(url, params={"identifier": identifier}, timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()