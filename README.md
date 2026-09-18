# Secure Patient-Facing Portal for Nigerian EHR Systems

MSc dissertation project (Ahmadu Bello University, Zaria) — a patient-facing
portal providing authenticated access to laboratory results and remote
appointment management, integrated with an existing OpenMRS-based Electronic
Health System.

## Overview

This is an academic proof-of-concept, not a production system. Security is
treated as a first-class design constraint rather than an afterthought: the
application is built against a STRIDE-based threat model and a derived
security requirements specification (REQ-01 to REQ-16), covering
authentication, access control, data protection, audit, and availability.

## Tech Stack

- **Backend**: Django (custom user model, role-based access)
- **Database**: PostgreSQL
- **EHR integration**: OpenMRS 2.13.0, accessed via FHIR R4 (lab results)
  and the classic REST API (appointment scheduling)
- **MFA**: django-otp (TOTP)
- **Configuration**: python-decouple (environment-based settings)

## Current Status

- [x] Patient self-registration with OpenMRS identity verification
      (identifier + date of birth) followed by phone-based OTP confirmation
- [x] MFA (TOTP) enforced on all protected views
- [x] Role distinction: patient vs. portal admin
- [ ] Lab results module — not yet implemented
- [ ] Appointment request/scheduling module — not yet implemented
- [ ] Security evaluation (OWASP ZAP + manual STRIDE-based testing) — pending

## Setup

### Prerequisites

- Python 3.x
- PostgreSQL
- A running OpenMRS instance (local development via the OpenMRS SDK)

### Installation

```bash
git clone <repo-url>
cd <repo-name>
python -m venv venv
source venv/bin/activate        # venv\Scripts\activate on Windows
pip install -r requirements.txt

cp .env.example .env
# Edit .env with your own local values. Never commit this file.

python manage.py migrate
python manage.py create_admin <username> <password>
python manage.py runserver
```

## Environment Variables

See `.env.example` for the full list (secret key, database credentials,
OpenMRS service account, SMS backend). No real values are committed to this
repository.

## Security Notes

- This project handles simulated patient data for academic purposes only.
- Certificates, `.env` files, and any credentials are excluded via
  `.gitignore` — see that file before your first commit, not after.
- The full threat model and security requirements specification are
  maintained separately from this repository.

## License

TBD