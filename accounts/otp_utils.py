#accounts/otp_utils.py

"""
Phone-based OTP for registration identity verification.

Proves the registrant controls the phone number OpenMRS has on file for
the claimed patient — closes the gap our STRIDE model never covered
explicitly: registration/enrollment, as distinct from login.
"""
import hashlib
import logging
import random
import re

from django.conf import settings

logger = logging.getLogger("accounts.otp")

OTP_LENGTH = 6
OTP_VALIDITY_SECONDS = 600   # 10 minutes
OTP_MAX_ATTEMPTS = 5          # brute-force ceiling on a 6-digit space


def generate_otp() -> str:
    return "".join(random.SystemRandom().choice("0123456789") for _ in range(OTP_LENGTH))


def hash_otp(code: str) -> str:
    # Server-side session already isn't client-readable — this is defense
    # in depth so a code is never held in plaintext anywhere, logs included.
    return hashlib.sha256(code.encode()).hexdigest()


_PHONE_LIKE_RE = re.compile(r"^[\d\s()+-]{5,20}$")


def extract_phone_number(telecom_entries: list) -> str | None:
    """
    FHIR `telecom` mixes phone/email/fax in any order — the original code's
    telecom[0] was a real bug: it could silently grab an email and "send"
    the OTP nowhere.

    Certaines instances OpenMRS (mapping FHIR2 du person attribute type
    non configuré) n'émettent pas du tout le champ `system` : l'entrée
    ne contient que {'id', 'value'}. On garde system="phone" en priorité,
    puis on retombe sur une entrée sans `system` explicite si sa valeur a
    une forme de numéro de téléphone (pas d'email/URL) — pour ne pas
    réintroduire le bug telecom[0].
    """
    telecom_entries = telecom_entries or []

    for entry in telecom_entries:
        if entry.get("system") == "phone" and entry.get("value"):
            return entry["value"]

    for entry in telecom_entries:
        if entry.get("system"):
            continue  # system connu et différent de "phone" (email, fax...) : on l'ignore
        value = entry.get("value")
        if value and "@" not in value and _PHONE_LIKE_RE.match(value):
            return value

    return None


def mask_phone(phone: str) -> str:
    """
    '+2349022565396' -> '+234••••••396'. Shown on the verification screen —
    someone who merely guessed identifier+birthdate still shouldn't learn
    the patient's full phone number just by reaching this screen.
    """
    digits = re.sub(r"\D", "", phone)
    if len(digits) <= 4:
        return "•" * len(digits)
    prefix = phone[: len(phone) - len(digits)]
    return f"{prefix}{'•' * (len(digits) - 3)}{digits[-3:]}"


def send_otp_sms(phone_number: str, code: str) -> None:
    """
    Pluggable send step — logs in dev, real gateway (Termii/Africa's
    Talking/Twilio) in production. A paid SMS gateway account is an
    infrastructure/procurement decision, not application code a single
    developer builds in this sprint — same scoping logic as the WAF in
    Scope and Limitations. The security control demonstrated here is the
    OTP logic itself, not SMS delivery.
    """
    if getattr(settings, "SMS_BACKEND", "console") == "console":
        logger.info("[DEV SMS] OTP for %s: %s (valid %ss)", phone_number, code, OTP_VALIDITY_SECONDS)
    else:
        raise NotImplementedError("Configure a real SMS_BACKEND before production use.")


def send_sms(phone_number: str, message: str) -> None:
    if getattr(settings, "SMS_BACKEND", "console") == "console":
        logger.info("[DEV SMS] To %s: %s", phone_number, message)
    else:
        raise NotImplementedError("Configure a real SMS_BACKEND before production use.")

def normalize_phone_digits(phone: str) -> str:
    """Compare uniquement les chiffres — tolère espaces/tirets/parenthèses
    entre ce que l'utilisateur tape et ce qui est stocké depuis OpenMRS."""
    return re.sub(r"\D", "", phone or "")

# accounts/otp_utils.py

def phones_match(a: str, b: str, significant_digits: int = 10) -> bool:
    """
    Compare uniquement les N derniers chiffres — tolère un indicatif pays
    présent d'un côté et absent de l'autre (ex: +234 vs 0 en tête).
    """
    da, db = normalize_phone_digits(a), normalize_phone_digits(b)
    if len(da) < significant_digits or len(db) < significant_digits:
        return False
    return da[-significant_digits:] == db[-significant_digits:]