#accounts/views.py
import base64
from datetime import datetime, timedelta
from io import BytesIO
from urllib.parse import urlencode

import qrcode
import qrcode.image.svg
import requests
from django_otp.plugins.otp_totp.models import TOTPDevice
from django_ratelimit.decorators import ratelimit

from django.conf import settings
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import AuthenticationForm, PasswordChangeForm
from django.contrib.auth.hashers import make_password
from django.contrib.auth.models import User
from django.db import IntegrityError, transaction
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme

from auditlog.models import AuditLogEntry
from auditlog.utils import get_client_ip
from openmrs_integration.client import OpenMRSClient

from .decorators import portal_login_required
from .forms import (
    AccountDeletionRequestForm,
    OTPVerifyForm,
    PasswordResetConfirmForm,
    PasswordResetRequestForm,
    PatientRegistrationForm,
    ProfileInfoForm,
    UsernameChangeForm,
)
from .models import AccountErasureRequest, PatientProfile, PortalUser
from .otp_utils import (
    OTP_MAX_ATTEMPTS,
    OTP_VALIDITY_SECONDS,
    extract_phone_number,
    generate_otp,
    hash_otp,
    mask_phone,
    normalize_phone_digits,
    phones_match,
    send_otp_sms,
    send_sms,
)

@ratelimit(key='ip', rate='20/h', method='POST', block=False)
@ratelimit(key='post:openmrs_identifier', rate='5/h', method='POST', block=False)
def register(request):
    error = None

    if request.method == "POST":
        if getattr(request, "limited", False):
            return render(request, "accounts/register.html", {
                "form": PatientRegistrationForm(request.POST),
                "error": "Trop de tentatives. Réessaie dans quelques instants.",
            })

        form = PatientRegistrationForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data["username"]

            if PortalUser.objects.filter(username=username).exists():
                error = "Ce nom d'utilisateur est déjà pris. Choisis-en un autre."
            else:
                identifier = form.cleaned_data["openmrs_identifier"]
                birthdate = form.cleaned_data["birthdate"]

                try:
                    bundle = OpenMRSClient(client_ip=get_client_ip(request)).find_patient_by_identifier(identifier)
                except requests.exceptions.RequestException:
                    return render(request, "accounts/register.html", {
                        "form": form,
                        "error": "Service d'identification temporairement indisponible. Réessaie dans quelques instants.",
                    })

                matched_patient = None
                if bundle.get("total") == 1:
                    resource = bundle["entry"][0]["resource"]
                    if resource.get("birthDate") == birthdate.isoformat():
                        matched_patient = resource

                already_linked = matched_patient and PatientProfile.objects.filter(
                    openmrs_patient_uuid=matched_patient["id"]
                ).exists()

                if not matched_patient or already_linked:
                    # Seule cette partie reste générique — c'est la seule
                    # qui touche à des données patient sensibles.
                    error = "Impossible de vérifier votre identité avec les informations fournies."
                    AuditLogEntry.objects.create(
                        user=None, action_type=AuditLogEntry.ActionType.REGISTRATION_IDENTITY_FAILED,
                        target_reference=identifier, ip_address=get_client_ip(request),
                        status=AuditLogEntry.Status.FAILURE,
                    )
                else:
                    phone = extract_phone_number(matched_patient.get("telecom"))
                    if not phone:
                        error = "Impossible de vérifier votre identité automatiquement. Merci de contacter l'accueil."
                    else:
                        code = generate_otp()
                        request.session["pending_registration"] = {
                            "username": username,
                            "password_hash": make_password(form.cleaned_data["password1"]),
                            "openmrs_patient_uuid": matched_patient["id"],
                            "phone": phone,
                            "phone_masked": mask_phone(phone),
                            "otp_hash": hash_otp(code),
                            "otp_expires_at": (timezone.now() + timedelta(seconds=OTP_VALIDITY_SECONDS)).isoformat(),
                            "otp_attempts": 0,
                            "consent_at": timezone.now().isoformat(),
                            "consent_ip": get_client_ip(request),
                            "privacy_policy_version": settings.PRIVACY_POLICY_VERSION,
                        }
                        send_otp_sms(phone, code)
                        AuditLogEntry.objects.create(
                            user=None, action_type=AuditLogEntry.ActionType.REGISTRATION_OTP_SENT,
                            target_reference=matched_patient["id"], ip_address=get_client_ip(request),
                            status=AuditLogEntry.Status.SUCCESS,
                        )
                        return redirect("verify_registration_otp")
    else:
        form = PatientRegistrationForm()

    return render(request, "accounts/register.html", {"form": form, "error": error})

def verify_registration_otp(request):
    """
    Step 2 of 2. The User + PatientProfile rows are created here, only
    after OTP success — this is the actual security gate, not step 1.
    """
    pending = request.session.get("pending_registration")
    if not pending:
        return redirect("register")

    error = None
    expires_at = datetime.fromisoformat(pending["otp_expires_at"])

    if request.method == "POST":
        if timezone.now() > expires_at:
            del request.session["pending_registration"]
            return redirect("register")

        if pending["otp_attempts"] >= OTP_MAX_ATTEMPTS:
            del request.session["pending_registration"]
            AuditLogEntry.objects.create(
                user=None, action_type=AuditLogEntry.ActionType.REGISTRATION_OTP_LOCKED,
                target_reference=pending["openmrs_patient_uuid"], ip_address=get_client_ip(request),
                status=AuditLogEntry.Status.FAILURE,
            )
            return redirect("register")

        form = OTPVerifyForm(request.POST)
        if form.is_valid():
            token = form.cleaned_data["token"]
            if hash_otp(token) == pending["otp_hash"]:
                try:
                    with transaction.atomic():
                        user = PortalUser(
                            username=pending["username"],
                            password=pending["password_hash"],
                            role=PortalUser.Role.PATIENT,   # explicite, jamais par défaut
                        )
                        user.save()
                        PatientProfile.objects.create(
                            user=user,
                            openmrs_patient_uuid=pending["openmrs_patient_uuid"],
                            phone_number=pending["phone"],
                            consented_at=datetime.fromisoformat(pending["consent_at"]),
                            consent_ip_address=pending["consent_ip"],
                            privacy_policy_version=pending["privacy_policy_version"],
                        )
                        AuditLogEntry.objects.create(
                            user=user, action_type=AuditLogEntry.ActionType.CONSENT_RECORDED,
                            target_reference=pending["privacy_policy_version"],
                            ip_address=pending["consent_ip"], status=AuditLogEntry.Status.SUCCESS,
                        )
                except IntegrityError:
                    # Rare race: username taken between step 1 and step 2.
                    del request.session["pending_registration"]
                    return render(request, "accounts/register.html", {
                        "form": PatientRegistrationForm(),
                        "error": "Ce nom d'utilisateur vient d'être pris. Merci de recommencer.",
                    })
                del request.session["pending_registration"]
                auth_login(request, user, backend="django.contrib.auth.backends.ModelBackend")
                request.session["identity_proof_at"] = timezone.now().isoformat()
                return redirect("mfa_setup")
            else:
                pending["otp_attempts"] += 1
                request.session["pending_registration"] = pending
                remaining = OTP_MAX_ATTEMPTS - pending["otp_attempts"]
                error = f"Code invalide ({remaining} tentative(s) restante(s))."
                AuditLogEntry.objects.create(
                    user=None, action_type=AuditLogEntry.ActionType.REGISTRATION_OTP_FAILED,
                    target_reference=pending["openmrs_patient_uuid"], ip_address=get_client_ip(request),
                    status=AuditLogEntry.Status.FAILURE,
                )
    else:
        form = OTPVerifyForm()

    return render(request, "accounts/verify_registration_otp.html", {
        "form": form, "error": error, "phone_masked": pending["phone_masked"],
    })


MFA_ENROLLMENT_TRUST_WINDOW = timedelta(minutes=5)

def _has_fresh_identity_proof(request) -> bool:
    proof_at_raw = request.session.get("identity_proof_at")
    if not proof_at_raw:
        return False
    return (timezone.now() - datetime.fromisoformat(proof_at_raw)) < MFA_ENROLLMENT_TRUST_WINDOW


@ratelimit(key='user', rate='3/h', method='GET', block=False)
def _mfa_enrollment_phone_gate(request):
    try:
        phone = request.user.patientprofile.phone_number
    except PatientProfile.DoesNotExist:
        return render(request, "accounts/mfa_setup_error.html", {
            "error": "Impossible de vérifier votre identité automatiquement. Contactez un administrateur.",
        })

    pending = request.session.get("pending_mfa_enrollment_otp")
    error = None

    if request.method == "POST":
        if not pending:
            return redirect("mfa_setup")
        if timezone.now() > datetime.fromisoformat(pending["expires_at"]):
            del request.session["pending_mfa_enrollment_otp"]
            return redirect("mfa_setup")
        if pending["attempts"] >= OTP_MAX_ATTEMPTS:
            del request.session["pending_mfa_enrollment_otp"]
            return redirect("mfa_setup")

        form = OTPVerifyForm(request.POST)
        if form.is_valid():
            if hash_otp(form.cleaned_data["token"]) == pending["otp_hash"]:
                del request.session["pending_mfa_enrollment_otp"]
                request.session["identity_proof_at"] = timezone.now().isoformat()
                return redirect("mfa_setup")  # repasse par mfa_setup, fenêtre désormais fraîche
            pending["attempts"] += 1
            request.session["pending_mfa_enrollment_otp"] = pending
            error = f"Code invalide ({OTP_MAX_ATTEMPTS - pending['attempts']} tentative(s) restante(s))."
    else:
        if getattr(request, "limited", False):
            return render(request, "accounts/mfa_setup_error.html", {
                "error": "Trop de demandes de code. Réessaie dans une heure.",
            })
        code = generate_otp()
        pending = {
            "otp_hash": hash_otp(code),
            "expires_at": (timezone.now() + timedelta(seconds=OTP_VALIDITY_SECONDS)).isoformat(),
            "attempts": 0,
        }
        request.session["pending_mfa_enrollment_otp"] = pending
        send_otp_sms(phone, code)

    return render(request, "accounts/mfa_setup_verify_phone.html", {
        "form": OTPVerifyForm(), "error": error, "phone_masked": mask_phone(phone),
    })

@ratelimit(key='ip', rate='30/h', method='POST', block=False)
@ratelimit(key='user', rate='15/h', method='POST', block=False)
@login_required
def mfa_setup(request):
    if TOTPDevice.objects.filter(user=request.user, confirmed=True).exists():
        return redirect("dashboard" if request.user.is_verified() else "otp_verify")

    if not _has_fresh_identity_proof(request):
        return _mfa_enrollment_phone_gate(request)

    device, _ = TOTPDevice.objects.get_or_create(
        user=request.user, confirmed=False, defaults={"name": "default"}
    )

    error = None
    if request.method == "POST":
        if getattr(request, "limited", False):
            error = "Too many attempts. Please try again later."
        else:
            token = request.POST.get("token", "")
            if device.verify_token(token):
                device.confirmed = True
                device.save()
                request.session.pop("identity_proof_at", None)
                from django_otp import login as otp_login
                otp_login(request, device)
                AuditLogEntry.objects.create(
                    user=request.user, action_type=AuditLogEntry.ActionType.MFA_ENROLLED,
                    target_reference=str(device.id), ip_address=get_client_ip(request),
                    status=AuditLogEntry.Status.SUCCESS,
                )
                return redirect("dashboard")
            error = "Code invalide, réessaie."
            AuditLogEntry.objects.create(
                user=request.user, action_type=AuditLogEntry.ActionType.MFA_ENROLLMENT_FAILED,
                target_reference=str(device.id), ip_address=get_client_ip(request),
                status=AuditLogEntry.Status.FAILURE,
            )

    img = qrcode.make(device.config_url)
    buf = BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return render(request, "accounts/mfa_setup.html", {"qr_b64": qr_b64, "error": error})

@portal_login_required
def dashboard(request):
    return render(request, "accounts/dashboard.html")


@ratelimit(key='ip', rate='30/h', method='POST', block=False)
@ratelimit(key='post:username', rate='10/h', method='POST', block=False)
def login_view(request):
    error = None
    if request.method == "POST":
        if getattr(request, "limited", False):
            error = "Too many attempts. Please try again later."
            form = AuthenticationForm(request)
        else:
            form = AuthenticationForm(request, data=request.POST)
            if form.is_valid():
                user = form.get_user()
                auth_login(request, user, backend="django.contrib.auth.backends.ModelBackend")

                next_url = request.POST.get("next") or request.GET.get("next")
                safe_next = next_url if next_url and url_has_allowed_host_and_scheme(
                    next_url, allowed_hosts={request.get_host()}, require_https=request.is_secure()
                ) else ""

                # MFA is ALWAYS inserted before the final destination —
                # never shortcut to `next` here, otherwise we bypass
                # otp_verify and fall back into the observed loop.
                otp_url = reverse("otp_verify")
                if safe_next:
                    otp_url = f"{otp_url}?{urlencode({'next': safe_next})}"
                return redirect(otp_url)

            error = "Invalid credentials."
            attempted_username = request.POST.get("username", "")
            AuditLogEntry.objects.create(
                user=PortalUser.objects.filter(username=attempted_username).first(),
                action_type=AuditLogEntry.ActionType.LOGIN_FAILED,
                target_reference=attempted_username,
                ip_address=get_client_ip(request), status=AuditLogEntry.Status.FAILURE,
            )
    else:
        form = AuthenticationForm()

    return render(request, "accounts/login.html", {
        "form": form, "error": error, "next": request.GET.get("next", ""),
    })

OTP_VERIFY_SESSION_KEY = "otp_verify_attempts"


@ratelimit(key='ip', rate='40/h', method='POST', block=False)
@ratelimit(key='user', rate='20/h', method='POST', block=False)
@login_required
def otp_verify(request):
    next_url = request.POST.get("next") or request.GET.get("next")
    safe_next = next_url if next_url and url_has_allowed_host_and_scheme(
        next_url, allowed_hosts={request.get_host()}, require_https=request.is_secure()
    ) else ""

    if request.user.is_verified():
        return redirect(safe_next or "dashboard")

    device = TOTPDevice.objects.filter(user=request.user, confirmed=True).first()
    if not device:
        return redirect("mfa_setup")

    error = None
    if request.method == "POST":
        if getattr(request, "limited", False):
            return render(request, "accounts/otp_verify.html", {
                "form": OTPVerifyForm(), "error": "Too many attempts. Please try again later.", "next": safe_next,
            })

        attempts = request.session.get(OTP_VERIFY_SESSION_KEY, 0)
        if attempts >= OTP_MAX_ATTEMPTS:
            AuditLogEntry.objects.create(
                user=request.user, action_type=AuditLogEntry.ActionType.LOGIN_OTP_LOCKED,
                ip_address=get_client_ip(request), status=AuditLogEntry.Status.FAILURE,
            )
            auth_logout(request)
            return render(request, "accounts/otp_verify_locked.html")

        form = OTPVerifyForm(request.POST)
        if form.is_valid():
            token = form.cleaned_data["token"]
            if device.verify_token(token):
                request.session.pop(OTP_VERIFY_SESSION_KEY, None)
                from django_otp import login as otp_login
                otp_login(request, device)
                AuditLogEntry.objects.create(
                    user=request.user, action_type=AuditLogEntry.ActionType.LOGIN,
                    ip_address=get_client_ip(request), status=AuditLogEntry.Status.SUCCESS,
                )
                return redirect(safe_next or "dashboard")
            attempts += 1
            request.session[OTP_VERIFY_SESSION_KEY] = attempts
            remaining = OTP_MAX_ATTEMPTS - attempts
            error = f"Invalid code ({remaining} attempt(s) remaining)."
            AuditLogEntry.objects.create(
                user=request.user, action_type=AuditLogEntry.ActionType.OTP_VERIFICATION_FAILED,
                ip_address=get_client_ip(request), status=AuditLogEntry.Status.FAILURE,
            )
    else:
        form = OTPVerifyForm()
    return render(request, "accounts/otp_verify.html", {"form": form, "error": error, "next": safe_next})


def logout_view(request):
    auth_logout(request)
    return redirect("login")


@ratelimit(key='ip', rate='20/h', method='POST', block=False)
@ratelimit(key='post:username', rate='5/h', method='POST', block=False)
@ratelimit(key='post:phone_number', rate='5/h', method='POST', block=False)
def forgot_password(request):
    """
    Exige username + téléphone (même principe que identifiant+birthdate
    dans register()) : connaître seulement le username ne suffit plus à
    déclencher un SMS vers quelqu'un d'autre. Message d'erreur fusionné
    volontairement — jamais laquelle des deux infos est fausse.
    """
    error = None

    if request.method == "POST":
        form = PasswordResetRequestForm(request.POST)
        if form.is_valid():
            if getattr(request, "limited", False):
                error = "Too many attempts. Please try again later."
            else:
                username = form.cleaned_data["username"]
                submitted_phone = normalize_phone_digits(form.cleaned_data["phone_number"])

                user = PortalUser.objects.filter(username=username, is_active=True).first()
                matched = False
                if user:
                    try:
                        stored_phone = normalize_phone_digits(user.patientprofile.phone_number)
                        matched = phones_match(form.cleaned_data["phone_number"], user.patientprofile.phone_number)
                    except PatientProfile.DoesNotExist:
                        matched = False

                if matched:
                    code = generate_otp()
                    request.session["pending_password_reset"] = {
                        "user_id": user.id,
                        "otp_hash": hash_otp(code),
                        "otp_expires_at": (timezone.now() + timedelta(seconds=OTP_VALIDITY_SECONDS)).isoformat(),
                        "otp_attempts": 0,
                        "resend_count": 0,
                    }
                    send_otp_sms(user.patientprofile.phone_number, code)
                    AuditLogEntry.objects.create(
                        user=user, action_type=AuditLogEntry.ActionType.PASSWORD_RESET_REQUESTED,
                        target_reference=username, ip_address=get_client_ip(request),
                        status=AuditLogEntry.Status.SUCCESS,
                    )
                    return redirect("reset_password_confirm")

                error = "Invalid username and/or phone number."
                AuditLogEntry.objects.create(
                    user=user, action_type=AuditLogEntry.ActionType.PASSWORD_RESET_IDENTITY_FAILED,
                    target_reference=username, ip_address=get_client_ip(request),
                    status=AuditLogEntry.Status.FAILURE,
                )
    else:
        form = PasswordResetRequestForm()

    return render(request, "accounts/forgot_password.html", {"form": form, "error": error})

RESEND_MAX = 3


@ratelimit(key='ip', rate='30/h', method='POST', block=False)
def reset_password_confirm(request):
    """
    Contains the reset form AND code resend on the same page —
    avoids a back-and-forth to forgot_password once identity is
    already proven. No auth_login here: the user goes back through
    login_view, which will prompt for TOTP again if a device is confirmed —
    this flow never bypasses MFA.
    """
    pending = request.session.get("pending_password_reset")
    if not pending:
        return redirect("forgot_password")

    error = None
    resent = False

    if request.method == "POST" and getattr(request, "limited", False):
        error = "Too many attempts. Please try again later."
        return render(request, "accounts/reset_password_confirm.html", {
            "form": PasswordResetConfirmForm(), "error": error,
        })

    if request.method == "POST" and "resend" in request.POST:
        if pending.get("resend_count", 0) >= RESEND_MAX:
            del request.session["pending_password_reset"]
            return render(request, "accounts/forgot_password.html", {
                "form": PasswordResetRequestForm(),
                "error": "Maximum number of resends reached. Please restart the process.",
            })
        user = PortalUser.objects.get(id=pending["user_id"])
        code = generate_otp()
        pending.update({
            "otp_hash": hash_otp(code),
            "otp_expires_at": (timezone.now() + timedelta(seconds=OTP_VALIDITY_SECONDS)).isoformat(),
            "otp_attempts": 0,
            "resend_count": pending.get("resend_count", 0) + 1,
        })
        request.session["pending_password_reset"] = pending
        send_otp_sms(user.patientprofile.phone_number, code)
        return render(request, "accounts/reset_password_confirm.html", {
            "form": PasswordResetConfirmForm(), "resent": True,
        })

    expires_at = datetime.fromisoformat(pending["otp_expires_at"])

    if request.method == "POST":
        if timezone.now() > expires_at:
            del request.session["pending_password_reset"]
            return redirect("forgot_password")

        if pending["otp_attempts"] >= OTP_MAX_ATTEMPTS:
            del request.session["pending_password_reset"]
            AuditLogEntry.objects.create(
                user_id=pending["user_id"], action_type=AuditLogEntry.ActionType.PASSWORD_RESET_LOCKED,
                ip_address=get_client_ip(request), status=AuditLogEntry.Status.FAILURE,
            )
            return redirect("forgot_password")

        form = PasswordResetConfirmForm(request.POST)
        if form.is_valid():
            if hash_otp(form.cleaned_data["token"]) == pending["otp_hash"]:
                user = PortalUser.objects.get(id=pending["user_id"])
                user.set_password(form.cleaned_data["new_password1"])
                user.save()
                send_sms(
                    user.patientprofile.phone_number,
                    "Your password has just been reset. If this was not you, please contact reception immediately.",
                )
                del request.session["pending_password_reset"]
                AuditLogEntry.objects.create(
                    user=user, action_type=AuditLogEntry.ActionType.PASSWORD_RESET_SUCCESS,
                    ip_address=get_client_ip(request), status=AuditLogEntry.Status.SUCCESS,
                )
                return redirect("login")
            pending["otp_attempts"] += 1
            request.session["pending_password_reset"] = pending
            remaining = OTP_MAX_ATTEMPTS - pending["otp_attempts"]
            error = f"Invalid code ({remaining} attempt(s) remaining)."
            AuditLogEntry.objects.create(
                user_id=pending["user_id"], action_type=AuditLogEntry.ActionType.PASSWORD_RESET_OTP_FAILED,
                ip_address=get_client_ip(request), status=AuditLogEntry.Status.FAILURE,
            )
    else:
        form = PasswordResetConfirmForm()

    return render(request, "accounts/reset_password_confirm.html", {"form": form, "error": error, "resent": resent})

@ratelimit(key='user', rate='10/h', method='POST', block=False)
@portal_login_required
def change_username(request):
    """
    Requires the current password: a stolen session (cookie, XSS) is not
    enough to change a login identifier without re-confirming a secret
    the attacker does not have.
    """
    error = None
    if request.method == "POST":
        if getattr(request, "limited", False):
            error = "Too many attempts. Please try again later."
        else:
            form = UsernameChangeForm(request.user, request.POST)
            if form.is_valid():
                old_username = request.user.username
                request.user.username = form.cleaned_data["new_username"]
                request.user.save(update_fields=["username"])
                AuditLogEntry.objects.create(
                    user=request.user, action_type=AuditLogEntry.ActionType.USERNAME_CHANGED,
                    target_reference=f"{old_username} -> {request.user.username}",
                    ip_address=get_client_ip(request), status=AuditLogEntry.Status.SUCCESS,
                )
                try:
                    send_sms(
                        request.user.patientprofile.phone_number,
                        f"Your username has been changed to '{request.user.username}'. "
                        "If this was not you, please contact support immediately.",
                    )
                except PatientProfile.DoesNotExist:
                    pass
                return redirect("dashboard")
    else:
        form = UsernameChangeForm(request.user)
        return render(request, "accounts/change_username.html", {"form": form})

    return render(request, "accounts/change_username.html", {"form": form, "error": error})

@ratelimit(key='user', rate='10/h', method='POST', block=False)
@portal_login_required
def change_password(request):
    """
    PasswordChangeForm already requires the old password. update_session_auth_hash
    prevents logging out the current session — OTHER sessions for this account
    will be automatically invalidated (their session hash no longer matches the
    new password), closing any parallel session an attacker might have opened.
    """
    error = None
    if request.method == "POST":
        if getattr(request, "limited", False):
            error = "Too many attempts. Please try again later."
            form = PasswordChangeForm(user=request.user)
        else:
            form = PasswordChangeForm(user=request.user, data=request.POST)
            if form.is_valid():
                user = form.save()
                update_session_auth_hash(request, user)
                AuditLogEntry.objects.create(
                    user=user, action_type=AuditLogEntry.ActionType.PASSWORD_CHANGED,
                    ip_address=get_client_ip(request), status=AuditLogEntry.Status.SUCCESS,
                )
                try:
                    send_sms(
                        user.patientprofile.phone_number,
                        "Your password has just been changed. If this was not you, please contact reception immediately.",
                    )
                except PatientProfile.DoesNotExist:
                    pass
                return redirect("dashboard")
    else:
        form = PasswordChangeForm(user=request.user)

    return render(request, "accounts/change_password.html", {"form": form, "error": error})

@portal_login_required
def edit_profile(request):
    """Champs non sensibles uniquement — username et mot de passe ont chacun leur propre flux."""
    if request.method == "POST":
        form = ProfileInfoForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            AuditLogEntry.objects.create(
                user=request.user, action_type=AuditLogEntry.ActionType.PROFILE_UPDATED,
                ip_address=get_client_ip(request), status=AuditLogEntry.Status.SUCCESS,
            )
            return redirect("dashboard")
    else:
        form = ProfileInfoForm(instance=request.user)
    return render(request, "accounts/edit_profile.html", {"form": form})


ACCOUNT_DELETION_GRACE_PERIOD = timedelta(days=30)


@ratelimit(key='user', rate='5/h', method='POST', block=False)
@portal_login_required
def request_account_deletion(request):
    """
    Fresh re-authentication required (password + TOTP), even if the session
    is already verified — an irreversible action must never rely on a session
    that could be stolen. The account is deactivated immediately; actual
    anonymization only happens after the grace period via purge_erased_accounts
    (see management/commands/).
    """
    if hasattr(request.user, "erasure_request") and request.user.erasure_request.executed_at is None:
        return render(request, "accounts/deletion_already_requested.html", {
            "scheduled_for": request.user.erasure_request.scheduled_for,
        })

    error = None
    if request.method == "POST":
        form = AccountDeletionRequestForm(request.POST)
        if getattr(request, "limited", False):
            error = "Too many attempts. Please try again later."
        elif form.is_valid():
            device = TOTPDevice.objects.filter(user=request.user, confirmed=True).first()
            password_ok = request.user.check_password(form.cleaned_data["current_password"])
            totp_ok = bool(device and device.verify_token(form.cleaned_data["totp_token"]))

            if password_ok and totp_ok:
                scheduled_for = timezone.now() + ACCOUNT_DELETION_GRACE_PERIOD
                AccountErasureRequest.objects.create(user=request.user, scheduled_for=scheduled_for)
                request.user.is_active = False
                request.user.save(update_fields=["is_active"])
                AuditLogEntry.objects.create(
                    user=request.user, action_type=AuditLogEntry.ActionType.DATA_ERASURE_REQUESTED,
                    target_reference=f"scheduled_for={scheduled_for.isoformat()}",
                    ip_address=get_client_ip(request), status=AuditLogEntry.Status.SUCCESS,
                )
                try:
                    send_sms(
                        request.user.patientprofile.phone_number,
                        f"Account deletion requested. Your data will be permanently "
                        f"erased on {scheduled_for:%d/%m/%Y}. If this was not you, "
                        "contact reception immediately.",
                    )
                except PatientProfile.DoesNotExist:
                    pass
                auth_logout(request)
                return render(request, "accounts/deletion_requested.html", {"scheduled_for": scheduled_for})
            error = "Incorrect password and/or authentication code."
    else:
        form = AccountDeletionRequestForm()

    return render(request, "accounts/request_account_deletion.html", {"form": form, "error": error})


MFA_RECOVERY_SESSION_KEY = "pending_mfa_recovery_otp"
MFA_RECOVERY_RESEND_MAX = 3


@ratelimit(key='ip', rate='30/h', method='POST', block=False)
@ratelimit(key='user', rate='10/h', method='POST', block=False)
@login_required
def lost_mfa_device(request):
    """
    Entry point for an authenticated user (password validated)
    but stuck at otp_verify — lost TOTP device. Password alone
    must never be enough to disable someone's MFA (otherwise
    MFA loses its utility against a stolen password) — we therefore
    require proof of phone possession before revoking the device.
    """
    if request.user.is_verified():
        return redirect("dashboard")

    device = TOTPDevice.objects.filter(user=request.user, confirmed=True).first()
    if not device:
        return redirect("mfa_setup")  # nothing to reset, standard flow is sufficient

    try:
        phone = request.user.patientprofile.phone_number
    except PatientProfile.DoesNotExist:
        return render(request, "accounts/lost_mfa_device_error.html", {
            "error": "Unable to verify your identity automatically. Contact an administrator.",
        })

    pending = request.session.get(MFA_RECOVERY_SESSION_KEY)
    error = None
    resent = False

    if request.method == "POST" and getattr(request, "limited", False):
        return render(request, "accounts/lost_mfa_device.html", {
            "form": OTPVerifyForm(), "error": "Too many attempts. Please try again later.",
            "phone_masked": mask_phone(phone),
        })

    if request.method == "POST" and "resend" in request.POST:
        if not pending or pending.get("resend_count", 0) >= MFA_RECOVERY_RESEND_MAX:
            error = "Maximum number of resends reached. Contact reception."
        else:
            code = generate_otp()
            pending.update({
                "otp_hash": hash_otp(code),
                "expires_at": (timezone.now() + timedelta(seconds=OTP_VALIDITY_SECONDS)).isoformat(),
                "attempts": 0,
                "resend_count": pending.get("resend_count", 0) + 1,
            })
            request.session[MFA_RECOVERY_SESSION_KEY] = pending
            send_otp_sms(phone, code)
            resent = True
        return render(request, "accounts/lost_mfa_device.html", {
            "form": OTPVerifyForm(), "error": error, "resent": resent, "phone_masked": mask_phone(phone),
        })

    if not pending:
        code = generate_otp()
        pending = {
            "otp_hash": hash_otp(code),
            "expires_at": (timezone.now() + timedelta(seconds=OTP_VALIDITY_SECONDS)).isoformat(),
            "attempts": 0,
            "resend_count": 0,
        }
        request.session[MFA_RECOVERY_SESSION_KEY] = pending
        send_otp_sms(phone, code)
        AuditLogEntry.objects.create(
            user=request.user, action_type=AuditLogEntry.ActionType.MFA_RECOVERY_OTP_SENT,
            ip_address=get_client_ip(request), status=AuditLogEntry.Status.SUCCESS,
        )

    if request.method == "POST":
        expires_at = datetime.fromisoformat(pending["expires_at"])
        if timezone.now() > expires_at:
            del request.session[MFA_RECOVERY_SESSION_KEY]
            return redirect("lost_mfa_device")

        if pending["attempts"] >= OTP_MAX_ATTEMPTS:
            del request.session[MFA_RECOVERY_SESSION_KEY]
            AuditLogEntry.objects.create(
                user=request.user, action_type=AuditLogEntry.ActionType.MFA_RECOVERY_OTP_LOCKED,
                ip_address=get_client_ip(request), status=AuditLogEntry.Status.FAILURE,
            )
            return render(request, "accounts/lost_mfa_device_error.html", {
                "error": "Too many incorrect attempts. Contact reception to unlock your account.",
            })

        form = OTPVerifyForm(request.POST)
        if form.is_valid() and hash_otp(form.cleaned_data["token"]) == pending["otp_hash"]:
            TOTPDevice.objects.filter(user=request.user, confirmed=True).delete()
            del request.session[MFA_RECOVERY_SESSION_KEY]
            request.session["identity_proof_at"] = timezone.now().isoformat()
            AuditLogEntry.objects.create(
                user=request.user, action_type=AuditLogEntry.ActionType.MFA_DEVICE_RESET,
                ip_address=get_client_ip(request), status=AuditLogEntry.Status.SUCCESS,
            )
            send_sms(
                phone,
                "Your two-factor authentication has been reset. "
                "If this was not you, please contact reception immediately.",
            )
            return redirect("mfa_setup")
        pending["attempts"] += 1
        request.session[MFA_RECOVERY_SESSION_KEY] = pending
        remaining = OTP_MAX_ATTEMPTS - pending["attempts"]
        error = f"Invalid code ({remaining} attempt(s) remaining)."
        AuditLogEntry.objects.create(
            user=request.user, action_type=AuditLogEntry.ActionType.MFA_RECOVERY_OTP_FAILED,
            ip_address=get_client_ip(request), status=AuditLogEntry.Status.FAILURE,
        )
    else:
        form = OTPVerifyForm()

    return render(request, "accounts/lost_mfa_device.html", {
        "form": form, "error": error, "resent": resent, "phone_masked": mask_phone(phone),
    })


