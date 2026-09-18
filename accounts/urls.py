#accounts/urls.py

from django.urls import path
from . import views

urlpatterns = [
    path("register/", views.register, name="register"),
    path("mfa-setup/", views.mfa_setup, name="mfa_setup"),
    path("login/", views.login_view, name="login"),
    path("otp-verify/", views.otp_verify, name="otp_verify"),
    path("logout/", views.logout_view, name="logout"),
    path("forgot-password/", views.forgot_password, name="forgot_password"),
    path("reset-password-confirm/", views.reset_password_confirm, name="reset_password_confirm"),
    path("dashboard/", views.dashboard, name="dashboard"),
    path("verify-registration-otp/", views.verify_registration_otp, name="verify_registration_otp"),
    path("change-username/", views.change_username, name="change_username"),
    path("change-password/", views.change_password, name="change_password"),
    path("edit-profile/", views.edit_profile, name="edit_profile"),
    path("request-deletion/", views.request_account_deletion, name="request_account_deletion"),
    path("lost-device/", views.lost_mfa_device, name="lost_mfa_device"),
    


]