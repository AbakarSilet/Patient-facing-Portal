from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.password_validation import validate_password
from .models import PortalUser


class PatientRegistrationForm(UserCreationForm):
    openmrs_identifier = forms.CharField(max_length=20, label="OpenMRS ID (ex: 10000X)")
    birthdate = forms.DateField(label="Date de naissance", widget=forms.DateInput(attrs={'type': 'date'}))
    accept_privacy_policy = forms.BooleanField(
        required=True,
        label="J'accepte la politique de confidentialité",
        error_messages={"required": "Vous devez accepter la politique de confidentialité pour continuer."},
    )

    class Meta:
        model = PortalUser
        fields = ["username", "password1", "password2", "openmrs_identifier", "birthdate"]


class OTPVerifyForm(forms.Form):
    token = forms.CharField(
        max_length=6, label="Code à 6 chiffres",
        widget=forms.TextInput(attrs={"inputmode": "numeric", "autocomplete": "one-time-code", "autofocus": True}),
    )




class PasswordResetRequestForm(forms.Form):
    username = forms.CharField(max_length=150)
    phone_number = forms.CharField(max_length=20)


class PasswordResetConfirmForm(forms.Form):
    token = forms.CharField(max_length=6)
    new_password1 = forms.CharField(widget=forms.PasswordInput)
    new_password2 = forms.CharField(widget=forms.PasswordInput)

    def clean(self):
        cleaned = super().clean()
        p1, p2 = cleaned.get("new_password1"), cleaned.get("new_password2")
        if p1 and p2 and p1 != p2:
            self.add_error("new_password2", "Les mots de passe ne correspondent pas.")
        if p1:
            try:
                validate_password(p1)
            except forms.ValidationError as e:
                self.add_error("new_password1", e)
        return cleaned


class UsernameChangeForm(forms.Form):
    new_username = forms.CharField(max_length=150)
    current_password = forms.CharField(widget=forms.PasswordInput)

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super().__init__(*args, **kwargs)

    def clean_current_password(self):
        password = self.cleaned_data["current_password"]
        if not self.user.check_password(password):
            raise forms.ValidationError("Mot de passe incorrect.")
        return password

    def clean_new_username(self):
        new_username = self.cleaned_data["new_username"]
        if PortalUser.objects.filter(username=new_username).exclude(pk=self.user.pk).exists():
            raise forms.ValidationError("Ce nom d'utilisateur est déjà pris.")
        return new_username


class ProfileInfoForm(forms.ModelForm):
    class Meta:
        model = PortalUser
        fields = ["first_name", "last_name"]


class AccountDeletionRequestForm(forms.Form):
    current_password = forms.CharField(widget=forms.PasswordInput, label="Mot de passe actuel")
    totp_token = forms.CharField(max_length=6, label="Code d'authentification (app)")    