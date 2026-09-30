from datetime import datetime, time, timedelta

from django import forms
from django.contrib.auth import get_user_model
from django.db.models import Q
from django.utils import timezone

from .models import AuditLogEntry


def _day_start(d):
    return timezone.make_aware(datetime.combine(d, time.min))


class BaseDateRangeForm(forms.Form):
    date_from = forms.DateField(
        required=False, label="From",
        widget=forms.DateInput(attrs={"type": "date"}),
    )
    date_to = forms.DateField(
        required=False, label="To (inclusive)",
        widget=forms.DateInput(attrs={"type": "date"}),
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Classes Bootstrap appliquées une seule fois, pour tous les filtres.
        for field in self.fields.values():
            widget = field.widget
            if isinstance(widget, forms.CheckboxInput):
                css = "form-check-input"
            elif isinstance(widget, forms.Select):  # inclut SelectMultiple
                css = "form-select"
                if isinstance(widget, forms.SelectMultiple):
                    widget.attrs.setdefault("size", 6)
            else:
                css = "form-control"
            widget.attrs["class"] = f"{widget.attrs.get('class', '')} {css}".strip()

    def clean(self):
        data = super().clean()
        d1, d2 = data.get("date_from"), data.get("date_to")
        if d1 and d2 and d1 > d2:
            raise forms.ValidationError("The start date must not be after the end date.")
        return data

    def filter_dates(self, qs):
        d1, d2 = self.cleaned_data.get("date_from"), self.cleaned_data.get("date_to")
        if d1:
            qs = qs.filter(timestamp__gte=_day_start(d1))
        if d2:
            qs = qs.filter(timestamp__lt=_day_start(d2 + timedelta(days=1)))
        return qs


class AuditLogFilterForm(BaseDateRangeForm):
    user = forms.CharField(required=False, label="User")
    action_type = forms.MultipleChoiceField(
        required=False, label="Action",
        choices=AuditLogEntry.ActionType.choices,
    )
    status = forms.ChoiceField(
        required=False, label="Status",
        choices=[("", "All")] + AuditLogEntry.Status.choices,
    )
    ip_address = forms.GenericIPAddressField(required=False, label="IP address")
    target = forms.CharField(required=False, label="Target reference")
    anonymous_only = forms.BooleanField(
        required=False, label="Events without an account (pre-registration)",
    )

    def filter(self, qs):
        d = self.cleaned_data
        if d.get("user"):
            field = get_user_model().USERNAME_FIELD
            qs = qs.filter(
                Q(**{f"user__{field}__icontains": d["user"]})
                | Q(username_snapshot__icontains=d["user"])  # retrouve aussi les anciens usernames
            )
        if d["action_type"]:
            qs = qs.filter(action_type__in=d["action_type"])
        if d["status"]:
            qs = qs.filter(status=d["status"])
        if d["ip_address"]:
            qs = qs.filter(ip_address=d["ip_address"])
        if d["target"]:
            qs = qs.filter(target_reference__icontains=d["target"])
        if d.get("anonymous_only"):
            qs = qs.filter(user__isnull=True)
        return self.filter_dates(qs)


class OpenMRSLogFilterForm(BaseDateRangeForm):
    STATUS_CHOICES = [
        ("", "All"),
        ("2xx", "Success (2xx)"),
        ("4xx", "Client error (4xx)"),
        ("5xx", "Server error (5xx)"),
        ("network", "Network failure (no response)"),
    ]
    _RANGES = {"2xx": (200, 299), "4xx": (400, 499), "5xx": (500, 599)}

    method = forms.ChoiceField(
        required=False, label="Method",
        choices=[("", "All")] + [(m, m) for m in ("GET", "POST", "PUT", "DELETE")],
    )
    status = forms.ChoiceField(required=False, label="Result", choices=STATUS_CHOICES)
    endpoint = forms.CharField(required=False, label="Endpoint")
    triggered_by_ip = forms.GenericIPAddressField(required=False, label="Visitor IP")

    def filter(self, qs):
        d = self.cleaned_data
        if d["method"]:
            qs = qs.filter(method=d["method"])
        if d["status"] == "network":
            qs = qs.filter(status_code__isnull=True)
        elif d["status"]:
            lo, hi = self._RANGES[d["status"]]
            qs = qs.filter(status_code__gte=lo, status_code__lte=hi)
        if d["endpoint"]:
            qs = qs.filter(endpoint__icontains=d["endpoint"])
        if d["triggered_by_ip"]:
            qs = qs.filter(triggered_by_ip=d["triggered_by_ip"])
        return self.filter_dates(qs)