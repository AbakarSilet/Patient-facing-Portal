import csv
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.db.models import Count, Q
from django.http import StreamingHttpResponse
from django.shortcuts import get_object_or_404
from django.utils import timezone
from django.utils.functional import cached_property
from django.utils.text import get_valid_filename
from django.views import View
from django.views.generic import ListView, TemplateView

from .forms import AuditLogFilterForm, OpenMRSLogFilterForm
from .models import AuditLogEntry, OpenMRSRequestLog
from .permissions import AdminRequiredMixin
from .utils import get_client_ip

A = AuditLogEntry.ActionType


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

class _Echo:
    """Pseudo-fichier : csv.writer.writerow() retourne la ligne au lieu de l'écrire."""

    def write(self, value):
        return value


def _safe(value):
    """Neutralise l'injection de formules (Excel/LibreOffice) dans les exports CSV."""
    s = "" if value is None else str(value)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s


def _log_access(request, action, target_user=None):
    """
    Tout accès privilégié au journal d'audit est lui-même tracé.
    target_reference ne contient ni username ni valeur de filtre (PII, donc
    incompatible avec le droit à l'oubli) : seulement la vue, le pk de
    l'utilisateur consulté et les NOMS des filtres utilisés.
    """
    scope = f"user_pk={target_user.pk}" if target_user else "all"
    filters = ",".join(sorted(k for k in request.GET if request.GET.get(k) and k != "page"))
    ref = f"{request.resolver_match.url_name} {scope}"
    if filters:
        ref += f" filters={filters}"
    AuditLogEntry.objects.create(
        user=request.user,
        action_type=action,
        target_reference=ref[:255],
        ip_address=get_client_ip(request),
        status=AuditLogEntry.Status.SUCCESS,
    )


# --------------------------------------------------------------------------
# Mixins
# --------------------------------------------------------------------------

class FilteredLogMixin(AdminRequiredMixin):
    """Applique le formulaire de filtres (GET) au queryset de base."""

    form_class = None

    def base_queryset(self):
        raise NotImplementedError

    def build_filter_form(self):
        return self.form_class(self.request.GET)

    @cached_property
    def filter_form(self):
        return self.build_filter_form()

    def get_queryset(self):
        qs = self.base_queryset()
        # Filtres invalides -> rien, plutôt qu'un export non filtré par surprise.
        return self.filter_form.filter(qs) if self.filter_form.is_valid() else qs.none()


class LogAccessMixin:
    """
    Trace chaque consultation (pagination comprise : pas de contournement
    possible via ?page=N). S'exécute après le contrôle d'accès.
    """

    def get(self, request, *args, **kwargs):
        _log_access(request, A.AUDIT_LOG_VIEWED, getattr(self, "target_user", None))
        return super().get(request, *args, **kwargs)


class CSVExportMixin:
    csv_header = ()

    def get_filename(self):
        return "export"

    def csv_row(self, obj):
        raise NotImplementedError

    def get(self, request, *args, **kwargs):
        qs = self.get_queryset()  # évalué ici : un 404 ne doit pas survenir en plein stream
        _log_access(request, A.AUDIT_LOG_EXPORTED, getattr(self, "target_user", None))
        writer = csv.writer(_Echo())

        def stream():
            yield "\ufeff"  # BOM : accents corrects dans Excel
            yield writer.writerow(self.csv_header)
            for obj in qs.iterator(chunk_size=2000):
                yield writer.writerow([_safe(v) for v in self.csv_row(obj)])

        stamp = timezone.now().strftime("%Y%m%d-%H%M%S")
        response = StreamingHttpResponse(stream(), content_type="text/csv; charset=utf-8")
        response["Content-Disposition"] = (
            f'attachment; filename="{self.get_filename()}-{stamp}.csv"'
        )
        return response


class AuditLogMixin(FilteredLogMixin):
    """Journal d'audit, global ou restreint à un utilisateur (kwarg `username`)."""

    form_class = AuditLogFilterForm

    @cached_property
    def target_user(self):
        username = self.kwargs.get("username")
        if username is None:
            return None
        User = get_user_model()
        return get_object_or_404(User, **{User.USERNAME_FIELD: username})

    def build_filter_form(self):
        form = super().build_filter_form()
        if self.target_user:  # ces filtres n'ont plus de sens sur la page d'un utilisateur
            del form.fields["user"]
            del form.fields["anonymous_only"]
        return form

    def base_queryset(self):
        qs = AuditLogEntry.objects.select_related("user").order_by("-timestamp", "-pk")
        if self.target_user:
            qs = qs.filter(user=self.target_user)
        return qs


class OpenMRSLogMixin(FilteredLogMixin):
    form_class = OpenMRSLogFilterForm

    def base_queryset(self):
        return OpenMRSRequestLog.objects.order_by("-timestamp", "-pk")


class PaginatedFilterListView(ListView):
    paginate_by = 50

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        params = self.request.GET.copy()
        params.pop("page", None)
        ctx["form"] = self.filter_form
        ctx["querystring"] = params.urlencode()  # pour pagination et lien d'export
        return ctx


# --------------------------------------------------------------------------
# Dashboard
# --------------------------------------------------------------------------

class DashboardView(AdminRequiredMixin, TemplateView):
    template_name = "auditlog/dashboard.html"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        since = timezone.now() - timedelta(hours=24)
        recent = AuditLogEntry.objects.filter(timestamp__gte=since)
        lockouts = [A.REGISTRATION_OTP_LOCKED, A.PASSWORD_RESET_LOCKED,
                    A.MFA_RECOVERY_OTP_LOCKED, A.LOGIN_OTP_LOCKED]
        ctx.update(
            failed_logins=recent.filter(action_type=A.LOGIN_FAILED).count(),
            lockouts=recent.filter(action_type__in=lockouts).count(),
            erasure_requests=recent.filter(action_type=A.DATA_ERASURE_REQUESTED).count(),
            top_failing_ips=(
                recent.filter(status=AuditLogEntry.Status.FAILURE)
                .values("ip_address").annotate(n=Count("id")).order_by("-n")[:10]
            ),
            openmrs_errors=(
                OpenMRSRequestLog.objects.filter(timestamp__gte=since)
                .filter(Q(status_code__isnull=True) | Q(status_code__gte=400)).count()
            ),
        )
        return ctx


# --------------------------------------------------------------------------
# Journal d'audit
# --------------------------------------------------------------------------

class AuditLogListView(LogAccessMixin, AuditLogMixin, PaginatedFilterListView):
    template_name = "auditlog/entry_list.html"
    context_object_name = "entries"

    def get_context_data(self, **kwargs):
        ctx = super().get_context_data(**kwargs)
        ctx["target_user"] = self.target_user
        return ctx


class AuditLogExportView(AuditLogMixin, CSVExportMixin, View):
    csv_header = ("timestamp", "username_at_event", "current_username", "action_type",
                  "status", "ip_address", "target_reference")

    def get_filename(self):
        if self.target_user:
            return f"auditlog-{get_valid_filename(self.target_user.get_username())}"
        return "auditlog"

    def csv_row(self, e):
        return (e.timestamp.isoformat(), e.username_snapshot, e.user, e.action_type,
                e.status, e.ip_address, e.target_reference)


# --------------------------------------------------------------------------
# Appels sortants OpenMRS
# --------------------------------------------------------------------------

class OpenMRSLogListView(LogAccessMixin, OpenMRSLogMixin, PaginatedFilterListView):
    template_name = "auditlog/openmrs_list.html"
    context_object_name = "requests"


class OpenMRSLogExportView(OpenMRSLogMixin, CSVExportMixin, View):
    csv_header = ("timestamp", "method", "endpoint", "status_code", "duration_ms", "triggered_by_ip")

    def get_filename(self):
        return "openmrs-requests"

    def csv_row(self, r):
        return (r.timestamp.isoformat(), r.method, r.endpoint,
                r.status_code, r.duration_ms, r.triggered_by_ip)