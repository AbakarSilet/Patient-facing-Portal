
from django.conf import settings


def get_client_ip(request):
    num_trusted_proxies = getattr(settings, "NUM_TRUSTED_PROXIES", 0)

    if num_trusted_proxies <= 0:
        return request.META.get("REMOTE_ADDR", "0.0.0.0")

    xff = request.META.get("HTTP_X_FORWARDED_FOR", "")
    parts = [ip.strip() for ip in xff.split(",") if ip.strip()]

    if len(parts) < num_trusted_proxies:
        # En-tête incohérent avec la topologie attendue : on ne devine
        # pas, on retombe sur l'IP du dernier saut connu.
        return request.META.get("REMOTE_ADDR", "0.0.0.0")

    return parts[-num_trusted_proxies]