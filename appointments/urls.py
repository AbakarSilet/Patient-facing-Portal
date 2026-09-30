from django.urls import path
from . import views

urlpatterns = [
    path("request/", views.request_appointment, name="request_appointment"),
    path("my-requests/", views.my_appointment_requests, name="my_appointment_requests"),
    path("cancel/<uuid:request_uuid>/", views.cancel_appointment_request, name="cancel_appointment_request"),

]