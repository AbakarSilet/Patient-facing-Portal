from django.urls import path
from . import views

urlpatterns = [
    path("request/", views.request_appointment, name="request_appointment"),
]