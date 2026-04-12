from __future__ import annotations

from django.contrib import messages
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.urls import reverse
from django.views.defaults import page_not_found, permission_denied


def _is_web_navigation_request(request: HttpRequest) -> bool:
    if request.method not in {"GET", "HEAD"}:
        return False
    if request.path.startswith("/api/"):
        return False
    if request.path.startswith("/admin/"):
        return False
    if request.headers.get("HX-Request", "").lower() == "true":
        return False
    return True


def _initial_route(request: HttpRequest) -> str:
    if getattr(request, "user", None) and request.user.is_authenticated:
        return reverse("webui:dashboard")
    return reverse("webui:login")


def app_permission_denied(request: HttpRequest, exception=None) -> HttpResponse:
    if _is_web_navigation_request(request):
        messages.warning(request, "Voce nao tem permissao para acessar esta pagina.")
        return redirect(_initial_route(request))
    return permission_denied(request, exception)


def app_page_not_found(request: HttpRequest, exception) -> HttpResponse:
    if _is_web_navigation_request(request):
        messages.warning(request, "A pagina solicitada nao existe.")
        return redirect(_initial_route(request))
    return page_not_found(request, exception)
