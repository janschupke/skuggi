from django.contrib.auth import authenticate, login, logout
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render

from .models import Customer


def health(request):
    # Touch the DB so the healthcheck fails until migrations/seed are done.
    Customer.objects.exists()
    return JsonResponse({"ok": True})


def index(request):
    customers = Customer.objects.order_by("id")
    return render(request, "billing/index.html", {"customers": customers})


def account_detail(request, account_id):
    # VULN (G, IDOR): get_object_or_404 keys on the URL id alone. There is no
    # check that the caller owns this account — and no @login_required at all,
    # so any visitor can walk the id space and read every billing record.
    customer = get_object_or_404(Customer, pk=account_id)
    # VULN (H): the template renders customer.bio with |safe, so a stored
    # <script> payload in the note executes in the viewer's browser.
    return render(request, "billing/account_detail.html", {"customer": customer})


def api_profile(request):
    # VULN (G, IDOR via query param): same object-level flaw, JSON flavour.
    # ?user_id=<n> returns any customer with no auth and no ownership check.
    user_id = request.GET.get("user_id")
    if not user_id:
        return JsonResponse({"error": "user_id required"}, status=400)
    customer = get_object_or_404(Customer, pk=user_id)
    return JsonResponse(
        {
            "id": customer.id,
            "name": customer.name,
            "email": customer.email,
            "phone": customer.phone,
            "card_last4": customer.card_last4,
            "mrr": customer.mrr,
            "bio": customer.bio,
        }
    )


def login_view(request):
    # A cosmetic staff sign-in. It drives Django auth over auth_user, which is
    # why the legacy md5$$ row matters: crack it offline and it logs in here.
    error = None
    if request.method == "POST":
        username = request.POST.get("username", "")
        password = request.POST.get("password", "")
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect("index")
        error = "Invalid credentials."
    return render(request, "billing/login.html", {"error": error})


def logout_view(request):
    logout(request)
    return redirect("index")
