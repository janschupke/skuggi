from django.urls import path

from billing import views

urlpatterns = [
    path("", views.index, name="index"),
    path("health/", views.health, name="health"),
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    # VULN (G, IDOR via route): any integer id returns that customer's record
    # with no object-level permission check and no authentication.
    path("account/<int:account_id>/", views.account_detail, name="account_detail"),
    # VULN (G, IDOR via query param): same object, reached as JSON.
    path("api/profile", views.api_profile, name="api_profile"),
]
