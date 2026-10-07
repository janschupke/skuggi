"""First-boot seed for the FernData portal. Idempotent: safe to re-run.

Plants:
  * the customer billing book (PII) — loot `customer-pii`;
  * one customer whose note carries a raw <script> payload — loot `stored-xss`;
  * normal pbkdf2 staff accounts plus one legacy md5$$ import row — loot
    `legacy-md5-hash`.
"""

from django.contrib.auth.models import User
from django.core.management.base import BaseCommand

from billing.models import Customer

# md5("sunshine") — the classic rockyou-crackable plaintext. Stored in the
# UnsaltedMD5PasswordHasher wire format: "md5$" + "" (empty salt) + "$" + hex.
LEGACY_MD5 = "md5$$0571749e2ac330a7455809c6b0e7af90"

XSS_PAYLOAD = "<script>alert('ferndata-xss-7f3a')</script>"

CUSTOMERS = [
    {
        "name": "Alder & Finch Pharmacy",
        "email": "a.morales@alder-finch.example",
        "phone": "+1-415-555-0142",
        "card_last4": "4417",
        "mrr": 2600,
        "bio": "Net-30 billing. Primary contact prefers email.",
    },
    {
        # Account #2 — the stored-XSS oracle. The note was pasted by an
        # operator and is rendered through |safe on /account/2/.
        "name": "Cobalt Robotics",
        "email": "j.tan@cobalt-robotics.example",
        "phone": "+1-312-555-0178",
        "card_last4": "9021",
        "mrr": 4100,
        "bio": "Escalations route to ops. " + XSS_PAYLOAD,
    },
    {
        "name": "Dunmore Credit Union",
        "email": "billing@dunmore-cu.example",
        "phone": "+44-20-7946-0991",
        "card_last4": "3376",
        "mrr": 3300,
        "bio": "Quarterly invoice. PO number required on every invoice.",
    },
    {
        "name": "Everly Interiors",
        "email": "p.novak@everly-interiors.example",
        "phone": "+1-646-555-0119",
        "card_last4": "1180",
        "mrr": 1200,
        "bio": "Seasonal account. Pauses billing over summer.",
    },
]

# Normal accounts — strong pbkdf2 hashes, not the point of the lab.
STAFF = [
    {"username": "admin", "password": "FernAdmin!2024", "email": "admin@ferndata.lab", "superuser": True},
    {"username": "nwalsh", "password": "Autumn#Leaves7", "email": "n.walsh@ferndata.lab", "superuser": False},
]


class Command(BaseCommand):
    help = "Seed the FernData customer book and staff accounts (idempotent)."

    def handle(self, *args, **options):
        if Customer.objects.exists():
            self.stdout.write("customers already seeded; skipping")
        else:
            for row in CUSTOMERS:
                Customer.objects.create(**row)
            self.stdout.write(self.style.SUCCESS(f"seeded {len(CUSTOMERS)} customers"))

        for s in STAFF:
            if User.objects.filter(username=s["username"]).exists():
                continue
            if s["superuser"]:
                User.objects.create_superuser(s["username"], s["email"], s["password"])
            else:
                User.objects.create_user(s["username"], s["email"], s["password"])
            self.stdout.write(f"created staff user {s['username']}")

        # Legacy CSV-import account, stored as an unsalted MD5 (md5$$<hex>).
        # Set the password field directly so it is NOT re-hashed.
        if not User.objects.filter(username="svc_import").exists():
            legacy = User.objects.create(
                username="svc_import",
                email="imports@ferndata.lab",
                is_staff=True,
                is_active=True,
            )
            legacy.password = LEGACY_MD5
            legacy.save(update_fields=["password"])
            self.stdout.write(self.style.SUCCESS("created legacy md5 user svc_import"))
