from django.db import models


class Customer(models.Model):
    """A FernData billing account. The `bio`/support-note field is operator
    free text and is rendered with |safe on the public account page."""

    name = models.CharField(max_length=128)
    # Billing contact address — the PII the IDOR leaks.
    email = models.CharField(max_length=128)
    phone = models.CharField(max_length=32)
    card_last4 = models.CharField(max_length=4)
    mrr = models.IntegerField(help_text="monthly recurring revenue, USD")
    # VULN (H, stored XSS): rendered through |safe in account_detail.html.
    bio = models.TextField(blank=True, default="")

    class Meta:
        db_table = "billing_customers"

    def __str__(self):
        return self.name
