"""Build the planted KeePass DB at image-build time.

The master password ("Autumn2024!") is intentionally NOT in stock wordlists — it
is derivable only from the naming convention hinted in the share's HR notes
(Season+Year+!). Cracking it reveals the pivot SSH credentials.
"""

import sys

from pykeepass import create_database

MASTER = "Autumn2024!"


def main(out: str) -> None:
    db = create_database(out, password=MASTER)
    it = db.add_group(db.root_group, "IT")
    db.add_entry(
        it,
        title="pivot-backup (svc-backup@northwind-pivot)",
        username="svc-backup",
        password="b7-KZ2p-Wq9x",
        url="ssh://10.13.6.20",
        notes="Nightly rsync service account for the pivot host.",
    )
    db.add_entry(
        it,
        title="lobby-wifi",
        username="guest",
        password="Cafe-Latte-9",
        notes="Guest wifi in reception.",
    )
    db.save()


if __name__ == "__main__":
    main(sys.argv[1])
