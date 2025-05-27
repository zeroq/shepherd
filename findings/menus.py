# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.urls import reverse
from menu import Menu, MenuItem


def top_assets(request):
    return '<span class="glyphicon" aria-hidden="true"></span> Scans/Tools'

sharing_children = (
    MenuItem("Assets", reverse("findings:assets"), weight=10),
    MenuItem("Nmap", reverse("findings:nmap_results"), weight=15),
    MenuItem("Findings", reverse("findings:all_findings"), weight=15),
    # MenuItem("Screenshots", reverse("findings:recent_findings"), weight=15),
    # MenuItem("Recent Findings", reverse("findings:recent_findings"), weight=15),
    # MenuItem("Ignored Assets", reverse("findings:ignored_assets"), weight=20),
)

Menu.add_item("findings", MenuItem(top_assets,
    reverse("findings:assets"),
    weight=10,
    children=sharing_children
    )
)
