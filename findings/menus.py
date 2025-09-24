from django.urls import reverse
from menu import Menu, MenuItem


def top_security_scans(request):
    return '<span class="glyphicon glyphicon-screenshot" aria-hidden="true"></span> Security Scans'

security_children = (
    MenuItem("Nmap", reverse("findings:nmap_results"), weight=10),
    MenuItem("Nuclei Findings", reverse("findings:all_findings"), weight=20),
    MenuItem("Httpx (Screenshots)", reverse("findings:httpx_results"), weight=30),
    MenuItem("Data Leaks", reverse("findings:data_leaks"), weight=40),
)

Menu.add_item("findings", MenuItem(top_security_scans,
    "#",  # No direct URL for the parent menu
    weight=30,
    children=security_children
    )
)
