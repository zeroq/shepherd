from django.urls import reverse
from menu import Menu, MenuItem


def top_assets(request):
    return '<span class="glyphicon" aria-hidden="true"></span> Scans/Tools'

sharing_children = (
    MenuItem("Assets", reverse("findings:assets"), weight=10),
    MenuItem("Nmap", reverse("findings:nmap_results"), weight=15),
    MenuItem("Nuclei Findings", reverse("findings:all_findings"), weight=15),
    MenuItem("Httpx (Screenshots and Techs)", reverse("findings:httpx_results"), weight=15),
)

Menu.add_item("findings", MenuItem(top_assets,
    reverse("findings:assets"),
    weight=10,
    children=sharing_children
    )
)
