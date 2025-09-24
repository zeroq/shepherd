# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.urls import reverse
from menu import Menu, MenuItem

def top_inventory(request):
    return '<span class="glyphicon glyphicon-list-alt" aria-hidden="true"></span> Inventory'

Menu.add_item("suggestions", MenuItem(top_inventory,
    reverse("findings:assets"),
    weight=20
    )
)
