# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.urls import reverse
from menu import Menu, MenuItem

def top_home(request):
    return '<span class="glyphicon glyphicon-home" aria-hidden="true"></span> Home'

home_childs = (
    MenuItem("Home", reverse("home"), weight=10),
    #MenuItem("Favorites", reverse("favorites"), weight=15),
    #MenuItem("Upload File", reverse("upload_file"), weight=20),
)

Menu.add_item("main", MenuItem(top_home, reverse("home"), weight=10, children=home_childs))
