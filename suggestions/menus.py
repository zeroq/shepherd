# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.urls import reverse
from menu import Menu, MenuItem

def top_suggestions(request):
    return '<span class="glyphicon glyphicon-tasks" aria-hidden="true"></span> Suggestions'

sharing_children = (
    MenuItem("Suggestions", reverse("suggestions:suggestions"), weight=10),
    MenuItem("Ignored Suggestions", reverse("suggestions:ignored_suggestions"), weight=20),
    # MenuItem("Recent Suggestions", reverse("suggestions:recent_suggestions"), weight=30),
)

Menu.add_item("suggestions", MenuItem(top_suggestions,
    reverse("suggestions:suggestions"),
    weight=10,
    children=sharing_children
    )
)
