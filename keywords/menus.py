# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.urls import reverse
from menu import Menu, MenuItem

def top_keywords(request):
    return '<span class="glyphicon glyphicon-tasks" aria-hidden="true"></span> Keywords'

sharing_children = (
    MenuItem("Keywords",
            reverse("keywords:keywords"),
            weight=10
        ),
)

Menu.add_item("keywords", MenuItem(top_keywords,
    reverse("keywords:keywords"),
    weight=10,
    children=sharing_children
    )
)
