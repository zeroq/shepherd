# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.urls import reverse
from menu import Menu, MenuItem
from project.models import Job  # Add this import

def top_keywords(request):
    running_count = Job.objects.filter(status="running").count()
    icon_html = '<span class="glyphicon glyphicon-tasks" aria-hidden="true"></span>'
    if running_count > 0:
        icon_html += f' <span class="badge" style="background-color:#337ab7;">{running_count}</span>'
    return f'{icon_html} Jobs'

sharing_children = (
    MenuItem("Jobs",
            reverse("jobs:jobs"),
            weight=10
        ),
)

Menu.add_item("jobs", MenuItem(top_keywords,
    reverse("jobs:jobs"),
    weight=10,
    )
)


