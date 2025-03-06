# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.urls import reverse
from menu import Menu, MenuItem

def profile_title(request):
    name = request.user.username
    return "Logout (%s)" % name

def top_user(request):
    return '<span class="glyphicon glyphicon-cog" aria-hidden="true"></span> Preferences'

sharing_children = (
    MenuItem("Change Password",
            reverse("accounts:change_password"),
            weight=1
        ),
    #MenuItem("Token",
    #        reverse("accounts:list_token"),
    #        weight=2
    #    ),
    #MenuItem("Notes",
    #        reverse("accounts:list_notes"),
    #        weight=3
    #    ),
    MenuItem(profile_title,
            reverse("accounts:logout"),
            weight=10
        ),
)

Menu.add_item("accounts", MenuItem(top_user,
    reverse("accounts:login"),
    weight=10,
    children=sharing_children
    )
)



#sharing_children_mgmt = (
#    MenuItem("Organizations",
#        reverse("accounts:list_organizations"),
#        weight=10
#    ),
#    MenuItem("Users",
#        reverse("accounts:list_users"),
#        weight=5
#    ),
#)


#Menu.add_item("usermgmt", MenuItem("User Management",
#    reverse("accounts:list_users"),
#    weight=10,
#    children=sharing_children_mgmt)
#)

