from django.core.management.base import BaseCommand
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType

class Command(BaseCommand):
    help = 'Set up user groups with read and write access'

    def handle(self, *args, **kwargs):

        # List of apps to include in the Write group
        app_labels = ['findings', 'project']

        # Collect all permissions for the specified apps
        write_permissions = Permission.objects.none()  # Start with an empty queryset
        read_permissions = Permission.objects.none()  # Start with an empty queryset
        for app_label in app_labels:
            content_types = ContentType.objects.filter(app_label=app_label)
            for content_type in content_types:
                # Write permissions of the app
                app_write_permissions = Permission.objects.filter(content_type=content_type)
                write_permissions |= app_write_permissions  # Combine permissions
                # Write permissions of the app
                app_read_permissions = Permission.objects.filter(content_type=content_type, codename__startswith='view_')
                read_permissions |= app_read_permissions  # Combine permissions

        # Create "Write" group
        write_group, created = Group.objects.get_or_create(name='Read/Write')
        write_group.permissions.set(write_permissions)
        self.stdout.write(self.style.SUCCESS('Write group created or updated with all permissions from specified apps.'))

        # Create "Read-Only" group
        read_only_group, created = Group.objects.get_or_create(name='Read Only')
        read_only_group.permissions.set(read_permissions)  # Assign all read-related permissions
        self.stdout.write(self.style.SUCCESS('Read-Only group created or updated with all read-related permissions.'))
        