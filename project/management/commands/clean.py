from django.core.management.base import BaseCommand
from project.models import Asset, Suggestion

class Command(BaseCommand):
    help = 'Delete all Asset objects from the database.'

    def handle(self, *args, **options):
        count = Asset.objects.count()
        Asset.objects.all().delete()
        self.stdout.write(self.style.SUCCESS(f"Deleted {count} Asset objects."))

        sugg_count = Suggestion.objects.filter(source='file_upload').count()
        Suggestion.objects.filter(source='file_upload').delete()
        self.stdout.write(self.style.SUCCESS(f"Deleted {sugg_count} Suggestion objects with source 'file_upload'."))
