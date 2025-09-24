from django.core.management.base import BaseCommand
from project.models import Asset
import concurrent.futures
import dns.resolver

class Command(BaseCommand):
    help = "Check DNS records for all suggestions and update their active status"

    def add_arguments(self, parser):
        parser.add_argument(
            '--projectid',
            type=int,
            help='Filter by specific project ID',
            required=False,
        )
        parser.add_argument(
            '--uuids',
            type=str,
            help='Comma separated list of suggestion UUIDs to process',
            required=False,
        )

    def handle(self, *args, **kwargs):
        project_filter = {}
        if kwargs.get('projectid'):
            project_filter['related_project__id'] = kwargs['projectid']

        uuids_arg = kwargs.get('uuids')

        # Get total count without loading all objects
        assets_query = Asset.objects.filter(**project_filter).filter(scope='external', type='domain')
        if uuids_arg:
            uuid_list = [u.strip() for u in uuids_arg.split(",") if u.strip()]
            assets_query = assets_query.filter(uuid__in=uuid_list)

        total_count = assets_query.count()
        self.stdout.write(f"Checking DNS records for {total_count} active assets...")

        def check_dns(asset):
            record_types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'PTR']
            try:
                for record_type in record_types:
                    try:
                        dns.resolver.resolve(asset.value, record_type)
                        self.stdout.write(f"record found {record_type} for {asset.value}")
                        return asset, True  # If any record type is resolved, mark as active
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                        continue  # Try the next record type
                return asset, False  # If no record types are resolved, mark as inactive
            except Exception as e:
                self.stderr.write(f"Error checking {asset.value}: {e}")
                return asset, asset.active  # Keep the current status if an error occurs

        # Process in batches to reduce memory usage
        batch_size = 100  # Process 100 assets at a time
        processed = 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:  # Limit concurrent threads
            while processed < total_count:
                # Get a batch of assets
                batch_assets = list(assets_query[processed:processed + batch_size])
                
                if not batch_assets:
                    break
                
                self.stdout.write(f"Processing batch {processed//batch_size + 1} ({len(batch_assets)} assets)...")
                
                # Submit batch to thread pool
                future_to_asset = {executor.submit(check_dns, asset): asset for asset in batch_assets}
                
                # Process results for this batch
                for future in concurrent.futures.as_completed(future_to_asset):
                    asset, has_dns = future.result()
                    print(asset.value, has_dns)
                    if not has_dns:
                        asset.active = False
                        asset.save()
                        self.stdout.write(f"Updated {asset.value}: active=False")
                    else:
                        asset.active = True
                        asset.save()
                        self.stdout.write(f"Updated {asset.value}: active=True")
                
                processed += len(batch_assets)
                
                # Force garbage collection between batches
                import gc
                gc.collect()

        self.stdout.write("DNS check completed.")
