from django.core.management.base import BaseCommand
from project.models import Asset, DNSRecord
import concurrent.futures
import dns.resolver
from django.utils import timezone

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
            found_records = []
            has_any_records = False
            
            try:
                for record_type in record_types:
                    try:
                        answers = dns.resolver.resolve(asset.value, record_type)
                        for answer in answers:
                            record_value = str(answer)
                            ttl = answer.ttl if hasattr(answer, 'ttl') else None
                            
                            # Store the DNS record
                            dns_record, created = DNSRecord.objects.get_or_create(
                                related_asset=asset,
                                related_project=asset.related_project,
                                record_type=record_type,
                                record_value=record_value,
                                defaults={'ttl': ttl}
                            )
                            
                            if not created:
                                # Update existing record
                                dns_record.ttl = ttl
                                dns_record.last_checked = timezone.now()
                                dns_record.save()
                            
                            found_records.append((record_type, record_value, ttl))
                            self.stdout.write(f"Found {record_type} record for {asset.value}: {record_value}")
                        
                        has_any_records = True
                        
                    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                        continue  # Try the next record type
                    except Exception as e:
                        self.stderr.write(f"Error checking {record_type} for {asset.value}: {e}")
                        continue
                
                return asset, has_any_records, found_records
                
            except Exception as e:
                self.stderr.write(f"Error checking {asset.value}: {e}")
                return asset, asset.active, []  # Keep the current status if an error occurs

        # Process in batches to reduce memory usage
        batch_size = 1000  # Process 100 assets at a time
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
                    asset, has_dns, found_records = future.result()
                    print(f"{asset.value}: {len(found_records)} records found, active={has_dns}")
                    
                    if not has_dns:
                        asset.active = False
                        asset.save()
                        self.stdout.write(f"Updated {asset.value}: active=False (no DNS records)")
                    else:
                        asset.active = True
                        asset.save()
                        self.stdout.write(f"Updated {asset.value}: active=True ({len(found_records)} DNS records)")
                
                processed += len(batch_assets)
                
                # Force garbage collection between batches
                import gc
                gc.collect()

        self.stdout.write("DNS check completed.")
