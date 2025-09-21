import requests
import json
import time
import os
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from django.core.management.base import BaseCommand, CommandError
from django.conf import settings


class Command(BaseCommand):
    help = 'Run Burp Suite scan against a specific URL using local Burp Suite API'

    def add_arguments(self, parser):
        parser.add_argument(
            'url',
            type=str,
            help='URL to scan (e.g., https://example.com)',
        )
        parser.add_argument(
            '--burp-host',
            type=str,
            default='127.0.0.1',
            help='Burp Suite API host (default: 127.0.0.1)',
        )
        parser.add_argument(
            '--burp-port',
            type=int,
            default=1337,
            help='Burp Suite API port (default: 1337)',
        )
        parser.add_argument(
            '--api-key',
            type=str,
            help='Burp Suite API key (if authentication is enabled)',
        )
        parser.add_argument(
            '--scan-config',
            type=str,
            default='Audit coverage - maximum',
            help='Burp Suite scan configuration (default: "Audit coverage - maximum")',
        )
        parser.add_argument(
            '--wait',
            action='store_true',
            help='Wait for scan completion and show results',
        )
        parser.add_argument(
            '--timeout',
            type=int,
            default=3600,
            help='Maximum time to wait for scan completion in seconds (default: 3600)',
        )
        parser.add_argument(
            '--bruteforce-paths',
            action='store_true',
            help='Perform path bruteforcing before scanning to discover hidden endpoints',
        )
        parser.add_argument(
            '--wordlist',
            type=str,
            help='Path to wordlist file for path bruteforcing (one path per line)',
        )
        parser.add_argument(
            '--threads',
            type=int,
            default=10,
            help='Number of threads for path bruteforcing (default: 10)',
        )

    def handle(self, *args, **options):
        url = options['url']
        burp_host = options['burp_host']
        burp_port = options['burp_port']
        api_key = options.get('api_key')
        scan_config = options['scan_config']
        wait_for_completion = options['wait']
        timeout = options['timeout']
        bruteforce_paths = options['bruteforce_paths']
        wordlist_path = options.get('wordlist')
        threads = options['threads']

        # Validate URL
        try:
            parsed_url = urlparse(url)
            if not parsed_url.scheme or not parsed_url.netloc:
                raise ValueError("Invalid URL format")
        except Exception as e:
            raise CommandError(f"Invalid URL '{url}': {e}")

        # Build Burp Suite API base URL
        burp_api_base = f"http://{burp_host}:{burp_port}"
        
        # Prepare headers
        headers = {'Content-Type': 'application/json'}
        if api_key:
            headers['Authorization'] = f'Bearer {api_key}'

        self.stdout.write(f"Starting Burp Suite scan for: {url}")
        self.stdout.write(f"Using Burp API at: {burp_api_base}")

        try:
            # Test connection to Burp Suite API
            self._test_burp_connection(burp_api_base, headers)
            
            # Optionally perform path bruteforcing first
            discovered_urls = [url]  # Always include the original URL
            if bruteforce_paths:
                if not wordlist_path:
                    # Use a default small wordlist if none provided
                    discovered_urls.extend(self._bruteforce_paths_default(url, threads))
                else:
                    discovered_urls.extend(self._bruteforce_paths_wordlist(url, wordlist_path, threads))
            
            # Start the scan (with discovered URLs if any)
            scan_urls = list(set(discovered_urls))  # Remove duplicates
            task_id = self._start_scan(burp_api_base, headers, scan_urls, scan_config)
            
            if task_id:
                self.stdout.write(
                    self.style.SUCCESS(f"Scan started successfully! Task ID: {task_id}")
                )
                
                if wait_for_completion:
                    self._wait_for_scan_completion(burp_api_base, headers, task_id, timeout)
                else:
                    self.stdout.write("Use --wait flag to monitor scan progress")
                    self.stdout.write(f"You can check scan status manually with task ID: {task_id}")
            else:
                self.stdout.write(
                    self.style.SUCCESS("Scan started successfully!")
                )
                if wait_for_completion:
                    self.stdout.write("Cannot monitor progress without task ID from API")
                
        except Exception as e:
            raise CommandError(f"Failed to start Burp Suite scan: {e}")

    def _test_burp_connection(self, base_url, headers):
        """Test connection to Burp Suite API"""
        try:
            response = requests.get(f"{base_url}/v0.1/", headers=headers, timeout=10)
            response.raise_for_status()
            
            self.stdout.write("Connected to Burp Suite API successfully")
            
        except requests.exceptions.ConnectionError:
            raise CommandError(
                "Cannot connect to Burp Suite API. Make sure Burp Suite is running "
                "with the REST API enabled."
            )
        except requests.exceptions.Timeout:
            raise CommandError("Connection to Burp Suite API timed out")
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 401:
                raise CommandError("Authentication failed. Check your API key.")
            else:
                raise CommandError(f"HTTP error connecting to Burp Suite API: {e}")

    def _bruteforce_paths_default(self, base_url, threads):
        """Bruteforce paths using a default wordlist"""
        default_paths = [
            'admin', 'administrator', 'login', 'api', 'v1', 'v2', 'test', 'dev',
            'staging', 'backup', 'config', 'dashboard', 'panel', 'manage',
            'uploads', 'files', 'docs', 'documentation', 'help', 'support',
            'robots.txt', 'sitemap.xml', '.well-known', 'health', 'status',
            'info', 'debug', 'console', 'phpmyadmin', 'wp-admin', 'wp-login.php'
        ]
        
        self.stdout.write("Using default wordlist for path bruteforcing...")
        return self._bruteforce_paths(base_url, default_paths, threads)

    def _bruteforce_paths_wordlist(self, base_url, wordlist_path, threads):
        """Bruteforce paths using a custom wordlist file"""
        if not os.path.exists(wordlist_path):
            self.stdout.write(
                self.style.WARNING(f"Wordlist file not found: {wordlist_path}")
            )
            return []
            
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
                paths = [line.strip() for line in f if line.strip() and not line.startswith('#')]
            
            self.stdout.write(f"Loaded {len(paths)} paths from wordlist: {wordlist_path}")
            return self._bruteforce_paths(base_url, paths, threads)
            
        except Exception as e:
            self.stdout.write(
                self.style.WARNING(f"Error reading wordlist file: {e}")
            )
            return []

    def _bruteforce_paths(self, base_url, paths, threads):
        """Perform the actual path bruteforcing"""
        discovered_urls = []
        
        def test_path(path):
            """Test a single path and return URL if it exists"""
            try:
                # Clean up the path
                path = path.strip('/')
                test_url = urljoin(base_url.rstrip('/') + '/', path)
                
                response = requests.get(test_url, timeout=10, allow_redirects=True)
                
                # Consider various success indicators
                if (response.status_code == 200 or 
                    response.status_code == 403 or  # Forbidden but exists
                    response.status_code == 401 or  # Unauthorized but exists
                    (response.status_code == 302 and 'login' not in response.headers.get('location', '').lower())):
                    
                    return test_url
                    
            except requests.exceptions.RequestException:
                # Ignore connection errors, timeouts, etc.
                pass
            return None

        self.stdout.write(f"Starting path bruteforce with {threads} threads...")
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            # Submit all tasks
            future_to_path = {executor.submit(test_path, path): path for path in paths}
            
            # Process completed tasks
            for future in as_completed(future_to_path):
                path = future_to_path[future]
                try:
                    result = future.result()
                    if result:
                        discovered_urls.append(result)
                        self.stdout.write(f"  Found: {result}")
                except Exception as e:
                    self.stdout.write(f"  Error testing {path}: {e}")
        
        self.stdout.write(f"Path bruteforcing complete. Found {len(discovered_urls)} valid paths.")
        return discovered_urls

    def _start_scan(self, base_url, headers, urls, scan_config):
        """Start a Burp Suite scan and return task ID"""
        # Handle both single URL (string) and multiple URLs (list)
        if isinstance(urls, str):
            urls = [urls]
            
        scan_data = {
            "urls": urls,
            "scan_configurations": [
                {
                    "name": scan_config,
                    "type": "NamedConfiguration"
                }
            ]
        }
        
        if len(urls) > 1:
            self.stdout.write(f"Scanning {len(urls)} URLs (including discovered paths)")
        
        # Note: Burp Suite automatically performs crawling/spidering as part of the scan
        # The scan configuration (e.g., "Audit coverage - maximum") controls this behavior
        
        self.stdout.write(f"Sending scan request to: {base_url}/v0.1/scan")
        self.stdout.write(f"Scan data: {json.dumps(scan_data, indent=2)}")
        
        response = requests.post(
            f"{base_url}/v0.1/scan",
            headers=headers,
            json=scan_data,
            timeout=30
        )
        
        self.stdout.write(f"Response status: {response.status_code}")
        self.stdout.write(f"Response headers: {dict(response.headers)}")
        self.stdout.write(f"Response content: {response.text[:500]}")
        
        if response.status_code == 201:
            print(response.text)
            if response.text.strip():
                try:
                    result = response.json()
                    return result.get('task_id')
                except json.JSONDecodeError as e:
                    raise CommandError(f"Invalid JSON response: {e}. Response: {response.text}")
            else:
                # Some APIs return empty responses on successful creation
                self.stdout.write("Scan started successfully (empty response from API)")
                return None
        else:
            response.raise_for_status()

    def _wait_for_scan_completion(self, base_url, headers, task_id, timeout):
        """Wait for scan completion and display results"""
        self.stdout.write("Waiting for scan completion...")
        start_time = time.time()
        
        while True:
            if time.time() - start_time > timeout:
                self.stdout.write(
                    self.style.WARNING(f"Timeout reached ({timeout}s). Scan may still be running.")
                )
                break
                
            try:
                # Check scan status
                status_response = requests.get(
                    f"{base_url}/v0.1/scan/{task_id}",
                    headers=headers,
                    timeout=10
                )
                
                if status_response.status_code == 200:
                    try:
                        status_data = status_response.json()
                        scan_status = status_data.get('scan_status', 'unknown')
                    except json.JSONDecodeError:
                        self.stdout.write(
                            self.style.WARNING(f"Invalid JSON in status response: {status_response.text}")
                        )
                        scan_status = 'unknown'
                    
                    self.stdout.write(f"Scan status: {scan_status}")
                    
                    if scan_status in ['succeeded', 'failed', 'cancelled']:
                        break
                        
                elif status_response.status_code == 404:
                    self.stdout.write(
                        self.style.WARNING("Scan task not found. It may have completed or been removed.")
                    )
                    break
                    
                time.sleep(10)  # Wait 10 seconds before checking again
                
            except requests.exceptions.RequestException as e:
                self.stdout.write(
                    self.style.WARNING(f"Error checking scan status: {e}")
                )
                time.sleep(10)
        
        # Get scan results
        self._get_scan_results(base_url, headers, task_id)

    def _get_scan_results(self, base_url, headers, task_id):
        """Get and display scan results"""
        try:
            # Get issues found during the scan
            issues_response = requests.get(
                f"{base_url}/v0.1/scan/{task_id}/issues",
                headers=headers,
                timeout=30
            )
            
            if issues_response.status_code == 200:
                try:
                    issues = issues_response.json()
                except json.JSONDecodeError:
                    self.stdout.write(
                        self.style.WARNING(f"Invalid JSON in issues response: {issues_response.text}")
                    )
                    issues = []
                
                if issues:
                    self.stdout.write(
                        self.style.SUCCESS(f"\nScan completed! Found {len(issues)} issues:")
                    )
                    
                    for issue in issues:
                        severity = issue.get('severity', 'Unknown')
                        confidence = issue.get('confidence', 'Unknown')
                        issue_name = issue.get('issue_name', 'Unknown Issue')
                        url = issue.get('origin', 'Unknown URL')
                        
                        # Color code by severity
                        if severity.lower() == 'high':
                            style = self.style.ERROR
                        elif severity.lower() == 'medium':
                            style = self.style.WARNING
                        else:
                            style = self.style.NOTICE
                            
                        self.stdout.write(
                            style(f"  [{severity}] {issue_name} - {url}")
                        )
                        self.stdout.write(f"    Confidence: {confidence}")
                else:
                    self.stdout.write(
                        self.style.SUCCESS("Scan completed! No issues found.")
                    )
            else:
                self.stdout.write(
                    self.style.WARNING("Could not retrieve scan results.")
                )
                
        except requests.exceptions.RequestException as e:
            self.stdout.write(
                self.style.WARNING(f"Error retrieving scan results: {e}")
            )
