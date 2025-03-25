# Install and quick run

```bash
cp shepherd/clean_settings.py shepherd/settings.py
# Set DEBUG to False for use in Production

pip3 install -r requirements.txt
./clean_all.sh

# Start server
python3 manage.py runserver 127.0.0.1:80

# For additional tools
# Install https://github.com/projectdiscovery/nuclei in the PATH
```

# Trigger imports

```bash
python3 manage.py import_domaintools
python3 manage.py scan_nmap
python3 manage.py scan_nuclei
```
