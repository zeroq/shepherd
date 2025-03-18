# Install and quick run

```bash
cp shepherd/clean_settings.py shepherd/settings.py
# Set DEBUG to False for use in Production

pip3 install -r requirements.txt
python3 manage.py makemigrations
python3 manage.py migrate

# For additional tools
# Install https://github.com/projectdiscovery/nuclei in the PATH
```

# Trigger imports

```bash
python3 manage.py import_domaintools
```
