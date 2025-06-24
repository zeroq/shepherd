# Install and quick run

```bash
git clone https://github.com/zeroq/shepherd
cp shepherd/clean_settings.py shepherd/settings.py
# Set DEBUG to False for use in Production

python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
./clean_all.sh

# Start server
python3 manage.py runserver 127.0.0.1:80
```

# Dependency tools (can all be installed as a single user for quick runs)

```bash
# As root
apt install nmap
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
apt install ./google-chrome-stable_current_amd64.deb
wget https://go.dev/dl/go1.24.4.linux-amd64.tar.gz -O /tmp/go1.24.4.linux-amd64.tar.gz
rm -rf /usr/local/go
tar -C /usr/local -xzf /tmp/go1.24.4.linux-amd64.tar.gz

# Switch to www-data
mkdir /var/www/
sudo chown -R www-data:www-data /var/www/
sudo -u www-data bash

# As www-data
export PATH=/opt/shepherd/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/usr/local/go/bin:/var/www/go/bin
cd
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

```

# For production
```bash
# As root
cd /opt
git clone https://github.com/zeroq/shepherd
cp shepherd/clean_settings.py shepherd/settings.py
chown -R www-data:www-data /opt/shepherd/
apt install python3-pip python3-venv libpq-dev postgresql postgresql-contrib nginx
cd /opt/shepherd
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt

# Psql
sudo -u postgres psql
# In the psql shell:
CREATE DATABASE shepherddb;
CREATE USER shepherd WITH PASSWORD 'mypassword';
ALTER ROLE shepherd SET client_encoding TO 'utf8';
ALTER ROLE shepherd SET default_transaction_isolation TO 'read committed';
ALTER ROLE shepherd SET timezone TO 'UTC';
GRANT ALL PRIVILEGES ON DATABASE shepherddb TO shepherd;
\q
```

## shepherd/settings.py
```py
DEBUG = False

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.postgresql',
        'NAME': 'shepherddb',
        'USER': 'shepherd',
        'PASSWORD': 'mypassword',
        'HOST': 'localhost',
        'PORT': '',
    }
}

# For Nginx proxy to Gunicorn
USE_X_FORWARDED_HOST = True
SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
RATELIMIT_IP_META_KEY = 'HTTP_X_FORWARDED_FOR'
RATELIMIT_TRUSTED_PROXIES = ['127.0.0.1', '::1']
```

## /etc/systemd/system/gunicorn.service
```conf
[Unit]
Description=gunicorn daemon
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/opt/shepherd
Environment="PATH=/opt/shepherd/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/usr/local/go/bin:/var/www/go/"
ExecStart=/opt/shepherd/venv/bin/gunicorn --access-logfile - --workers 3 --bind unix:/opt/shepherd/gunicorn.sock shepherd.wsgi:application

[Install]
WantedBy=multi-user.target
```

```bash
systemctl start gunicorn
systemctl enable gunicorn
```

## SSL cert
```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/shepherd.key -out /etc/ssl/certs/shepherd.crt
```

## /etc/nginx/sites-available/shepherd
```conf
server {
    listen 80;
    server_name your_domain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name your_domain.com;

    ssl_certificate /etc/ssl/certs/shepherd.crt;
    ssl_certificate_key /etc/ssl/private/shepherd.key;

    location = /favicon.ico { access_log off; log_not_found off; }
    location /static/ {
        root /opt/shepherd;
    }

    location / {
        include proxy_params;
        # proxy_set_header X-Forwarded-For;
        proxy_pass http://unix:/opt/shepherd/gunicorn.sock;
    }
}
```

## Enable the site and restard Nginx
```bash
rm /etc/nginx/sites-enabled/default
ln -s /etc/nginx/sites-available/shepherd /etc/nginx/sites-enabled
nginx -t
systemctl restart nginx
```

## Setup the Shepherd
```
./clean_all.sh
```
