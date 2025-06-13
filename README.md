# Install and quick run

```bash
cp shepherd/clean_settings.py shepherd/settings.py
# Set DEBUG to False for use in Production

pip3 install -r requirements.txt
./clean_all.sh

# Start server
python3 manage.py runserver 127.0.0.1:80
```

# Other tools

```bash
# Tools must be in the path
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```