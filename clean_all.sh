#!/bin/bash

# Remove migration files except __init__.py
find . -path "./venv" -prune -o -path "*/migrations/*.py" -not -name "__init__.py" -exec rm -f {} +
find . -path "./venv" -prune -o -path "*/migrations/*.pyc" -exec rm -f {} +

# Remove the database file
rm -rf db.sqlite3

# Recreate migrations and apply them
python3 manage.py makemigrations
python3 manage.py migrate

# Collect static files for production
python3 manage.py collectstatic

# Create user groups for administration
python3 manage.py setup_user_groups

# Create a superuser
python3 manage.py createsuperuser
