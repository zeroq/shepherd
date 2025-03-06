#!/bin/bash

find . -path "*/migrations/*.py" -not -name "__init__.py" -delete
find . -path "*/migrations/*.pyc"  -delete
rm -rf db.sqlite3
python3 manage.py makemigrations
python3 manage.py migrate
python3 manage.py createsuperuser
