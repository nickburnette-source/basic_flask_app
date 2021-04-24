#!/bin/bash

gunicorn -w 2 -b :7002 --chdir /opt/webapp app:app --log-level info --access-logfile /var/log/flask/app.access.log --error-logfile /var/log/flask/app.error.log
# /usr/bin/python3 app.py
