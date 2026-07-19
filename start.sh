#!/bin/sh
# Runs DB migrations then starts the server.
# Used in Railway (and any other environment where docker-compose isn't
# running migrate as a separate service).
set -e
python migrate.py
exec uvicorn main:app --host 0.0.0.0 --port "${PORT:-8000}"