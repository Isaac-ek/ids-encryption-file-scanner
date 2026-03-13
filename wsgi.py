"""WSGI entrypoint for production server.

Use a WSGI server like gunicorn to run this safely in production.

Example:
    gunicorn -w 4 -b 0.0.0.0:8000 wsgi:application
"""

from web import app as application
