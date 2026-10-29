"""WSGI entry point — ``flask run`` and ``gunicorn app:app``.

The CLI (``python cli.py web``) is the normal way to start the UI; this module exists
so a plain WSGI server can import it without knowing the package layout.
"""

from rennacs.app import create_app

app = create_app()
