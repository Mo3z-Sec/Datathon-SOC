"""ASGI entry point:  uvicorn soc.asgi:app --host 127.0.0.1 --port 8000"""
from .main import create_app

app = create_app()
