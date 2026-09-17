import os

bind = f"0.0.0.0:{os.getenv('PORT', '8080')}"
workers = int(os.getenv("WEB_CONCURRENCY", "1"))
timeout = int(os.getenv("GUNICORN_TIMEOUT", "120"))
accesslog = "-"
errorlog = "-"
capture_output = True
