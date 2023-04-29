# mitmproxy-data-cache-logger

Mitmproxy addon to log requests and responses to database, additionally serve requests or cache from database if it exists.

## Requirements

- Python 3.6+
- Mitmproxy from PIP not standalone
- venv or virtualenv (recommended)

## Run

```bash
pip install -r requirements.txt
mitmdump -s main.py
```

## Feature

- Save requests and responses to database
- Intercept request and serve it from database if it exists
- Deduplicate response body
- Asynchronous

## Supported database

- [x] MongoDB
