import os
from flask import Flask, request, abort
import requests

ALLOWED_DOMAINS = {'api.stripe.com', 'api.sendgrid.com', 'api.github.com'}

app = Flask(__name__)
DEBUG = os.environ.get('DEBUG', 'false').lower() == 'true'

@app.route('/fetch')
def fetch_resource():
    url = request.args.get('url', '')
    from urllib.parse import urlparse
    domain = urlparse(url).hostname or ''
    if domain not in ALLOWED_DOMAINS:
        abort(403)
    return requests.get(url).text

@app.route('/proxy')
def proxy():
    return requests.get("https://api.internal/data").text
