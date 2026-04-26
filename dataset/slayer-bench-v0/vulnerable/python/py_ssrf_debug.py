from flask import Flask, request
import requests

app = Flask(__name__)
DEBUG = True

@app.route('/fetch')
def fetch_resource():
    return requests.get(request.args['url']).text

@app.route('/proxy')
def proxy():
    target = request.form.get('target')
    return requests.get(f"https://api.internal/{target}").text
