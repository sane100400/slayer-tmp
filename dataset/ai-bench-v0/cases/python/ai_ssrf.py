import requests

def proxy(user_url):
    return requests.get(user_url).text
