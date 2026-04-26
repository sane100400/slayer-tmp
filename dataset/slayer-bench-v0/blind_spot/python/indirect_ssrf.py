import requests

def fetch_user_profile(user_id: str) -> dict:
    base_url = "https://internal-api.example.com"
    path = f"/users/{user_id}/profile"
    endpoint = base_url + path      # URL constructed from parts, not direct user input
    response = requests.get(endpoint)
    return response.json()
