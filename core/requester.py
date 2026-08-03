# core/requester.py
import requests

class APIRequester:
    def __init__(self, base_url, timeout=5, headers=None):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.headers = headers or {'User-Agent': 'APISentinelScanner/1.0'}

    def send_request(self, endpoint, method='GET', payload=None, custom_headers=None):
        url = f"{self.base_url}{endpoint}"
        headers = {**self.headers, **(custom_headers or {})}
        
        try:
            response = requests.request(
                method=method,
                url=url,
                json=payload,
                headers=headers,
                timeout=self.timeout
            )
            return response
        except requests.exceptions.RequestException as e:
            return None