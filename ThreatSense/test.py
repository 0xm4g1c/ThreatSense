# curl --request GET \  --url  \ --header 'x-apikey: <your API key>'
# API key d685cea07210fcb509d434cda02ad48864d8c533bc9873a72f85b9cd70c77963

import requests

url = 'https://www.virustotal.com/vtapi/v2/url/report'

url_scan = 'https://curl.trillworks.com/'
params = {'apikey': 'd685cea07210fcb509d434cda02ad48864d8c533bc9873a72f85b9cd70c77963', 'resource':(url_scan)}

response = requests.get(url, params=params)

print(response.json())


