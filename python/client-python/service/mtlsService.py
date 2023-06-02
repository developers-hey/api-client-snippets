#py -m pip install requests
import requests

import http.client
import json
import ssl
#import urllib
#import urllib.request as urllib2
from requests import Session
from requests.exceptions import Timeout

from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectionError

from urllib3.util.retry import Retry

#from requests_pkcs12 import Pkcs12Adapter

private_key = 'C:\\Users\\BRM17037\\Downloads\\Client_Certificate_Cris\\Client_sbox_cab1da7a-dbef-41bb-8824-eb14aa079ae3.pem'
private_key2 = 'C:\\Users\\BRM17037\\Downloads\\Client_Certificate_Cris\\Client_sbox_cab1da7a-dbef-41bb-8824-eb14aa079ae3.key'
public_key = 'C:\\Users\\BRM17037\\Downloads\\Client_Certificate_Cris\\Server_Public_sbox_cab1da7a-dbef-41bb-8824-eb14aa079ae3.pem'
pwd = 'YDs/+ExqvS0xN3thWpu8GisqJz/aVCsl5FX53SV7X8I='
keystore_path="C:\\Users\\BRM17037\\Downloads\\Client_Certificate_Cris\\Client_KeyStore_sbox_cab1da7a-dbef-41bb-8824-eb14aa079ae3.p12"
ca='C:\\Users\\BRM17037\\Downloads\\Client_Certificate080523\\CA_sbox.cer'
crt='C:\\Users\\BRM17037\\Downloads\\Client_Certificate080523\\banregio_2019.crt'
certs=(private_key, public_key)
certs=(crt, private_key2, pwd)

#certs=('C:\\Users\\BRM17037\\Downloads\\CA_open-api-banregio-com\\CA_open-api.banregio.com.cer', 'C:\\Users\\BRM17037\\Downloads\\877f71bc-381f-4cef-90ea-6a41025773d2\\Client_sbox_877f71bc-381f-4cef-90ea-6a41025773d2.key', certificate_secret)

payload = { 'grant_type':'client_credentials', 'client_id':'5937a4bf-40c9-470e-b79b-c646c9b3d548', 'client_secret':'4472c868-d72f-41ed-93ab-2ac7459ebe9c' }

#json_data = json.dumps(payload)

headers = { 'Content-Type': 'application/x-www-form-urlencoded' }

token_endpoint = 'https://sbox-open-api.banregio.com/auth/v1/oidc/token'
#s = requests.Session()
#s.verify='C:\\Users\\BRM17037\\Downloads\\CA_open-api-banregio-com\\CA_open-api.banregio.com.cer'
#context = ssl._create_unverified_context()
#urllib.request.urlopen(token_endpoint,context=context)
#ssl._create_default_https_context = ssl._create_unverified_context
#urllib2.urlopen(token_endpoint).read()
#github_adapter = HTTPAdapter(max_retries=5)
s = requests.Session()
#retry = Retry(connect=3, backoff_factor=0.5)
#retry = Retry(connect=3)
#adapter = HTTPAdapter(max_retries=retry)
#s.mount('https://', adapter)
#s.verify(ca)


try:
    #s.cert=crt
    result_token = s.post(url=token_endpoint, headers=headers, params=payload, cert=certs)
    print(result_token)
    #result_token = requests.post(token_endpoint, headers=headers, params=payload, cert=keystore_path)
except requests.exceptions.SSLError as ssle:
    print(ssle)
except requests.exceptions.HTTPError as errh:
    print(errh)
except requests.exceptions.ConnectionError as errc:
    print(errc)
except requests.exceptions.Timeout as errt:
    print(errt)
except requests.exceptions.RequestException as err:
    print(err)

"""
with Session() as s:
    s.mount(token_endpoint, Pkcs12Adapter(pkcs12_filename=keystore_path, pkcs12_password=secret))
try:
    result_token = s.post(token_endpoint, params=payload)
except ConnectionError as ce:
    print("ERROR:",ce)"""


"""try:
    result_token = requests.post(token_endpoint, data=json.dumps(payload), verify=cer, cert=certs)
except Timeout:
    print('The request timed out')
else:
    print('The request did not time out')"""
 
#getToken(private_key_path, certificate_secret,token_endpoint)

#r = requests.post(token_endpoint, data=the_data)
#token = r.json().access_token

#end_point = 'https://sbox-open-api.banregio.com/datr/v1.0/accounts'

#aqui directo a las apis despues de obtener el token

#result = requests.get(result_token, data=the_data, headers=headers, cert=certs)
#print(result)

