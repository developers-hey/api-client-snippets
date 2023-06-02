import http.client
import json

import requests
import ssl

from requests.adapters import HTTPAdapter, Retry

#from requests.utils import DEFAULT_CA_BUNDLE_PATH
#print("path del ssistema",DEFAULT_CA_BUNDLE_PATH)


# Defining certificate related stuff and host of endpoint
private_key = 'C:\\Users\\BRM17037\\Downloads\\copia-test\\Client_sbox_cab1da7a-dbef-41bb-8824-eb14aa079ae3.pem'
private_key2 = 'C:\\Users\\BRM17037\\Downloads\\copia-test\\Client_sbox_key.key'
public_key = 'C:\\Users\\BRM17037\\Downloads\\copia-test\\Server_Public_sbox_cab1da7a-dbef-41bb-8824-eb14aa079ae3.pem'
pwd = 'YDs/+ExqvS0xN3thWpu8GisqJz/aVCsl5FX53SV7X8I='
keystore_path="C:\\Users\\BRM17037\\Downloads\\copia-test\\Client_KeyStore_sbox_cab1da7a-dbef-41bb-8824-eb14aa079ae3.p12"
ca='C:\\Users\\BRM17037\\Downloads\\Client_Certificate080523\\CA_sbox.cer'

crt='C:\\Users\\BRM17037\\Downloads\\Client_Certificate080523\\banregio_2019.crt'
#certs=(public_key, private_key)
certs=(crt, private_key2, pwd)
#certs=(keystore_path, None, pwd)

host = 'https://sbox-open-api.banregio.com'

# Defining parts of the HTTP request
request_url='https://sbox-open-api.banregio.com/auth/v1/oidc/token'

uri='/auth/v1/oidc/token'

request_headers = {
    'Content-Type': 'application/x-www-form-urlencoded'
}
payload = { 'grant_type':'client_credentials', 'client_id':'5937a4bf-40c9-470e-b79b-c646c9b3d548', 'client_secret':'4472c868-d72f-41ed-93ab-2ac7459ebe9c' }

result = requests.post(request_url,  cert=certs, verify=ca, params=payload)
# do something with result...



#connection = http.client.HTTPSConnection("www.google.com")
#connection.request("GET", "/")
#response = connection.getresponse()
#print("Status: {} and reason: {}".format(response.status, response.reason))
"""
context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
context.load_cert_chain(certfile=public_key,keyfile=keystore_path, password=certificate_secret)
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = True

conn = http.client.HTTPSConnection(host, port=443, context=context)

conn.request("POST", uri, request_headers, payload)
response = conn.getresponse()
print(response.status, response.reason)
data = response.read()
print(data)
conn.close()"""



try:
    # Use connection to submit a HTTP POST request
   result = requests.post(url=request_url, params=payload, headers=request_headers, proxies={"https": "https://10.2.208.199:443"}, verify=crt, timeout=(0.1, 10))
   #result = requests.post(url=request_url, params=payload, headers=request_headers, cert=certs)
   print(result)
except requests.exceptions.ConnectionError as errc:
    print(errc)
    

# Define the client certificate settings for https connection
#context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
#context.load_cert_chain(certfile=keystore_path,  password=certificate_secret)
# Create a connection to submit HTTP requests
#connection = http.client.HTTPSConnection(host, port=443, context=context)
# Use connection to submit a HTTP POST request
#connection.request(method="POST", url=request_url, headers=request_headers, body=json.dumps(the_data))

#context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
#context.load_cert_chain(certfile=public_key, keyfile=private_key, password=certificate_secret)

"""context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations(cafile=ca)
context.check_hostname = True
context.verify_mode = ssl.CERT_REQUIRED"""
#context.load_cert_chain(private_key, keyfile=None, password=None)

#context.verify_mode = ssl.CERT_REQUIRED
#context.load_verify_locations(crt)

#context = ssl.SSLContext()
#context.verify_mode = ssl.CERT_NONE
"""conn = http.client.HTTPSConnection(host, port=8012, context=context, timeout=10)

try:
    # Use connection to submit a HTTP POST request
    conn.request(method="POST", url=request_url,headers=request_headers, body=payload )
except requests.exceptions.SSLError as e:
    print(e)"""
 
# Print the HTTP response from the IOT service endpoint
#response = conn.getresponse
#print(response)
#print(response.status, response.reason)
#data = response.read()
#print(data)





