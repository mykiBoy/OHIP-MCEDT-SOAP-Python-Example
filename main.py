import hashlib, re, os, uuid, requests
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from base64 import b64encode, b64decode
from lxml import etree


# this script will send a sample download request to server and receive a encrypted response
# this script demonstrate decryption is possible for the SOAP body which means the method to decrypt AES key is correct
# however the second AES key (in <ciphervalue>) is not able to decrypt the binary attachment data
# the purpose of this assignment is to decrypt the encrypted binary data with the second AES key.
# mike suspect the issue is response is processed as text, where some non-displayable binary characters are lost.
# need to find a python library that directly parse MIME message, extract binary attachment and run decryption on a raw byte variable containing the binary attachment.

# Generate a UUID
uuid_var = uuid.uuid4()

# Load the samplerequest.xml file
with open('samplerequest.xml', 'r') as file:
    rawrequest = file.read()
file.close()

# Replace the <AuditId> with the generated uuid
rawrequest = rawrequest.replace('<AuditId>25ee7c33-7bdf-9df1-7510-a41aef13bf82</AuditId>', f'<AuditId>{uuid_var}</AuditId>')

# Replace timestamp with current time
current_time = datetime.utcnow().isoformat()[:-3] + 'Z'
expiry_time = (datetime.utcnow() + timedelta(minutes=10)).isoformat()[:-3] + 'Z'
rawrequest = rawrequest.replace('2024-01-10T18:11:10.526Z', current_time)
rawrequest = rawrequest.replace('2024-01-10T18:21:10.526Z', expiry_time)

#turns out the digest and signature stuff is still necessary. without it the server sometimes respond with valid response, sometimes EBSfault. Probably the server is checking the signature against the public certificate transmitted certain percentage of time. So the following blocks of code are necessary.
MOH_namespaces = """ xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:ebs="http://ebs.health.ontario.ca/" xmlns:edt="http://edt.health.ontario.ca/" xmlns:idp="http://idp.ebs.health.ontario.ca/" xmlns:msa="http://msa.ebs.health.ontario.ca/" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#" xmlns:inc="http://www.w3.org/2004/08/xop/include" """

msgtodigest = """<ebs:EBS wsu:Id="id-4"{}>
    <SoftwareConformanceKey>da3c7d46-42b9-4cd5-8485-8580e3a39593</SoftwareConformanceKey>
    <AuditId>{}</AuditId>
</ebs:EBS>"""
msgtodigest = msgtodigest.format(MOH_namespaces,uuid_var)
# print (msgtodigest,"\n\n")

def canonicalize(xml_string):
  root = etree.fromstring(xml_string)
  canonicalized_string = etree.tostring(root,
                                        method="c14n",
                                        exclusive=False,
                                        with_comments=False)
  return canonicalized_string.decode()

canonmsg = canonicalize(msgtodigest)
hash_object = hashlib.sha256(canonmsg.encode())
hashed_value = b64encode(hash_object.digest())
hashstr = hashed_value.decode()

rawrequest = rawrequest.replace('QLCvJYb1zT9TUYNEkY2qS0VjHPTcjn+WQyZU7Sl5I68=', f'{hashstr}')


def read_pub_key_from_cert(certfile):
  # Read certificate file.
  # with open(certfile) as certificate:
  #     cert = certificate.read()
  cert = certfile

  # Convert it into bytes.
  cert_in_bytes = bytes(cert, 'utf-8')

  # Create x509 certificate object.
  cert_obj = x509.load_pem_x509_certificate(cert_in_bytes)

  # Create Public key object.
  public_key_obj = cert_obj.public_key()

  # Convert Public key object into Pem format in bytes.
  public_pem = public_key_obj.public_bytes(
      encoding=serialization.Encoding.PEM,
      format=serialization.PublicFormat.SubjectPublicKeyInfo)
  # Convert Public key into string.
  pub_key_string = public_pem.decode("utf-8")

  # return(pub_key_string)
  return (public_key_obj)


# Load private key from PKCS12 file
def load_private_key_from_pkcs12(pkcs12_file, password):
  with open(pkcs12_file, 'rb') as f:
    pkcs12_data = f.read()
  private_key = serialization.pkcs12.load_key_and_certificates(
      pkcs12_data, password.encode())[0]
  return private_key


def cert_example():
  cert_file = """-----BEGIN CERTIFICATE-----
  MIIDhTCCAm2gAwIBAgIIIb6aMdhgs54wDQYJKoZIhvcNAQELBQAwcTELMAkGA1UEBhMCQ0ExEDAOBgNVBAgTB09udGFyaW8xEDAOBgNVBAcTB1Rvcm9udG8xETAPBgNVBAoTCGxpZ2h0RU1SMRAwDgYDVQQLEwdvaGlwRUJTMRkwFwYDVQQDExBvaGlwRUJTLmxpZ2h0RU1SMB4XDTIzMTEyMzA4NDk1NVoXDTQzMTExODA4NDk1NVowcTELMAkGA1UEBhMCQ0ExEDAOBgNVBAgTB09udGFyaW8xEDAOBgNVBAcTB1Rvcm9udG8xETAPBgNVBAoTCGxpZ2h0RU1SMRAwDgYDVQQLEwdvaGlwRUJTMRkwFwYDVQQDExBvaGlwRUJTLmxpZ2h0RU1SMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkjtA8ralyYqHoKTbBckhaMD6sj/sfWyI7jI8VEBHg/Vd+YSRNtwL495TPxfHZ3vAjr8UJxLJFN1uWzllRVtLqbRxtvAPpjDr7oT/rULI3Rqh4ZnnCiCX6GeJqZ7RtVknM6bLdFT7uQ6B0TXTSXoOErgDUAxZIr+pmJjnZxAhkRwhvalq0Bh9Vmo3NHxxKw/141xNocO3pG//gPPO5Y1nTGonC/HmylCzHgeDQEX+au3xYCInioDSQ97SGfMzY+r4nvR3D8nA9zG6fIEiM4HvNCemPVrnYykc2ggneiGFlzK/xNNqDBsZvByYCsCpayp+HP/BgJIe04xKiKMcEGuH2QIDAQABoyEwHzAdBgNVHQ4EFgQUue/sefEqVZ5HKmgmiToKxrJISlcwDQYJKoZIhvcNAQELBQADggEBAFRfNA0l7nuw11GOjrTcVdd8RgTTarHRprhEVMp3ahK61qs+r2C85pzqJxCmJHtIQ0gCW4/Lk3QxJ2iNJiyV3oo1atqAroqJldfP/cDad/FQRvhzWUzuNgBNr1HK8Ie6tkeoIj/MA67FSL8jWxi0L48Ycb07XM7JJ9ssxvLrpONqNYNC0qB3gqrNomkif7jGnqIdP9CaR5sWy1wH8vOmYbIhO0+8QAZZQQHd+eLsSYU2LkStT3cHe67xv/4maMCWZpbB9PqlumgoWOsd007Er+H1Yu8iINXvQ+uRkZFuAaIZVu4Bw4a2y3WdBMpabuwRZ/JncT5e5C5ewmpn7X3GwXY=
  -----END CERTIFICATE-----"""
  return read_pub_key_from_cert(cert_file)


public_key = cert_example()
private_key = load_private_key_from_pkcs12("teststore.p12", "changeit")


signed_info = re.search(r'<ds:SignedInfo>.*?</ds:SignedInfo>', rawrequest, re.DOTALL).group(0)
# Insert MOH_namespaces between <ds:SignedInfo and >
signed_info = re.sub(r'(<ds:SignedInfo.*?)(>)', r'\1' + MOH_namespaces + r'\2', signed_info)
signed_info = canonicalize(signed_info)
hash_object = hashlib.sha1(signed_info.encode())
hashed_value = b64encode(hash_object.digest())
# print("\nSHA1 digest of signed info: "+hashed_value.decode())
signature = private_key.sign(signed_info.encode(), padding.PKCS1v15(),
                             hashes.SHA1())
signaturestr = b64encode(signature).decode()
rawrequest = rawrequest.replace('agTeFD3UOYUhFH2vWsCD/IjJrLPL4F3E4nlPkzgJeDFyz39cLe0Q/Yy2gg9WrA8vvTPd3z2+U6+s8YVbnwdnZD9Nl48YeqGSAs8XuBur3LLvV5XcuQiZQGRv7F1w5VF3pVuGBDuWiVEPqvMZumekkBesclWixFWkMi0ruIk2Ih0=', signaturestr)

# save generated request SOAP msg to disk for debugging purposes
with open('generatedrequest.xml', 'w') as file:
    file.write(rawrequest)
file.close()

# get ready to connect to server and send request
# Load the SSL certificates
cafile = "cacert.pem"
url = "https://ws.conf.ebs.health.gov.on.ca:1443/EDTService/EDTService"
headers = {'Content-Type': 'text/xml;charset=UTF-8'}

# Send request using the provided SSL certificates
rawresponse = requests.post(url, data=rawrequest, headers=headers, verify=cafile)

# write rawresponse to file to attack the binary attachment from different angles.
with open('rawresponse.bin', 'wb') as file:
    file.write(rawresponse.content)
file.close()



aes_key = re.search(r'<xenc:CipherValue>(.*?)<\/xenc:CipherValue>', rawresponse.text, re.DOTALL).group(1)

aes_key_bytes = b64decode(aes_key)
# print("AES key length: ", len(aes_key_bytes))

decrypted_aes_key = private_key.decrypt(aes_key_bytes, padding.PKCS1v15())
print("Decrypted AES key for SOAP body:", b64encode(decrypted_aes_key).decode(), "\n\n")

aes_key = re.findall(r'<xenc:CipherValue>(.*?)<\/xenc:CipherValue>', rawresponse.text, re.DOTALL)[1]
aes_key_bytes = b64decode(aes_key)
attachment_aes_key = private_key.decrypt(aes_key_bytes, padding.PKCS1v15())
print("Decrypted AES key for attachment:", b64encode(attachment_aes_key).decode(), "\n\n")

# exit("check rawresponse.bin file to debug")
ciphertext = re.findall(r'<xenc:CipherValue>(.*?)<\/xenc:CipherValue>', rawresponse.text, re.DOTALL)[2]

from Crypto.Cipher import AES
# Initialize the AES cipher with the decrypted_aes_key and CBC mode
cipher = AES.new(decrypted_aes_key, AES.MODE_CBC)
# Base64 decode the ciphertext
ciphertext_bytes = b64decode(ciphertext)
# Decrypt the ciphertext using the initialized AES cipher
decrypted_text = cipher.decrypt(ciphertext_bytes)
# Remove PKCS5 padding from the decrypted text
plaintext = decrypted_text[:-ord(decrypted_text[-1:])]
# First 16 bytes removed as it is just initialization vector per MOH documentation
plaintext = plaintext[16:]
print(plaintext.decode())
# ==========================================================
print("\n⇧⇧⇧⇧⇧⇧ above is proof that decryption works and AES key is decrypted and used correctly. The SOAP body is decrypted and plain text is printed.")

attachment = re.search(r'Content-Type: application/octet-stream(.*?)--MIMEBoundary_', rawresponse.text, re.DOTALL).group(1)

print("The challenge for this assignment is to decrypt the following binary attachment with the second AES key⇩⇩⇩⇩⇩⇩⇩⇩⇩⇩⇩⇩")

print(attachment) # be careful, this attachment is no longer raw binary, it is now a string which might have already lost some non-printable characters.