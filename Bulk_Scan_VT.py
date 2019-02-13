import requests
import re
import time
def g(line):
    params = {'apikey': 'c058c032efb7be34fc8f130e8bcda4d12fe4d87a3f480993dfe37ff5f196cab7','resource':line}
    headers = {
      "Accept-Encoding": "gzip, deflate",
      "User-Agent" : "gzip,  gaja"
      }
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
      params=params, headers=headers)
    fx = response.json()
    fx=str(fx)

    Microsoft=re.findall(r"Microsoft': {u'detected': True, u'version': u'.+?result': u'(.+?)', u'update",fx)
    Kaspersky=re.findall(r"Kaspersky': {u'detected': True, u'version': u'.+?result': u'(.+?)', u'update",fx)
    ESET = re.findall(r"ESET-NOD32': {u'detected': True, u'version': u'.+?result': u'(.+?)', u'update",fx)
    Bitdefender= re.findall(r"BitDefender': {u'detected': True, u'version': u'.+?result': u'(.+?)', u'update",fx)
    print("-----------------"+line+"----------------------\n")
    print("Microsoft -> "+ str(Microsoft))
    print("Kaspersky -> "+ str(Kaspersky))
    print("ESET -> "+ str(ESET))
    print("Bitdefender -> "+ str(Bitdefender))
    print("-----------------------------------------------\n")

f=open("filewh.txt","r").readlines()
for line in f:
    line=line.strip(" \n")
    g(line)
    time.sleep(5)
