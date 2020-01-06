import hashlib
import requests
import json
import sys
import os

file_path = input("File Path: ")

BLOCK_SIZE = 65536

filehash = hashlib.sha256()
with open(file_path, "rb") as f:
    fb = f.read(BLOCK_SIZE)
    while len(fb) > 0:
        filehash.update(fb)
        fb = f.read(BLOCK_SIZE)

headers = {
     'pragma': 'no-cache',
     'x-app-hostname': 'https://www.virustotal.com/gui/',
     'dnt': '1',
     'x-app-version': '20190611t171116',
     'accept-encoding': 'gzip, deflate, br',
     'accept-language': 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7,la;q=0.6,mt;q=0.5',
     'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36',
     'accept': 'application/json',
     'cache-control': 'no-cache',
     'authority': 'www.virustotal.com',
     'referer': 'https://www.virustotal.com/',
 }

filelink = ("")
response = requests.get("https://www.virustotal.com/ui/files/" + filehash.hexdigest(), headers=headers)
data = json.loads(response.content)
malicious = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
undedected = data["data"]["attributes"]["last_analysis_stats"]["undetected"]

if malicious > 0:
    print("WARNING: This file is MALICIOUS!")
    print(malicious, "System found this file is malicious out of ", (malicious+undedected))
    print("\n  You want to delete malicious file? y/n")
    input()
    if input == "y":
        os.remove(file_path)
        print("Malicious File is Succesfully Deleted.")
    if input == "n":
        pass
    else:
        print("Unknown Command!")
    
else:
    print("This file is not malicious.")
    print(malicious, "System found this file is malicious out of ", (malicious+undedected))

input("Press enter for terminate the script...")