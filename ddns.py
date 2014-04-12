#!/usr/bin/python
""" Requierments
requests
"""

import requests

DOMAIN  = "fap.no"
SUBDOMAIN  = "tw"

CLIENTID = ""
APIKEY = ""
APIURL = "https://api.digitalocean.com/domains/"
APIURL2 = "client_id=%s&api_key=%s" % (CLIENTID, APIKEY)

def get_public_ip():
    r = requests.get("http://canihazip.com/s")
    return r.text

def get_record_id(domain, subdomain=None):
    url = "%s/records?%s" % (domain, APIURL2)
    r = requests.get(APIURL + url).json()
    if r["status"] == "OK":
        for record in r["records"]:
            if subdomain == None and record["name"] == domain:
                return record["id"]
            elif record["name"] == subdomain:
                return record["id"]
        return False    
    else:
        return False

def update_record(domain, ip, subdomain=None):
    url = "%s/records/%s/edit?%s&data=%s" % (domain, get_record_id(domain, subdomain=subdomain), APIURL2, ip)
    r = requests.get(APIURL + url)
    if r.status_code == 200:
        return True
    else:
        return False
     

update_record(DOMAIN, get_public_ip(), subdomain=SUBDOMAIN)
                
                
    



