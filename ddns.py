#!/usr/bin/python
""" 
Requierments:
requests
"""

import requests
from datetime import datetime

DOMAIN  = "fap.no"
SUBDOMAIN  = "tw"

CLIENTID = ""
APIKEY = ""
APIURL = "https://api.digitalocean.com/v1/domains/"
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


def get_current_dns_ip(domain, subdomain=None):
    url = "%s/records/%s?%s" % (domain, get_record_id(domain, subdomain=subdomain), APIURL2)
    r = requests.get(APIURL + url)
    return r.json()['record']['data']


def update_record(domain, ip, subdomain=None):
    url = "%s/records/%s/edit?%s&data=%s" % (domain, get_record_id(domain, subdomain=subdomain), APIURL2, ip)
    r = requests.get(APIURL + url)
    if r.status_code == 200:
        return True
    else:
        return False
     

if __name__ == "__main__":
    try:
        pub_ip = get_public_ip()
        dns_ip = get_current_dns_ip(DOMAIN, subdomain=SUBDOMAIN)

        if pub_ip == dns_ip:
            print("%s - Current ip: %s, no change, so no update" % (datetime.now(), pub_ip))
        else: 
            print("%s - IP has changed from %s to %s, updating" % (datetime.now(), dns_ip, pub_ip))
            if update_record(DOMAIN, pub_ip, subdomain=SUBDOMAIN):
                print("%s - Update successful" % datetime.now())
            else:
                print("%s - Update failed" % datetime.now())
                
    
    except:
        print("%s - Something went wrong, do you have internet?" % datetime.now())



