#!/usr/bin/env python
import yara
import re
import sys
import json
import os
import argparse
import time
import common
from check_base64 import extract_base64_strings


#load config file
config=common.config()

#load needed params
samples_dir = config['samples_dir']
json_db = config['json_db']
rules_dir = config['rules_dir']

with open(json_db, 'r') as db_file:
    db = json.load(db_file)

def xmrig(sha256):
    sample_path = samples_dir + sha256
    Xmrig_rule = yara.compile(filepath = rules_dir + './xmrig.yara')
    matches = Xmrig_rule.match(sample_path)
    if len(matches) != 0:
        return True
    else:
        return False


#look for wget/curl
def wget_curl(sha256):
    sample_path = samples_dir + sha256
    wgetcurl_rule = yara.compile(filepath = rules_dir + './wget_curl.yara')
    matches = wgetcurl_rule.match(sample_path)
    filtered_matches = []
    if matches != []:
        for match in matches[0].strings:
            tmp=''
            urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', str(match[2]))
            for url in urls:
                if "\\" in url or len(url) < 20:
                    tmp = ''
                elif ";" in url:
                    tmp = url.split(";")[0]
                elif "'" in url:
                    tmp = url.split("'")[0]
                elif ")" in url:
                    tmp = url.split(")")[0]
                else:
                    tmp = url
            if tmp != '' and tmp not in filtered_matches:
                filtered_matches.append(tmp)
    return filtered_matches

def powershell_url_param(sha256):
        sample_path = samples_dir + sha256
        powershell_url_rule = yara.compile(filepath = rules_dir + './powershell_url.yara')
        matches = powershell_url_rule.match(sample_path)
        filtered_matches = []
        if matches != []:
            for match in matches[0].strings:
                tmp=''
                urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', str(match[2]))
                for url in urls:
                    if "\\" in url or len(url) < 20:
                        tmp = ''
                    elif ";" in url:
                        tmp = url.split(";")[0]
                    elif "'" in url:
                        tmp = url.split("'")[0]
                    elif ")" in url:
                        tmp = url.split(")")[0]
                    else:
                        tmp = url
                if tmp != '' and tmp not in filtered_matches:
                    filtered_matches.append(tmp)
        return filtered_matches

def http_ext(sha256):
        sample_path = samples_dir + sha256
        http_ext_rule = yara.compile(filepath = rules_dir + './http_ext.yara')
        matches = http_ext_rule.match(sample_path)
        filtered_matches = []
        if matches != []:
            for match in matches[0].strings:
                tmp=''
                urls = re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', str(match[2]))
                for url in urls:
                    if url.count("/") < 3:
                        tmp = ''
                    elif "'" in url:
                        tmp = url.split("'")[0]
                    else:
                        tmp = url
                if tmp != '' and tmp not in filtered_matches:
                    filtered_matches.append(tmp)
        return filtered_matches
#def

## testing

def urls(sample):
    urls=[]
    #search for urls
    powershell_urls = powershell_url_param(sample['sha256'])
    urls += powershell_urls
    wget_curl_urls = wget_curl(sample['sha256'])
    urls += wget_curl_urls
    http_ext_urls = http_ext(sample['sha256'])
    urls += http_ext_urls
    #removing duplicates
    urls = list(set(urls))
    sample['urls']=urls
    return sample

def test():
    for sample in db['samples']:
        if sample['sha256'] == '38c381e1f0d8db27082d5809b70fc73d5c7137e266bc22b4301dd4bbd5e79637':
            print(urls(sample))

#test()
#print(http_ext("38c381e1f0d8db27082d5809b70fc73d5c7137e266bc22b4301dd4bbd5e79637"))
