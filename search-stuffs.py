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
rules_dir = config['rules_dir']

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
    return(filtered_matches)

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
        return(filtered_matches)
#def

## testing
