import string
import re
import yara
import common
import json
import copy
import base64

#load config file
config=common.config()

#load needed params
samples_dir = config['samples_dir']
rules_dir = config['rules_dir']
json_db = config['json_db']
domains_file = config['domains_file']

with open(json_db, 'r') as db_file:
    db = json.load(db_file)

domain_list = open(domains_file).read().splitlines()

stratum_rule = yara.compile(filepath = rules_dir + './stratum.yara')
json_rule = yara.compile(filepath = rules_dir + './json_config_url.yara')

def mining_domains(sample):
    sample_path = samples_dir + sample['sha256']
    matching_domains=[]
    sample['mining_domains']=[]
    #search for known domains
    for domain in domain_list:
        rule= yara.compile(source='rule foo: bar {strings: $a = "' + domain + '" condition: $a}')
        matches = rule.match(sample_path)
        if matches != []:
            matching_domains.append(domain)
        if 'base64list' in sample.keys():
            for b64 in sample['base64list']:
                decoded = base64.b64decode(b64)
                matches = rule.match(data=str(decoded))
                if matches != [] and domain not in matching_domains:
                    matching_domains.append(domain)
    #search for others (stratum+tcp)
    matches = stratum_rule.match(sample_path)
    if matches != []:
        for match in matches[0].strings:
            if "@" in str(match):
                domain = str(match).split("@")[1].split(":")[0]
            else:
                domain = str(match).split("//")[1].split(":")[0]
            if domain not in matching_domains:
                matching_domains.append(domain)
    #search for others (stratum+tcp) in base64 encoded strings
    if 'base64list' in sample.keys():
        for b64 in sample['base64list']:
            decoded = base64.b64decode(b64)
            matches = stratum_rule.match(data=str(decoded))
            if matches != []:
                for match in matches[0].strings:
                    if "@" in str(match):
                        domain = str(match).split("@")[1].split(":")[0]
                    else:
                        domain = str(match).split("//")[1].split(":")[0]
                    if domain not in matching_domains:
                        matching_domains.append(domain)
    #search for json config
    matches = json_rule.match(sample_path)
    if matches != []:
        for match in matches[0].strings:
            if "//" in match:
                domain = str(match).split("\"")[3].split("//")[1].split(":")[0]
            else:
                domain = str(match).split("\"")[3].split(":")[0]
            if "\\x" in domain or "http" in domain or "127.0.0.1" in domain or "\\\\" in domain or len(domain) < 4:
                continue
            if domain not in matching_domains:
                matching_domains.append(domain)
    #search for json config in base64 encoded strings
    if 'base64list' in sample.keys():
        for b64 in sample['base64list']:
            decoded = base64.b64decode(b64)
            matches = json_rule.match(data=str(decoded))
            if matches != []:
                for match in matches[0].strings:
                    if "//" in match:
                        domain = str(match).split("\"")[3].split("//")[1].split(":")[0]
                    else:
                        domain = str(match).split("\"")[3].split(":")[0]
                    if "\\x" in domain or "http" in domain or "127.0.0.1" in domain or "\\\\" in domain or len(domain) < 4:
                        continue
                    if domain not in matching_domains:
                        matching_domains.append(domain)
    sample['mining_domains']=matching_domains
    print(matching_domains)
    return sample

def search_b64():
    for sample in db['samples']:
        if sample['sha256'] == '2bbb3d1b44c8aa10bf901842a7db5c64192751296351c0558969d92eeddbc4c4':
            mining_domains(sample)
#DEBUG
#search_b64()
