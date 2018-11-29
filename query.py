#!/usr/bin/env python
import json
import common
import sys
import argparse
import copy

#load config file
config=common.config()

#load db
json_db = config['json_db']
domains_file = config['domains_file']

with open(json_db, 'r') as db_file:
    db = json.load(db_file)

def main():
    argv = sys.argv
    p = argparse.ArgumentParser(
        description='processing data from cryptonote hunting'
    )
    p.add_argument('--action', dest='action', choices=['domains','wallets','MISPjson'], required=True)
    args = p.parse_args(argv[1:])

    if args.action == 'domains':
        domains(db['samples'])
    if args.action == 'wallets':
        wallets(db['samples'])
    if args.action == 'MISPjson':
        MISPjson(db['samples'])

def domains(samples):
    domain_list=[]
    for sample in samples:
        if 'mining_domains' in sample.keys():
            domain_list += sample['mining_domains']
    domain_set=list(set(domain_list))
    known = open(domains_file).read().splitlines()
    for domain in domain_set:
        if domain not in known:
            print(domain)

def wallets(samples):
    out = {"wallets" :[]}
    for sample in samples:
        if sample['monero'] != []:
            for monero in sample['monero']:
                if monero not in str(out['wallets']):
                    out['wallets'].append({"wallet_addr":monero,"tags":["monero"],"coin":"XMR"})
        if sample['sumokoin'] != []:
            for sumokoin in sample['sumokoin']:
                if sumokoin not in str(out['wallets']):
                    out['wallets'].append({"wallet_addr":sumokoin,"tags":["sumokoin"],"coin":"SUMO"})
        if sample['aeon'] != []:
            for aeon in sample['aeon']:
                if aeon not in str(out['wallets']):
                    out['wallets'].append({"wallet_addr":aeon,"tags":["aeon"],"coin":"AEON"})
    print(json.dumps(out, indent=4))

def MISPjson(samples):
    out = {"response" :[]}
    for sample in samples:
        if sample['monero'] != []:
            event = {"Event":{"threat_level_id":"3","info":sample["sha256"],"Attribute":[]}}
            for monero in sample['monero']:
                event['Event']['Attribute'].append({"type":"xmr","category":"Financial fraud","to_ids":False,"value":monero})
            event['Event']['Attribute'].append({"type":"sha256","category": "Payload delivery","to_ids": True,"value":sample['sha256']})
            event['Event']['Attribute'].append({"type":"sha1","category": "Payload delivery","to_ids": True,"value":sample['sha1']})
            event['Event']['Attribute'].append({"type":"md5","category": "Payload delivery","to_ids": True,"value":sample['md5']})
            if sample['mining_domains'] != []:
                for domain in sample['mining_domains']:
                    event['Event']['Attribute'].append({"type":"domain","category": "Network activity","to_ids": True,"value":domain})
            if sample['urls'] != []:
                for url in sample['urls']:
                    event['Event']['Attribute'].append({"type":"url","category": "Network activity","to_ids": True,"value":url})
            out['response'].append(event)
    print(json.dumps(out, indent=4))
main()
