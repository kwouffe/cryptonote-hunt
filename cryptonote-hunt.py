#!/usr/bin/env python
import yara
import re
import sys
import json
import os
import argparse
import time
import common
import walletsearch
import base64hunt
import mining_domains
import searchstuffs
from check_base64 import extract_base64_strings

#load config file
config=common.config()

#load db
json_db = config['json_db']

with open(json_db, 'r') as db_file:
    db = json.load(db_file)


def main():
    argv = sys.argv
    p = argparse.ArgumentParser(
        description='processing crytonote-mining samples'
    )
    p.add_argument('--process', dest='process', choices=['base64','wallets','base64hunt','miningdomains','urls'], required=True)
    args = p.parse_args(argv[1:])

    if args.process == 'base64':
        with open('backup.json', 'w') as data_file:
            data_file.write(json.dumps(db, indent=4))
        updated_db = search_base64(db)
        with open(json_db, 'w') as data_file:
            data_file.write(json.dumps(updated_db, indent=4))

    if args.process == 'wallets':
        with open('backup.json', 'w') as data_file:
            data_file.write(json.dumps(db, indent=4))
        updated_db = search_wallets(db)
#        print(json.dumps(updated_db['samples'][:100], indent=4))
        with open(json_db, 'w') as data_file:
            data_file.write(json.dumps(updated_db, indent=4))

    if args.process == 'xmrig':
        with open('backup.json', 'w') as data_file:
            data_file.write(json.dumps(db, indent=4))
        updated_db = search_xmrig(db)
#        print(json.dumps(updated_db['samples'][:100], indent=4))
        with open(json_db, 'w') as data_file:
            data_file.write(json.dumps(updated_db, indent=4))

    if args.process == 'base64hunt':
        with open('backup.json', 'w') as data_file:
            data_file.write(json.dumps(db, indent=4))
        updated_db = base64hunting(db)
#        print(json.dumps(updated_db['samples'][:100], indent=4))
        with open(json_db, 'w') as data_file:
            data_file.write(json.dumps(updated_db, indent=4))

    if args.process == 'miningdomains':
        with open('backup.json', 'w') as data_file:
            data_file.write(json.dumps(db, indent=4))
        updated_db = search_mining_domains(db)
#        print(json.dumps(updated_db['samples'][:100], indent=4))
        with open(json_db, 'w') as data_file:
            data_file.write(json.dumps(updated_db, indent=4))

    if args.process == 'urls':
        with open('backup.json', 'w') as data_file:
            data_file.write(json.dumps(db, indent=4))
        updated_db = search_urls(db)
#        print(json.dumps(updated_db['samples'][:100], indent=4))
        with open(json_db, 'w') as data_file:
            data_file.write(json.dumps(updated_db, indent=4))

def search_base64(data):
    exception_list = open('exception-list-base64.txt').read().splitlines()
    for sample in data['samples']:
        if ('base64list' not in sample) and (sample['sha256'] not in exception_list):
            sample['base64list'] = extract_base64_strings(sample['sha256'])
    return data

def search_wallets(data):
    for sample in data['samples']:
        if 'monero' not in sample:
            if 'base64list' in sample:
                sample['monero'] = walletsearch.MoneroWallet(sample['sha256'],sample['base64list'])
            else:
                sample['monero'] = walletsearch.MoneroWallet(sample['sha256'])
        if 'sumokoin' not in sample:
            if 'base64list' in sample:
                sample['sumokoin'] = walletsearch.SumoWallet(sample['sha256'],sample['base64list'])
            else:
                sample['sumokoin'] = walletsearch.SumoWallet(sample['sha256'])
        if 'aeon' not in sample:
            if 'base64list' in sample:
                sample['aeon'] = walletsearch.AeonWallet(sample['sha256'],sample['base64list'])
            else:
                sample['aeon'] = walletsearch.AeonWallet(sample['sha256'])
        if 'bytecoin' not in sample:
            if 'base64list' in sample:
                sample['bytecoin'] = walletsearch.ByteWallet(sample['sha256'],sample['base64list'])
            else:
                sample['bytecoin'] = walletsearch.ByteWallet(sample['sha256'])
        if 'dashcoin' not in sample:
            if 'base64list' in sample:
                sample['dashcoin'] = walletsearch.DashWallet(sample['sha256'],sample['base64list'])
            else:
                sample['dashcoin'] = walletsearch.DashWallet(sample['sha256'])
        if 'digitalnote' not in sample:
            if 'base64list' in sample:
                sample['digitalnote'] = walletsearch.DigitalNoteWallet(sample['sha256'],sample['base64list'])
            else:
                sample['digitalnote'] = walletsearch.DigitalNoteWallet(sample['sha256'])
        if 'fantomcoin' not in sample:
            if 'base64list' in sample:
                sample['fantomcoin'] = walletsearch.FantomWallet(sample['sha256'],sample['base64list'])
            else:
                sample['fantomcoin'] = walletsearch.FantomWallet(sample['sha256'])
        if 'quazarcoin' not in sample:
            if 'base64list' in sample:
                sample['quazarcoin'] = walletsearch.QuazarWallet(sample['sha256'],sample['base64list'])
            else:
                sample['quazarcoin'] = walletsearch.QuazarWallet(sample['sha256'])
    return data

def base64hunting(data):
    for sample in data['samples']:
        if 'base64list' in sample.keys():
            if sample['base64list'] != []:
                sample_index = data['samples'].index(sample)
                updated_sample = base64hunt.process_sample_b64(sample)
                data['samples'][sample_index] = updated_sample
    return data

def search_xmrig(data):
    for sample in data['samples']:
        return 0

def search_mining_domains(data):
    for sample in data['samples']:
        sample_index = data['samples'].index(sample)
        updated_sample = mining_domains.mining_domains(sample)
        data['samples'][sample_index] = updated_sample
    return data

def search_urls(data):
    for sample in data['samples']:
        sample_index = data['samples'].index(sample)
        updated_sample = searchstuffs.urls(sample)
        data['samples'][sample_index] = updated_sample
    return data

main()
