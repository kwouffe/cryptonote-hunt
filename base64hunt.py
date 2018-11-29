import string
import base64
import re
import yara
from timeout import timeout
from check_base64 import isBase64
import common
import json
import copy
from checkcryptonote import is_valid_wallet

#load config file
config=common.config()

#load needed params
samples_dir = config['samples_dir']
rules_dir = config['rules_dir']
json_db = config['json_db']

with open(json_db, 'r') as db_file:
    db = json.load(db_file)

#regexes
regex_monero = r"(4[0-9AB][0-9a-zA-Z]{93,104})"
regex_sumo = r"(Sumoo[0-9a-zA-Z]{94})"
regex_byte = r"(2[0-9AB][0-9a-zA-Z]{93})"
regex_aeon = r"(Wm[st]{1}[0-9a-zA-Z]{94})"


def process_sample_b64(sample):
    sample_new = copy.deepcopy(sample)
    #check nested base64
    b64tocheck = sample_new.pop('base64list')
    sample_new.update({'base64list':[]})
    print(len(b64tocheck))
    while b64tocheck != []:
        print(len(b64tocheck))
        #print(b64tocheck)
        checking=b64tocheck[0]
        if checking not in sample_new['base64list']:
            sample_new['base64list'].append(checking)
        substrings = []
        s = base64.b64decode(checking)
#        with timeout(seconds=30):
#            try:
        substrings = re.findall(r'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=|[A-Za-z0-9+/][AQgw]==)', str(s))
#            except Exception:
#                continue
        for ss in substrings:
            if isBase64(ss):
                b64tocheck.append(ss)
        b64tocheck.pop(0)

    for b64 in sample_new['base64list']:
        decoded = base64.b64decode(checking)
        # check for monero wallet addresses
        Monero_rule = yara.compile(filepath = rules_dir + './monerowallet.yara')
        matches = Monero_rule.match(data=str(decoded))
        if matches != []:
            filtered_matches = []
            for match in matches[0].strings:
                wallet_addr = re.search(regex_monero, str(match[2]))
                if not wallet_addr.group(0).islower() and not wallet_addr.group(0).isupper() and not wallet_addr.group(0).isdecimal() and not wallet_addr.group(0).isalpha() and wallet_addr.group(0) not in filtered_matches and wallet_addr.group(0) not in str(sample_new['base64list']) and wallet_addr.group(0) not in '48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgzYnDK9URnRoJMk1j8nLwEVsaSWJ4fhdUyZijBGUicoD':
                    if is_valid_wallet(wallet_addr.group(0)):
                        filtered_matches.append(wallet_addr.group(0))
            for match in filtered_matches:
                if match not in sample_new['monero']:
                    sample_new['monero'].append(match)
        # check for sumokoin wallet addresses
        Sumo_rule = yara.compile(filepath = rules_dir + './sumowallet.yara')
        matches = Sumo_rule.match(data=str(decoded))
        if matches != []:
            filtered_matches = []
            for match in matches[0].strings:
                wallet_addr = re.search(regex_sumo, str(match[2]))
                if not wallet_addr.group(0).islower() and not wallet_addr.group(0).isupper() and not wallet_addr.group(0).isdecimal() and not wallet_addr.group(0).isalpha() and wallet_addr.group(0) not in filtered_matches and wallet_addr.group(0) not in str(sample_new['base64list']) and wallet_addr.group(0) not in '48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgzYnDK9URnRoJMk1j8nLwEVsaSWJ4fhdUyZijBGUicoD':
                    if is_valid_wallet(wallet_addr.group(0)):
                        filtered_matches.append(wallet_addr.group(0))
            for match in filtered_matches:
                if match not in sample_new['sumokoin']:
                    sample_new['sumokoin'].append(match)
        # check for bytecoin wallet addresses
        Byte_rule = yara.compile(filepath = rules_dir + './bytecoinwallet.yara')
        matches = Byte_rule.match(data=str(decoded))
        if matches != []:
            filtered_matches = []
            for match in matches[0].strings:
                wallet_addr = re.search(regex_byte, str(match[2]))
                if not wallet_addr.group(0).islower() and not wallet_addr.group(0).isupper() and not wallet_addr.group(0).isdecimal() and not wallet_addr.group(0).isalpha() and wallet_addr.group(0) not in filtered_matches and wallet_addr.group(0) not in str(sample_new['base64list']) and wallet_addr.group(0) not in '48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgzYnDK9URnRoJMk1j8nLwEVsaSWJ4fhdUyZijBGUicoD':
                    if is_valid_wallet(wallet_addr.group(0)):
                        filtered_matches.append(wallet_addr.group(0))
            for match in filtered_matches:
                if match not in sample_new['bytecoin']:
                    sample_new['bytecoin'].append(match)
        # check for aeon wallet addresses
        Aeon_rule = yara.compile(filepath = rules_dir + './aeonwallet.yara')
        matches = Aeon_rule.match(data=str(decoded))
        if matches != []:
            filtered_matches = []
            for match in matches[0].strings:
                wallet_addr = re.search(regex_aeon, str(match[2]))
                if not wallet_addr.group(0).islower() and not wallet_addr.group(0).isupper() and not wallet_addr.group(0).isdecimal() and not wallet_addr.group(0).isalpha() and wallet_addr.group(0) not in filtered_matches and wallet_addr.group(0) not in str(sample_new['base64list']) and wallet_addr.group(0) not in '48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgzYnDK9URnRoJMk1j8nLwEVsaSWJ4fhdUyZijBGUicoD':
                    if is_valid_wallet(wallet_addr.group(0)):
                        filtered_matches.append(wallet_addr.group(0))
            for match in filtered_matches:
                if match not in sample_new['aeon']:
                    sample_new['aeon'].append(match)
    return sample_new
#process_sample_b64('c300c69b2f24f9ee20ade766a4ab3fd2e8f6b8468f9ef5b7319c8e68cada4a1b')

#DEBUG
#def search_b64():
#    for sample in db['samples']:
#        if sample['sha256'] == '4c463bbb2e2eec7c8bdb1cc68408d826e13bd894c5a693c8811840e1214e91e0' and 'base64list' in sample.keys():
#            if sample['base64list'] != []:
#                sample_index = db['samples'].index(sample)
#                updated_sample = process_sample_b64(sample)
#                db['samples'][sample_index] = updated_sample
#                print(db['samples'][1365])
                #print(sample['sha256'])
                #print(len(sample['base64list']))

#search_b64()
#process_sample_b64('34733be3b2cb64c5b456207fa51387f07fdcac244ada4070eb6b099eb0954fa7')
