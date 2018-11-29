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
from checkcryptonote import is_valid_wallet

#load config file
config=common.config()

#load needed params
samples_dir = config['samples_dir']
rules_dir = config['rules_dir']




def MoneroWallet(sha256, *base64list):
    #base64list = extract_base64_strings(sha256)
    regex_monero = r"(4[0-9AB][0-9a-zA-Z]{93,104})"
    sample_path = samples_dir + sha256
    Monero_rule = yara.compile(filepath = rules_dir + './monerowallet.yara')
    matches = Monero_rule.match(sample_path)
    if matches != []:
        filtered_matches = []
        for match in matches[0].strings:
            wallet_addr = re.search(regex_monero, str(match[2]))
            if not wallet_addr.group(0).islower() and not wallet_addr.group(0).isupper() and not wallet_addr.group(0).isdecimal() and not wallet_addr.group(0).isalpha() and wallet_addr.group(0) not in filtered_matches and wallet_addr.group(0) not in str(base64list) and wallet_addr.group(0) not in '48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgzYnDK9URnRoJMk1j8nLwEVsaSWJ4fhdUyZijBGUicoD':
                if is_valid_wallet(wallet_addr.group(0)):
                    filtered_matches.append(wallet_addr.group(0))
        if len(filtered_matches) < 5:
            return filtered_matches
        else:
            return []
    else:
        return []

def SumoWallet(sha256, *base64list):
    #base64list = extract_base64_strings(sha256)
    regex_sumo = r"(Sumoo[0-9a-zA-Z]{94})"
    sample_path = samples_dir + sha256
    Sumo_rule = yara.compile(filepath = rules_dir + './sumowallet.yara')
    matches = Sumo_rule.match(sample_path)
    if matches != []:
        filtered_matches = []
        for match in matches[0].strings:
            wallet_addr = re.search(regex_sumo, str(match[2]))
            if not wallet_addr.group(0).islower() and not wallet_addr.group(0).isupper() and not wallet_addr.group(0).isdecimal() and not wallet_addr.group(0).isalpha() and wallet_addr.group(0) not in filtered_matches and wallet_addr.group(0) not in str(base64list):
                filtered_matches.append(wallet_addr.group(0))
        if len(filtered_matches) < 5:
            return filtered_matches
        else:
            return []
    else:
        return []

def AeonWallet(sha256, *base64list):
    regex_aeon = r"(Wm[st]{1}[0-9a-zA-Z]{94})"
    sample_path = samples_dir + sha256
    Aeon_rule = yara.compile(filepath = rules_dir + './aeonwallet.yara')
    matches = Aeon_rule.match(sample_path)
    if matches != []:
        filtered_matches = []
        for match in matches[0].strings:
            wallet_addr = re.search(regex_aeon, str(match[2]))
            if not wallet_addr.group(0).islower() and not wallet_addr.group(0).isupper() and not wallet_addr.group(0).isdecimal() and not wallet_addr.group(0).isalpha() and wallet_addr.group(0) not in filtered_matches and wallet_addr.group(0) not in str(base64list):
                filtered_matches.append(wallet_addr.group(0))
        if len(filtered_matches) < 5:
            return filtered_matches
        else:
            return []
    else:
        return []

def ByteWallet(sha256, *base64list):
    regex_byte = r"(2[0-9AB][0-9a-zA-Z]{93})"
    sample_path = samples_dir + sha256
    Byte_rule = yara.compile(filepath = rules_dir + './bytecoinwallet.yara')
    matches = Byte_rule.match(sample_path)
    if matches != []:
        filtered_matches = []
        for match in matches[0].strings:
            wallet_addr = re.search(regex_byte, str(match[2]))
            if not wallet_addr.group(0).islower() and not wallet_addr.group(0).isupper() and not wallet_addr.group(0).isdecimal() and not wallet_addr.group(0).isalpha() and wallet_addr.group(0) not in filtered_matches and wallet_addr.group(0) not in str(base64list):
                filtered_matches.append(wallet_addr.group(0))
        if len(filtered_matches) < 5:
            return filtered_matches
        else:
            return []
    else:
        return []

def DashWallet(sha256, *base64list):
    regex_dash = r"(D[0-9a-zA-Z]{94})"
    sample_path = samples_dir + sha256
    Dash_rule = yara.compile(filepath = rules_dir + './dashcoinwallet.yara')
    matches = Dash_rule.match(sample_path)
    if matches != []:
        filtered_matches = []
        for match in matches[0].strings:
            wallet_addr = re.search(regex_dash, str(match[2]))
            if not wallet_addr.group(0).islower() and not wallet_addr.group(0).isupper() and not wallet_addr.group(0).isdecimal() and not wallet_addr.group(0).isalpha() and wallet_addr.group(0) not in filtered_matches and wallet_addr.group(0) not in str(base64list):
                filtered_matches.append(wallet_addr.group(0))
        if len(filtered_matches) < 5:
            return filtered_matches
        else:
            return []
    else:
        return []

def DigitalNoteWallet(sha256, *base64list):
    regex_digital = r"(dd[a-z][0-9a-zA-Z]{94})"
    sample_path = samples_dir + sha256
    Digital_rule = yara.compile(filepath = rules_dir + './digitalwallet.yara')
    matches = Digital_rule.match(sample_path)
    if matches != []:
        filtered_matches = []
        for match in matches[0].strings:
            wallet_addr = re.search(regex_digital, str(match[2]))
            if not wallet_addr.group(0).islower() and not wallet_addr.group(0).isupper() and not wallet_addr.group(0).isdecimal() and not wallet_addr.group(0).isalpha() and wallet_addr.group(0) not in filtered_matches and wallet_addr.group(0) not in str(base64list):
                filtered_matches.append(wallet_addr.group(0))
        if len(filtered_matches) < 5:
            return filtered_matches
        else:
            return []
    else:
        return []

def FantomWallet(sha256, *base64list):
    regex_fantom = r"(6[0-9a-zA-Z]{94})"
    sample_path = samples_dir + sha256
    Fantom_rule = yara.compile(filepath = rules_dir + './fantomwallet.yara')
    matches = Fantom_rule.match(sample_path)
    if matches != []:
        filtered_matches = []
        for match in matches[0].strings:
            wallet_addr = re.search(regex_fantom, str(match[2]))
            if not wallet_addr.group(0).islower() and not wallet_addr.group(0).isupper() and not wallet_addr.group(0).isdecimal() and not wallet_addr.group(0).isalpha() and wallet_addr.group(0) not in filtered_matches and wallet_addr.group(0) not in str(base64list):
                filtered_matches.append(wallet_addr.group(0))
        if len(filtered_matches) < 5:
            return filtered_matches
        else:
            return []
    else:
        return []

def QuazarWallet(sha256, *base64list):
    regex_quazar = r"(1[0-9a-zA-Z]{94})"
    sample_path = samples_dir + sha256
    Quazar_rule = yara.compile(filepath = rules_dir + './quazarwallet.yara')
    matches = Quazar_rule.match(sample_path)
    if matches != []:
        filtered_matches = []
        for match in matches[0].strings:
            wallet_addr = re.search(regex_quazar, str(match[2]))
            if not wallet_addr.group(0).islower() and not wallet_addr.group(0).isupper() and not wallet_addr.group(0).isdecimal() and not wallet_addr.group(0).isalpha() and wallet_addr.group(0) not in filtered_matches and wallet_addr.group(0) not in str(base64list):
                filtered_matches.append(wallet_addr.group(0))
        if len(filtered_matches) < 5:
            return filtered_matches
        else:
            return []
    else:
        return []
