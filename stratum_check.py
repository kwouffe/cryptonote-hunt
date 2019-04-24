#!/usr/bin/env python
import sys
import json
from stratum_scanner import stratum_scan
import datetime

now = datetime.datetime.now().replace(microsecond=0)


def main():
    if len(sys.argv) != 2:
        print("Usage: python stratum_check.py stratum_list.json")
        sys.exit()
    else:
        with open(sys.argv[1], 'r') as stratum_file:
            stratum_dict = json.load(stratum_file)
        result=stratum_check(stratum_dict)


def stratum_check(stratum_dict):
    scan_result = {'stratum':[]}
    for stratum in stratum_dict['stratum']:
        result = stratum_scan(stratum['host'],stratum['port'])
        if result == False or result == {}:
            continue
        else:
            stratum['result']=result
            scan_result['stratum'].append(stratum)
    with open("./stratum_live/test.json", 'w') as data_file:
        data_file.write(json.dumps(scan_result, indent=4))






if __name__ == "__main__":
    # execute only if run as a script
    main()
