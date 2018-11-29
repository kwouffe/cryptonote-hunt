import string
import base64
import re
from timeout import timeout

#### testing ####

samples_dir = './samples/'

#def main():
#    print(extract_base64_strings('8f535636c50dae96a3734d792231a028305c435ca02531cc0c8c327358886ecb'))

#### testing ####

def isBase64(s):
    try:
        recode=base64.b64encode(base64.b64decode(s))
        if (str(recode) in str(s) or str(s) in str(recode)) and not s.isdecimal() and not s.isupper() and not s.islower() and not s.isalpha():
            return True
    except Exception:
        return False



def strings(filename, min=90):
    with open(filename, errors="ignore") as f:  # Python 3.x
        result = ""
        for c in f.read():
            if c in string.printable:
                result += c
                continue
            if len(result) >= min:
                yield result
            result = ""
        if len(result) >= min:  # catch result at EOF
            yield result

def extract_base64_strings(sha256):
    base64_strings = []
    for s in strings(samples_dir + sha256):
        substrings = []
        with timeout(seconds=30):
            try:
                substrings = re.findall(r'(?:[A-Za-z0-9+/]{4}){2,}(?:[A-Za-z0-9+/]{2}[AEIMQUYcgkosw048]=|[A-Za-z0-9+/][AQgw]==)', s)
            except Exception:
                substrings = [s]
        for ss in substrings:
            if isBase64(ss):
                base64_strings.append(ss)
    return base64_strings

#main()
