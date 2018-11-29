#!/usr/bin/env python
import base58
import sha3
from binascii import hexlify, unhexlify


def is_valid_wallet(wallet):
    try:
        pubAddrHex = base58.decode(wallet)
        pubAddrChksum = pubAddrHex[-8:]
        pubAddrForHash = pubAddrHex[:-8]
        k = sha3.keccak_256()
        k.update(unhexlify(pubAddrForHash))
        pubAddrHash = k.hexdigest()
        pubAddrChksum2 = pubAddrHash[:8]
        if pubAddrChksum2 == pubAddrChksum:
            #print("True: %s" % wallet)
            return True
        else:
            #print("False: %s" % wallet)
            return False
    except Exception:
        #print("False: %s" % wallet)
        return False
