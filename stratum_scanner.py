#!/usr/bin/env python
import sys
import json
import socket


def main():
    if len(sys.argv) != 3:
        print("Usage: python stratum-scanner.py host port")
        sys.exit()
    else:
        result=stratum_scan(sys.argv[1],int(sys.argv[2]))
        print(json.dumps(result, indent=4))

def stratum_scan(host,port):
    json_msg = "{\"method\":\"login\",\"params\":{\"login\":\"MEOWWWW\",\"pass\":\"MIAOU\",\"agent\":\"XMRig/0.8.2\"},\"id\":1}\r\n"

    # fix for some json errors
    null = None

    try :
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((host, port))
        result_json={}
        if result == 0:
            sock.sendto(json_msg.encode(),(host, port))
            msg = sock.recv(32768)
            sock.close()
            try:
                result_json=json.loads(msg.decode().split('\n', 1)[0])
            except:
                print(host + " " + str(port))
                print(msg.decode())
        sock.close()
        return result_json

    except KeyboardInterrupt:
        print("You pressed Ctrl+C")
        sys.exit()

    except socket.gaierror:
        return False

    except socket.error:
        return False

    except socket.timeout:
        return False



if __name__ == "__main__":
    # execute only if run as a script
    main()
