# Introduction
In the world of cryptocurrency-related malware, mining botnets are a growing threat for organizations. It is also not unusual today to have banking malware, ransomware, or spyware embedding cryptomining capabilities.

In this presentation we explain how to leverage publicly available sources for hunting cryptomining malicious activities. We focus on a common behavior of such malicious activities: using collaborative work to mine cryptocurrencies.

All the tools and scripts detailed in this presentation are or will be available in a GitHub repository: <https://github.com/kwouffe/>

# Stratum Mining Protocol and Mining Pools
In the world of cryptomining (legitimate or not), almost nobody solo-mines as the probability of receiving the reward is getting lower with the age of the mined cryptocurrency. This is why most miners will rely on mining pools. The idea behind it is that the work is distributed between participants of the pool and the reward is shared based on the provided workload.

To communicate with the mining pool, the `Stratum mining protocol` is used ^[<https://en.bitcoinwiki.org/wiki/Stratum_mining_protocol>]. `Stratum` protocol was developed in 2012 as a replacement for the obsolete `getwork` protocol. `Stratum` protocol is a line-based protocol over TCP sockets (unencrypted) with payload encoded as JSON-RPC messages.

Most mining pools have different domains/IPs used for `Stratum` protocol, based on geolocation of the miners. Those domains can be used for detection of mining activities.

In this presentation we shortly explain the protocol and its different messages (authentication, job assigment, etc.). Snort/Suricata rules are available in the github repository. It is the starting point of the presentation as most of the strategies we show are related to how the interaction with the `Stratum` protocol can be used to build detection capabilities.



# Hunting and Processing Cryptomining Samples
In this part we present the first strategy. It is adapted from previous work dedicated to CryptoNote-related malware, presented at BotConf in 2018^[<https://github.com/kwouffe/cryptonote-hunt/blob/master/Cryptonote-hunting-1.3.pdf>]. The strategy is to gather malware samples involved in cryptomining and to extract useful information from them. In the previous work, we focused on wallet addresses. In this presentation we focus on how to extract the domains or IPs used to communicate with the mining pool.

## Hunting for Samples
In this part we present how we hunt for crypto-mining samples. We mostly rely on internal cases, YARA rules against malware repositories (free and non-free) or online sandboxes (YARA + samples connecting to known cryptomining domains).

Regarding YARA rules, we create new one each time we identify new tricks used by cryptominers. A very simple example looking for reference to `CryptoNight` and `Stratum mining protocol`:

            rule mining_cryptonote_basic {
              strings:
                  $a1 = "stratum+tcp://"
                  $a2 = "cryptonight"

              condition:
                  $a1 and $a2
            }

All YARA rules we used are shared via our GitHub repository.

We also wrote regular expression to detect pattern of wallet addresses (often used for authentication through the `Stratum` protocol) and cryptographic validation of the addresses found (as an example, based on the `Cryptonote` initial whitepaper^[<https://cryptonote.org/cns/cns007.txt>]).

As the project is ongoing, we present cases for other families of crypto-currencies.

## Static Analysis - Extracting Mining Configuration

The approach to static analysis is the following:

 - use YARA rules to identify the type of miner embedded in the samples,
 - identify how the mining process is started,
     - hardcoded command-line,
     - embedded configuration file,
     - encoded configuration,
     - download of configuration file,
 - extracting IOCs (mostly domains and ports used to communicate with the mining pools).


The way we extract IOCs is specific to the mining tool used by the malware. This list is non-exhaustive and growing.

As more and more malware use some obfuscation to hide its configuration, we also rely on different open-source projects to perform deobfuscation/unpacking/decompilation:

 - FLOSS^[<https://github.com/fireeye/flare-floss>]
 - Retdec decompiler^[<https://github.com/avast-tl/retdec>]
 - Snowman^[<https://derevenets.com/>]

We also look for Base64-encoded strings in the samples/decompiled code.

The following parts present different ways of configuring the mining processes (command-line or via a configuration file) and a table on how major types of mining software start the mining process.

### Hardcoded Command-Line (Cleartext or Encoded)

Some samples use simply a command line to start the mining process. The mining software can be downloaded from Internet or embedded in the samples. An example of command line:

    Miner -B -a cryptonight -o stratum+tcp://xmr.redacted.za:80 -u 44pgg5mYVH6Gn...eqQfvrdeGWzUdrADDu -p x -R 1

From there, it is quite easy to extract the domains, port and wallet address (useful for future hunting and correlation).

### Configuration File (Embedded or Downloaded)

Another option is to use a configuration file (TXT or JSON) to store the domains/IPs and port used for the `Stratum` protocol. As for the mining software, the configuration file can be downloaded from Internet or embedded in the samples.

The way this data is stored changes depending on the mining software, which is why it is important to first identify the type of mining software used.

### Types Mining Software

The following table explains for several types of mining software how to start the mining process via command-line and how the configuration is stored if a configuration file is used.


| Software | project URL                    | Hardcoded commandline example | config file | config file extract |
|----------|--------------------------------|-------------|-------------|---------------------|
| XMrig    | https://github.com/xmrig/xmrig | xmrig.exe --max-cpu-usage 85 --cpu-priority 3 -o xmr-classic.f2pool.com:13541 -u wallet_address.worker_name -p x -k | Yes (JSON)  |     "pools": [<br>{<br>"url": "pool.monero.hashvault.pro:3333",<br>"user": "4BrL51JCc9NGQ71k... |
| xmr-stak | https://github.com/fireice-uk/xmr-stak | No | Yes (pools.txt) | "pool_list" : [ <br> {"pool_address" : "haven.miner.rocks:4005", "wallet_address" : "hvxxzujE7USHRSMU... |
| cgminer  | https://github.com/ckolivas/cgminer/ | cgminer -o stratum+tcp://uk1.ghash.io:3333 -u username.worker -p X   | Yes (JSON)  | "pools" : [ {<br> "url" : "http://usa.wemineltc.com:3336",<br>"user" : "user.worker", |
| BFGminer | https://github.com/luke-jr/bfgminer | bfgminer -o stratum+tcp://stratum.slushpool.com:3333 -u YOUR_USER_NAME_OF_POOL -p YOUR_PASSWORD_OF_POOL | No | |
| ccminer | https://github.com/tpruvot/ccminer/ | ccminer-x64.exe -a x17 -o stratum+tcp://yiimp.eu:3777 -u DSqoG... -p X | Yes (JSON) | {<br>"url" :<br>"stratum+tcp://stratum.nicehash.com:3333",<br>"user" : "Bitcoin address",<br>"pass" : "p=0.8",<br>"algo" : "x11"<br>} |
| ethminer | https://github.com/ethereum-mining/ethminer | ethminer.exe --farm-recheck 200 -U -S eu1.ethermine.org:4444 -FS us1.ethermine.org:4444 -O X | No |  |
| claymore dual miner | https://github.com/nanopool/Claymore-Dual-Miner/ | EthDcrMiner64.exe -epool stratum+tcp://daggerhashimoto.eu.nicehash.com:3353 -ewal 1LmMN.. -epsw x -esm 3 -allpools 1 -estale 0 -dpool stratum+tcp://decred.eu.nicehash.com:3354 | Yes (TXT) | POOL: eth-eu1.nanopool.org:9999, WALLET: YOUR_WALLET/YOUR_WORKER/YOUR_EMAIL, PSW: x, WORKER: , ESM: 0, ALLPOOLS: 1<br></brPOOL:>POOL: eth-eu2.nanopool.org:9999, WALLET: YOUR_WALLET/YOUR_WORKER/YOUR_EMAIL, PSW: x, WORKER: , ESM: 0, ALLPOOLS: 1 |
| cpuminer | https://github.com/tpruvot/cpuminer-multi | cpuminer -a cryptonight -o stratum+tcp://pool.usxmrpool.com:3333 -u 48JvicghZ -p x | Yes (JSON) | {<br>"url" : "stratum+tcp://127.0.0.1:8332",v"user" : "rpcuser",<br>"pass" : "rpcpass",<br>} |

The list is non-exhaustive as we add content to it when we identify new mining software being used or embedded in malwares.

## Dynamic Analysis

Collected samples can be sent to sandboxes (public or internal) to perform dynamic analysis. Depending on the success of the sandbox, we can extract domains/IPs and ports used for the `Stratum` protocol.

### Parsing Sandboxes Reports for Mining Domains

Sandboxes provides different types of reports to look for relevant data:

 * extracted strings in samples and processes,
 * DNS requests,
 * network traffic and contacted hosts,
 * started processes (including command line).

Some data generated by the sandbox provides some additional useful information from which we can perform our own analysis:

 * extracted files and binaries,
 * network capture,
 * memory dump.

### Detecting Stratum Protocol in PCAPs
Some sandboxes provide network capture performed during the analysis (PCAP format). As the `Stratum` protocol uses unencrypted JSON over TCP, it is quite simple to identify the proper TCP stream using `pyshark` library in Python^[<https://github.com/KimiNewt/pyshark>].

Here is an exmaple of JSON data exchanged via the `Stratum` protocol:
```
{"method":"login","params":{"login":"4BrL51JCc9NGQ71kWhnYoDRffsDZy7m1HUU7MRU4nUMXAHNFBEJhkTZV9HdaL4gfuNBxLPc3BeMkLGaPbF5vWtANQmm4F1aSTkzJkmZqbi","pass":"x","agent":"XMRig/0.8.2"},"id":1}
{"id":1,"jsonrpc":"2.0","error":null,"result":{"id":"123489130288362","job":{"blob":"05059ed1bfcb057e68c2e40c6305fa9e2db80c6994aaa8f5d13588a15b0f641a0bda9fbe2836d500000000aee7784a6251e7592da89c746746883f70721c4cebe505219bc5e9458d45973f04","job_id":"617040931084193","target":"b88d0600"},"status":"OK"}}
{"method":"keepalived","params":{"id":"123489130288362"},"id":1}
{"id":1,"jsonrpc":"2.0","error":null,"result":{"status":"KEEPALIVED"}}
{"method":"submit","params":{"id":"123489130288362","job_id":"617040931084193","nonce":"80070000","result":"13349ec942808ba1c8a8555365b631edbd8a31f2da2be232bd20ae84426d0400"},"id":1}
{"id":1,"jsonrpc":"2.0","error":null,"result":{"status":"OK"}}
{"method":"submit","params":{"id":"123489130288362","job_id":"617040931084193","nonce":"2c0d0000","result":"c1c9a3ffff9ce6eae215b980bb4c130020add80bfbb1811815f332c256c30100"},"id":1}
{"id":1,"jsonrpc":"2.0","error":null,"result":{"status":"OK"}}
```

The identified stream will provide the TCP port and IP used. For the related domains, it is necessary to look for DNS queries/answer in the network capture:

```
Frame 2: 128 bytes on wire (1024 bits), 128 bytes captured (1024 bits)
Ethernet II, Src: 0a:00:27:00:00:00 (0a:00:27:00:00:00), Dst: 0a:00:27:45:ab:de (0a:00:27:45:ab:de)
Internet Protocol Version 4, Src: 8.8.8.8, Dst: 192.168.56.20
User Datagram Protocol, Src Port: 53, Dst Port: 60520
Domain Name System (response)
    Transaction ID: 0xe69b
    Flags: 0x8180 Standard query response, No error
    Questions: 1
    Answer RRs: 3
    Authority RRs: 0
    Additional RRs: 0
    Queries
        xmr-eu.dwarfpool.com: type A, class IN
    Answers
        xmr-eu.dwarfpool.com: type A, class IN, addr 79.137.57.106
            Name: xmr-eu.dwarfpool.com
            Type: A (Host Address) (1)
            Class: IN (0x0001)
            Time to live: 299
            Data length: 4
            Address: 79.137.57.106
        xmr-eu.dwarfpool.com: type A, class IN, addr 178.32.196.217
            Name: xmr-eu.dwarfpool.com
            Type: A (Host Address) (1)
            Class: IN (0x0001)
            Time to live: 299
            Data length: 4
            Address: 178.32.196.217
        xmr-eu.dwarfpool.com: type A, class IN, addr 178.32.145.31
            Name: xmr-eu.dwarfpool.com
            Type: A (Host Address) (1)
            Class: IN (0x0001)
            Time to live: 299
            Data length: 4
            Address: 178.32.145.31
    [Request In: 1]
    [Time: 0.017412000 seconds]
```

### Extracting Stratum-Related IOCs in Memory Dumps

We use volatility^[<https://github.com/volatilityfoundation/volatility>] to perform forensics on the downloaded memory dumps. As for static analysis, we use YARA rules to identify which type of miner is used and then extract the configuration:

 * use yarascan module,
 * dump matching processes,
 * regular expression on strings to extract configuration:
     * command-line,
     * configuration file.


# Looking for Stratum Servers
As mining malware connects to Internet via the `Stratum` protocol, the next tactical goal is to identify IP/domains hosting server. It is possible to use online services to do so or to perform the scanning ourselves. Finally, the last approach is to leverage legitimate mining pools APIs to obtain information about domains and ports used by the mining pool.


## Leveraging Internet Scanning Services

The main idea is to identify specific strings leading to domains/IPs and ports used for the `Stratum` protocol. To do so we are using some services already available online, which are providing results to Internet scans through their API. For now we use the following services:

 * Shodan^[<https://www.shodan.io/>]
 * Censys^[<https://censys.io/>]
 * Onyphe^[<https://www.onyphe.io/>]


### X-Stratum Custom HTTP Headers

Some mining pools provide in the headers of their websites the configuration for mining. It is found in the `X-Stratum` custom header, as described in the bitcoin wiki: <https://en.bitcoin.it/wiki/Getwork#stratum>:

```
HTTP/1.0 200 OK
Content-Type: application/json
Content-Length: 190
X-Stratum: stratum+tcp://litecoinpool.org:3333
```

### Miner HTTP Status

Some miners like `Xmrig` have an option to be running with an open service for remote configuration and status. Of course we can find some of those directly available on Internet. The service returns the actual configuration of the miner. Below an example:

```
HTTP/1.1 200 OK
Connection: Keep-Alive
Content-Length: 1585
Access-Control-Allow-Headers: Authorization, Content-Type
Access-Control-Allow-Methods: GET, PUT
Access-Control-Allow-Origin: *
Content-Type: application/json
Date: Sun, 23 Dec 2018 14:03:14 GMT

{
    "id": "2ee2e7634431965c",
    "worker_id": "ip-172-31-13-19",
    "version": "2.8.1-mo2",
    "kind": "cpu",
    "ua": "XMRig/2.8.1-mo2 (Linux x86_64) libuv/1.18.0 gcc/7.3.0",
    "cpu": {
        "brand": "Intel(R) Xeon(R) CPU E5-2670 v2 @ 2.50GHz",
        "aes": true,
        "x64": true,
        "sockets": 2
    },
    "algo": "cryptonight/2",
    "hugepages": true,
    "donate_level": 0,
    "hashrate": {
        "total": [
            716.9,
            717.7,
            0.0
        ],
        "highest": 751.17,
        "threads": [
            [
                178.34,
                178.62,
                0.0
            ],
            [
                177.64,
                178.04,
                0.0
            ],
            [
                174.7,
                174.99,
                0.0
            ],
            [
                186.2,
                186.04,
                0.0
            ]
        ]
    },
    "results": {
        "diff_current": 12803,
        "shares_good": 117493,
        "shares_total": 117496,
        "avg_time": 29,
        "hashes_total": 1164795207,
        "best": [
            373377076,
            225795724,
            197982538,
            172465207,
            167489797,
            142213918,
            131650101,
            126905879,
            125601849,
            119161305
        ],
        "error_log": []
    },
    "connection": {
        "pool": "gulf.moneroocean.stream:10008",
        "uptime": 1195392,
        "ping": 113,
        "failures": 3,
        "error_log": []
    }
}
```

The response consist of a json file from which we can extract domains/IP and port in `connection['pool']: gulf.moneroocean.stream:10008`.

### Stratum Servers Standard Messages

Some stratum servers return default messages:

 * `Mining server is Online`
 * `mining.set_difficulty`
 * `mining.notify`
 * `Wrong Wallet ID`
 * `Mining Pool Online`
 * `You are trying to connect to a Stratum server`

We can use above-mentioned scanning services to return domains/IP and ports containing those strings.

### Stratum Proxies

Some pools provide bridge between old HTTP/`getwork` protocol and `Stratum` protocol. They also have some specific headers.

 * Ethereum stratum proxy


Example:
```
HTTP/1.1 200 OK
Date: Sun, 23 Dec 2018 07:57:05 GMT
Content-Length: 338
Content-Type: text/html
Server: TwistedWeb/16.0.0

Ethereum stratum proxy<br>DAG-file: 04a3fa11bc92b068<br><br>Main server us2.ethermine.org:4444 (172.65.226.101) connected<br>Failover server1 us1.ethermine.org:14444 (172.65.218.238) connected<br>Failover server2 eu1.ethermine.org:4444 (172.65.207.106) connected<br>Failover server3 asia1.ethermine.org:4444 (172.65.231.156) connected<br>
```

We can extract configuration from the response: `us2.ethermine.org:4444`, `us1.ethermine.org:14444`, `eu1.ethermine.org:4444`, `asia1.ethermine.org:4444`.

### Detecting Mining Pool Websites

Legitimate mining pools provide to their users the configuration needed to collaborate to the mining. We can use scanning services to list websites of mining pool using specific keywords.

The list of keywords fits in two categories:

 * keywords used by most pools:
     * `scrypt`
     * `x-wallet-id`
     * `coin-logo`
     * `top 10 miners`
     * `pool blocks`
     * `Worker Statistics`
     * `Mining Pool\</title>`
     * `stratum+tcp`
 * keywords specific to open-source projects:
     * open-ethereum-pool
         * `\>open-ethereum-pool\</a>`
         * `open-ethereum-pool/config/environment`
     * node-cryptonote-pool
         * `<script src="config.js"></script>     <script src="custom.js"></script>`
         * `<script src="js/common.js"></script>``<script src="js/custom.js"></script>`
         *  `href="https://github.com/dvandal/cryptonote-nodejs-pool"`
         *  `href="//github.com/zone117x/node-cryptonote-pool"`

         * `#coinName`
     * nodejs-pool
         * `isActivePage('home')`
         * `<script src="globals.js"></script>`
         * ` href="https://github.com/Snipa22/nodejs-pool`

     * NOMP
         * `href="https://github.com/zone117x/node-open-mining-portal/ href="/api"`
         *  `href="https://github.com/foxer666/node-open-mining-portal"`

     * forks from node-cryptonote-pool
         * `href="https://github.com/forknote/cryptonote-forknote-pool"`
         * `href="https://github.com/SadBatman/cryptonote-sumokoin-pool/"`
         * `href="https://github.com/zelerius/zelerius-nodejs-pool"`
         * `href="https://github.com/fancoder/cryptonote-universal-pool"`
         * `href="https://github.com/Optmus/node-cryptonode-pool"`

Once the type of mining pool is identified, we can extract the configuration. The details are explained in the **Leveraging Mining Pools** chapter.

During our investigation, we add new mining pool project as we encounter them.

## Scanning for Known Stratum Ports

It is not unusual that configurations are kept by default or copied from another mining website. Because of that we observed that a lot of pools share the same ports for the `Stratum` protocol.

Based on the previously collected data, we build a list of known port used for the `Stratum` protocol. We can use this list to build our own scanner.

To perform the scanning, we initiate a TCP connection to open ports and send a fake JSON authentication package:

`{"method":"login","params":{"login":"MEOWWWW","pass":"MIAOU","agent":"XMRig/0.8.2"},"id":1}`

Based on the answer, we can guess if a Stratum server is running.

Example of possible answers from scanning:

 * error message:
     * `{"id":1,"jsonrpc":"2.0","error":{"code":-1,"message":"Invalid payment address provided"}}`
     * `{"error":[-3,"login",null],"id":1,"result":null}`
 * mining job:
     * `{"jsonrpc":"2.0","result":{"job":{"blob":"090994cd99e105cd907e72581063b914bf2e00e9c768b6b5776e29f7c32c196ec53ca57a697fed000000001cb23327a5c4379c90b3fd52ea6f98a5a59b6cd2105ed8d25b41c93ea25b5cba13","target":"e4a63d00","job_id":"86efec6c-269d-4c99-806b-6b3c886df888","time_to_live":5},"status":"OK","id":"df2e70ef-548c-4fb9-9756-215f30230769"},"id":1,"error":null}`

To validate the scan, we check if we receive a valid JSON file with specific keywords.

The scanner provides a list of valid Stratum servers in JSON format. The scanner will be available on our github account.

## Leveraging Mining Pools

We previously identified mining pool websites. When possible we tried to identify if a specific open-source project is used by the pool website. If so, we can look for configuration files or API endpoint to extract the Stratum configuration.

Below we shortly introduce a few open-source projects discovered while looking after mining pools.

### nodejs-pool

**nodejs-pool**^[<https://github.com/Snipa22/nodejs-pool>] is an open-source project used for mining cryptonote-related currencies.

Initial configuration is stored in a `globals.js` file as follows:

```
'use strict';

angular.module('pool.globals', [])

.factory('GLOBALS', function() {
	return {
		pool_name: "GNTL AEON",
		pool_name_long: "GNTL Aeon (AEON) Pool",
		api_url : 'https://aeon.pool.gntl.co.uk/api',
		api_refresh_interval: 5000,
		app_update_interval: 5*60000
	};
});
```

We can build an API request by extracting the `api_url` parameter. The `/pool/ports` endpoint gives us the domains/IP and port used for the `Stratum Mining protocol`:

```
$ curl https://aeon.pool.gntl.co.uk/api/pool/ports

{
  "solo": [
    {
      "host": {
        "ip": "10.192.168.31",
        "blockID": 1043442,
        "blockIDTime": 1547241078,
        "hostname": "aeon.pool.gntl.co.uk"
      },
      "port": 1111,
      "difficulty": 500000,
      "description": "Ultra High-End Hardware (around 25,000 h/s) ",
      "miners": 0
    }
  ],
  "pplns": [
    {
      "host": {
        "ip": "10.192.168.31",
        "blockID": 1043442,
        "blockIDTime": 1547241078,
        "hostname": "aeon.pool.gntl.co.uk"
      },
      "port": 2222,
      "difficulty": 1000,
      "description": "Very Low-End Hardware (around 50 h/s)",
      "miners": 6
    },
    {
      "host": {
        "ip": "10.192.168.31",
        "blockID": 1043442,
        "blockIDTime": 1547241078,
        "hostname": "aeon.pool.gntl.co.uk"
      },
      "port": 3333,
      "difficulty": 5000,
      "description": "Low-End Hardware (around 200 h/s)",
      "miners": 2
    },
    {
      "host": {
        "ip": "10.192.168.31",
        "blockID": 1043442,
        "blockIDTime": 1547241078,
        "hostname": "aeon.pool.gntl.co.uk"
      },
      "port": 4444,
      "difficulty": 10000,
      "description": "Medium-End Hardware (around 500 h/s)",
      "miners": 1
    },
    {
      "host": {
        "ip": "10.192.168.31",
        "blockID": 1043442,
        "blockIDTime": 1547241078,
        "hostname": "aeon.pool.gntl.co.uk"
      },
      "port": 7777,
      "difficulty": 25000,
      "description": "High-End Hardware (around 1,000 h/s)",
      "miners": 1
    },
    {
      "host": {
        "ip": "10.192.168.31",
        "blockID": 1043442,
        "blockIDTime": 1547241078,
        "hostname": "aeon.pool.gntl.co.uk"
      },
      "port": 8888,
      "difficulty": 200000,
      "description": "Very High-End Hardware (around 5,000 h/s)",
      "miners": 0
    },
    {
      "host": {
        "ip": "10.192.168.31",
        "blockID": 1043442,
        "blockIDTime": 1547241078,
        "hostname": "aeon.pool.gntl.co.uk"
      },
      "port": 9999,
      "difficulty": 400000,
      "description": "Ultra High-End Hardware (around 10,000 h/s)",
      "miners": 0
    }
  ]
}
```

We can easily parse the JSON output to extract hostnames and ports.

### node-cryptonote-pool and its Forks

**node-cryptonote-pool** ^[<https://github.com/zone117x/node-cryptonote-pool>]), **cryptonote-universal-pool** ^[<https://github.com/fancoder/cryptonote-universal-pool>] and **cryptonote-nodejs-pool** ^[<https://github.com/dvandal/cryptonote-nodejs-pool>] are used for mining cryptonote-related currencies.

They use the same API endpoints so the technique to recover the stratum configuration is the same.

Those pool softwares store their initial configuration in a `config.js` file as follow:

```
var api = "https://pool.croatpirineus.cat:8119";
var poolHost = "pool.croatpirineus.cat";

var email = "pool@croatpirineus.cat";
var telegram = "";
var discord = "";

var marketCurrencies = ["{symbol}-BTC", "{symbol}-EUR",  "{symbol}-ETH"];

var blockchainExplorer = "http://explorer.croatcoin.info/?hash={id}#blockchain_block";
var transactionExplorer = "http://explorer.croatcoin.info/?hash={id}#blockchain_transaction";

var themeCss = "themes/default.css";

var defaultLang = 'ca';
```

From this file, we can extract the `api` parameter. We can now connect to the API to extract the configuration by using the `live_stats` endpoint:

```
$ curl https://pool.croatpirineus.cat:8119/live_stats

{
  "config": {
    "poolHost": "pool.croatpirineus.cat",
    "ports": [
      {
        "port": 3333,
        "difficulty": 10000,
        "desc": "CPU (i3/i5)"
      },
      {
        "port": 4444,
        "difficulty": 50000,
        "desc": "CPU (i7)"
      },
      {
        "port": 5555,
        "difficulty": 200000,
        "desc": "GPU"
      },
      {
        "port": 7777,
        "difficulty": 1000000,
        "desc": "NICEHASH"
      },
      {
        "port": 9999,
        "difficulty": 200000,
        "desc": "GPU SSL",
        "ssl": true
      }
    ],
    "cnAlgorithm": "cryptonight",
...
```

We can easily parse the JSON output to extract hostnames and ports.


### open-ethereum-pool

**open-ethereum-pool**^[<https://github.com/sammy0New Open Mining Portal07/open-ethereum-pool>] is a project for mining Ethereum (ETH) crypto-currencies.

The frontend is a single-page `Ember.js` application that polls the pool API to render miner stats. There is no API endpoint to get the stratum configuration. However, the information is available through a `.js` file stored at `https://POOL/assets/open-ethereum-pool.js` or using the following naming convention:

 * `https://POOL/assets/open-ethereum-pool-XXX.js`
 * XXX is a base16 value randomly generated

The strategy is first to get the link to the `.js` file from the pool frontpage and then parse the downloaded `.js` file to extract the stratum configuration.


### Nomp (New Open Mining Portal) and its Forks

**Nomp** is a mining pool project which needs modules to manage the `Stratum` protocol. A lot of forks exist. To get the stratum configuration we need to parse the `/getting_started` html file. The configuration is stored in a `<div>` structure as follow:

```
<div id="coinInfo" class="hidden">
    <a href="#" id="coinInfoClose">×</a>
    <div><span class="coinInfoName"></span> Configuration / 設定:</div>
    <div id="coinInfoRows">
        <div id="coinInfoRowKeys">
            <div>Username / ユーザー名:</div>
            <div>Password / パスワード:</div>
            <div>Algorithm / アルゴリズム:</div>
            <div>CPU: (difficulty 0.1)</div>
            <div>GPU: (difficulty 1)</div>
            <div>High-End: (difficulty 10)</div>
            <div>ASIC: (difficulty 100)</div>
            <div>NiceHash: (difficulty 1000000)</div>
        </div>
        <div id="coinInfoRowValues">
            <div id="coinInfoUsername">your Susucoin address / すすコインのアドレス</div>
            <div>anything / 不要</div>
            <div>SHA256</div>
            <div>stratum+tcp://susu.mofumofu.me:3341</div>
            <div>stratum+tcp://susu.mofumofu.me:3342</div>
            <div>stratum+tcp://susu.mofumofu.me:3343</div>
            <div>stratum+tcp://susu.mofumofu.me:3344</div>
            <div>stratum+tcp://susu.mofumofu.me:3345</div>
        </div>
    </div>
    <div id="coinInfoCode">
        <div id="coinInfoCodeName">Examples / バッチファイル設定例:</div>
        <div id="coinInfoCodeClass">
            <div>CPU: minerd -a sha256d -o stratum+tcp://susu.mofumofu.me:3341 -u SeXbMBaax7NgnTEFEMxin5ycXy9r9CDBot.RIG1</div>
            <div> nVidia: ccminer -a sha256d -o stratum+tcp://susu.mofumofu.me:3342 -u SeXbMBaax7NgnTEFEMxin5ycXy9r9CDBot.RIG1<div/>
            <div>AMD: cgminer -a sha256d -o stratum+tcp://susu.mofumofu.me:3342 -u SeXbMBaax7NgnTEFEMxin5ycXy9r9CDBot.RIG1<div/>
            <div>NiceHash: ALGO: SHA256 STRATUM: susu.mofumofu.me PORT:3345 USER: SeXbMBaax7NgnTEFEMxin5ycXy9r9CDBot PASS: #</div>
        </div>
    </div>
</div>
```

### Other Pools

We identified several pool not using open-source projects, but used by malicious actors:

 * minergate
 * nanopool
 * dwarfpool
 * skypool
 * ...


For those we wrote custom techniques or API calls to extract the information.



# From IPs to Domains

Depending on the technique used, we may have IPs used for the `Stratum` protocol, but not the related domain.

Also, some samples use a simple trick to avoid being detected while mining on a legitimate mining pool: registering a custom domain resolving to a legitimate mining pool IP. By doing so, detection based on known mining domain names will fail.

We use the following services to obtain domains resolving to the discovered IPs:

 * Passive DNS data
 * Passive SSL data^[<https://www.circl.lu/services/passive-ssl/>]
 * BING search engine (with the `ip` keyword)
 * Reverse IP lookup


# Validating Gathered Data and Watchlists

In order to have an up-to-date list, we use the scanner we developped to verify that the IPs/domains are still used for the `Stratum` protocol. We keep historical data for backlog searches of mining activities. Keeping an up-to-date watchlist is useful for real-time detection.

# Consuming Generated Data

## Blocking and detection

Based on the research and generated data, we have several way to detect or block mining activities in our network:

 * IDS/IPS:
     * using list of IPs/domains being used for the `Stratum` protocol,
     * Snort rules for the `Stratum` protocol,
 * Blacklists of IPs/domains
     * on proxy level
     * on DNS level
 * Log monitoring on a SIEM:
     * Endpoint monitoring, using standard commands used to start the mining process (via Sigma rules^[<https://github.com/Neo23x0/sigma>])
     * Proxy/DNS logs (using IPs/domains as Indicator Of Compromise)
     * malicious hashes

## Sharing

The data generated can be useful to other organisations as well.

To share intel, we push to MISP^[<https://github.com/MISP/MISP>] the generated data by creating events for analysed samples and discovered `Stratum` servers. An other usage is to use the upadted lists as feeds for MISP:

* stratum IPs
* stratum domains
* malicious wallet adresses
* malicious hashes

Updated lists will be available on ou GitHub account.

## Hunting for More Samples

We can use the generated IPs/domains to look for more samples to analyse:

 * Looking for samples connecting to known IPs/domains in online sandboxes.
 * Writing custom YARA rules referencing to known IPs/domains to look on malware repositories.

## Getting Statistics of Mining Activities

As presented during Botconf 2018^[<https://github.com/kwouffe/cryptonote-hunt/blob/master/Cryptonote-hunting-1.3.pdf>], we can use the fact that most mining pools (especially those mining cryptonote-based currencies) use the same projects. We can use that to get statistics on the amount of coins mined by the mining botnet:

 * extract wallet addresses from samples,
 * validate wallet adresses,
 * request wallet statistics on all known mining pools (using open API),
 * do the math.

By doing this we can have a rough idea of the size of a mining botnet. Biggest ones made millions in crypto-currencies in the recent years.

# Some Interesting Cases

In thise part we will present some recent interesting recent cases, from interesting tricks being used to OPSEC fail from malware authors.

# Conclusions

It is well known that mining requires heavy resources, with a dedicated computer hardware. The need for a mining pool appeared when the difficulty for mining increased to the point where it could take centuries for slower miners to generate a block^[<https://en.wikipedia.org/wiki/Mining_pool>]. So it became much more convenient and accessible for normal users to pool their resources and to share the processing power over the internet in order to get a reward quickly, based on the amount of work they have done.
Unfortunately online criminals also developed an interest towards cryptomining as they can perform CPU-intensive mining tasks at no costs. What better option than using the resources available online, especially the mining pools, taking over and use them for cryptocurrency mining without the user's explicit consent.
Cryptomining malware gained more and more popularity as it can go undetected for a long time,can use all kind of devices connected to the internet(computers,smartphones, other electronics) and can generate enough revenue if the size and power of the mining botnet harnesses enough the processing power of the computers it controls.
The aim of this project was to gather more malware samples involved in cryptomining by analysing the Stratum protocol communication between mining malware and the mining pools and extracting relevant information. We showed different approaches to obtain information about domains, IPs and ports used by the mining pools, which in the end helped in generating new unique threat intelligence data . The collected data is intended to be used by different consumers for detection of potentially malicious activities.
