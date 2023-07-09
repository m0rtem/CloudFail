# CloudFail

CloudFail is a tactical reconnaissance tool which aims to gather enough information about a target protected by Cloudflare in the hopes of discovering the location of the server. Using Tor to mask all requests, the tool as of right now has 3 different attack phases.

1. Misconfigured DNS scan using DNSDumpster.com.
2. Scan the Crimeflare.com database.
3. Bruteforce scan over 2500 subdomains.

![Example usage](http://puu.sh/pq7vH/62d56aa41f.png "Example usage")

> Please feel free to contribute to this project. If you have an idea or improvement issue a pull request!

#### Disclaimer
This tool is a PoC (Proof of Concept) and does not guarantee results.  It is possible to setup Cloudflare properly so that the IP is never released or logged anywhere; this is not often the case and hence why this tool exists.
This tool is only for academic purposes and testing  under controlled environments. Do not use without obtaining proper authorization
from the network owner of the network under testing.
The author bears no responsibility for any misuse of the tool.

#### Install on Kali/Debian

First we need to install pip3 for python3 dependencies:

```$ sudo apt-get install python3-pip```

Then we can run through dependency checks:

```$ pip3 install -r requirements.txt```

If this fails because of missing setuptools, do this:

```sudo apt-get install python3-setuptools```

#### Usage
```bash
python3 cloudfail.py -h                                                                                                                                                        ──(Sun,Jul09)─┘
   ____ _                 _ _____     _ _
  / ___| | ___  _   _  __| |  ___|_ _(_) |
 | |   | |/ _ \| | | |/ _` | |_ / _` | | |
 | |___| | (_) | |_| | (_| |  _| (_| | | |
  \____|_|\___/ \__,_|\__,_|_|  \__,_|_|_|
    v1.0.6                      by m0rtem


[12:13:59] Initializing CloudFail - the date is: 09/07/2023  
usage: cloudfail.py [-h] [-t TARGET] [-l LIST] [-T] [-u] [-s SUBDOMAINS] [-d TIMEOUT] [-o OUTPUT]

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        target url of website
  -l LIST, --list LIST  input target list file
  -T, --tor             enable TOR routing
  -u, --update          update databases
  -s SUBDOMAINS, --subdomains SUBDOMAINS
                        name of alternate subdomains list stored in the data directory
  -d TIMEOUT, --timeout TIMEOUT
                        timeout in seconds (default: 10)
  -o OUTPUT, --output OUTPUT
                        output file name
```
To run a scan against a target:

```python3 cloudfail.py --target seo.com```

```python3 cloudfail.py --list target.txt```

To run a scan against a target using Tor:

```service tor start```

(or if you are using Windows or Mac install vidalia or just run the Tor browser)

```python3 cloudfail.py --target seo.com --tor```

> Please make sure you are running with Python3 and not Python2.*.


#### Dependencies
**Python3**
* argparse
* colorama
* socket
* binascii
* datetime
* requests
* win_inet_pton
* dnspython

## Donate BTC
> 13eiCHxmAEaRZDXcgKJVtVnCKK5mTR1u1F

Buy me a beer or coffee... or both! 
If you donate send me a message and I will add you to the credits!
Thank YOU!
