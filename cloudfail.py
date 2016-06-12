#!/usr/bin/env python3
import mmap
import argparse
import sys
import socket
import binascii
import datetime
import socks
import requests
import colorama
from colorama import Fore, Back, Style
from DNSDumpsterAPI import DNSDumpsterAPI

colorama.init(Style.BRIGHT)

def print_out(data):
	datetimestr = str(datetime.datetime.strftime(datetime.datetime.now(), '%H:%M:%S'))
	print(Style.NORMAL+"["+datetimestr+"] "+data+Style.RESET_ALL)

def ip_in_subnetwork(ip_address, subnetwork):

    (ip_integer, version1) = ip_to_integer(ip_address)
    (ip_lower, ip_upper, version2) = subnetwork_to_ip_range(subnetwork)
 
    if version1 != version2:
        raise ValueError("incompatible IP versions")
 
    return (ip_lower <= ip_integer <= ip_upper)
 
 
def ip_to_integer(ip_address):

    # try parsing the IP address first as IPv4, then as IPv6
    for version in (socket.AF_INET, socket.AF_INET6):
 
        try:
            ip_hex = socket.inet_pton(version, ip_address)
            ip_integer = int(binascii.hexlify(ip_hex), 16)
 
            return (ip_integer, 4 if version == socket.AF_INET else 6)
        except:
            pass
 
    raise ValueError("invalid IP address")
 
 
def subnetwork_to_ip_range(subnetwork):

    try:
        fragments = subnetwork.split('/')
        network_prefix = fragments[0]
        netmask_len = int(fragments[1])
 
        # try parsing the subnetwork first as IPv4, then as IPv6
        for version in (socket.AF_INET, socket.AF_INET6):
 
            ip_len = 32 if version == socket.AF_INET else 128
 
            try:
                suffix_mask = (1 << (ip_len - netmask_len)) - 1
                netmask = ((1 << ip_len) - 1) - suffix_mask
                ip_hex = socket.inet_pton(version, network_prefix)
                ip_lower = int(binascii.hexlify(ip_hex), 16) & netmask
                ip_upper = ip_lower + suffix_mask
 
                return (ip_lower,
                        ip_upper,
                        4 if version == socket.AF_INET else 6)
            except:
                pass
    except:
        pass
 
    raise ValueError("invalid subnetwork")
	
def dnsdumpster(target):
	print_out (Fore.CYAN + "Testing for misconfigured DNS using dnsdumpster...")

	res = DNSDumpsterAPI(False).search(target)

	if res['dns_records']['host']:
		for entry in res['dns_records']['host']:
			provider = str(entry['provider'])
			if "CloudFlare" not in provider:
				print_out(Style.BRIGHT+Fore.WHITE+"[FOUND:HOST] "+Fore.GREEN+"{domain} {ip} {as} {provider} {country}".format(**entry))
	
	if res['dns_records']['dns']:	
		for entry in res['dns_records']['dns']:
			provider = str(entry['provider'])
			if "CloudFlare" not in provider:
				print_out(Style.BRIGHT+Fore.WHITE+"[FOUND:DNS] "+Fore.GREEN+"{domain} {ip} {as} {provider} {country}".format(**entry))
		
	if res['dns_records']['mx']:	
		for entry in res['dns_records']['mx']:
			provider = str(entry['provider'])
			if "CloudFlare" not in provider:
				print_out(Style.BRIGHT+Fore.WHITE+"[FOUND:MX] "+Fore.GREEN+"{ip} {as} {provider} {domain}".format(**entry))

	#if res['dns_records']['txt']:
		#for entry in res['dns_records']['txt']:
			#print_out (entry)
			
def crimeflare(target):
	print_out (Fore.CYAN + "Scanning crimeflare database...")

	with open("data/ipout", "r") as ins:
		crimeFoundArray = []
		for line in ins:
			lineExploded = line.split(" ")
			if lineExploded[1] == args.target:
				crimeFoundArray.append(lineExploded[2])
			else:
				continue
	if(len(crimeFoundArray) != 0):
		for foundIp in crimeFoundArray:
			print_out(Style.BRIGHT+Fore.WHITE+"[FOUND:IP] "+Fore.GREEN+""+foundIp.strip())
	else:
		print_out("Did not find anything.")
		
def init(target):
	print_out (Fore.CYAN + "Fetching initial information from: "+args.target+"...")

	try:
		ip = socket.gethostbyname(args.target)
	except NetworkException as net_exc:
		print ("error parsing stream", net_exc)
		sys.exit(0)

	print_out(Fore.CYAN + "Server IP: "+ip)
	print_out(Fore.CYAN + "Testing if "+args.target+" is on the Cloudflare network...")

	ifIpIsWithin = inCloudFlare(ip)
					
	if ifIpIsWithin:
		print_out (Style.BRIGHT+Fore.GREEN+ args.target+" is part of the Cloudflare network!")
	else:
		print_out (Fore.RED + args.target+" is not part of the Cloudflare network, quitting...")
		sys.exit(0)
		
		
def inCloudFlare(ip):
	with open('data/cf-subnet.txt') as f:
		for line in f:
			isInNetwork = ip_in_subnetwork(ip,line)
			if isInNetwork:
				return True
			else:
				
				continue
		return False
		
def subdomain_scan(target):
	i = 0
	with open("data/subdomains.txt", "r") as wordlist:
		numOfLines = len(open("data/subdomains.txt").readlines(  ))
		numOfLines = str(numOfLines)
		print_out(Fore.CYAN + "Scanning "+numOfLines+" subdomains, please wait...")
		for word in wordlist:
			subdomain = "{}.{}".format(word.strip(), target)
			try:
				target_http = requests.get("http://"+subdomain)
				target_http = str(target_http.status_code)
				ip = socket.gethostbyname(subdomain)
				ifIpIsWithin = inCloudFlare(ip)
								
				if not ifIpIsWithin:
					i+= 1
					print_out(Style.BRIGHT+Fore.WHITE+"[FOUND:SUBDOMAIN] "+Fore.GREEN + "FOUND: " + subdomain + " IP: " + ip + " HTTP: " + target_http)
				else:
					print_out(Style.BRIGHT+Fore.WHITE+"[FOUND:SUBDOMAIN] "+Fore.RED + "FOUND: " + subdomain + " ON CLOUDFLARE NETWORK!")
					continue

			except requests.exceptions.RequestException as e:
				continue
		if(i == 0):
			print_out(Fore.CYAN + "Scanning finished, we did not find anything sorry...");
		else:
			print_out(Fore.CYAN + "Scanning finished...");
				
# END FUNCTIONS

logo = """\
   ____ _                 _ _____     _ _ 
  / ___| | ___  _   _  __| |  ___|_ _(_) |
 | |   | |/ _ \| | | |/ _` | |_ / _` | | |
 | |___| | (_) | |_| | (_| |  _| (_| | | |
  \____|_|\___/ \__,_|\__,_|_|  \__,_|_|_|
    v1.0                        by m0rtem

"""

print(Fore.RED+Style.BRIGHT+logo+Fore.RESET)
datetimestr = str(datetime.datetime.strftime(datetime.datetime.now(), '%d/%m/%Y %H:%M:%S'))
print_out("Initializing CloudFail - the date/time is: "+datetimestr)

parser = argparse.ArgumentParser()
parser.add_argument("--target", help="target url of website", type=str)
parser.add_argument('--tor', dest='tor', action='store_true', help="whether to route traffic through TOR or not")
parser.add_argument('--no-tor', dest='tor', action='store_false', help="whether to route traffic through TOR or not")
parser.set_defaults(tor=False)

args = parser.parse_args()

if(args.tor == True):
	ipcheck_url = 'http://canihazip.com/s'
	socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, '127.0.0.1', 9050)
	socket.socket = socks.socksocket
	try:
		tor_ip = requests.get(ipcheck_url)
		tor_ip = str(tor_ip.text)
		
		print_out(Fore.WHITE + Style.BRIGHT+"TOR connection established!")
		print_out(Fore.WHITE + Style.BRIGHT+"New IP: "+tor_ip)
		
	except requests.exceptions.RequestException as e:
		print (e, net_exc)
		sys.exit(0)
try:
    # Initialize CloudFaile
	init(args.target)
		
	# Scan DNSdumpster.com
	dnsdumpster(args.target)

	# Scan Crimeflare database
	crimeflare(args.target)

	# Scan subdomains with or without TOR
	subdomain_scan(args.target)
except KeyboardInterrupt:
    sys.exit(0)