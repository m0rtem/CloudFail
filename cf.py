#!/usr/bin/env python3
import mmap
import argparse
import sys
from DNSDumpsterAPI import DNSDumpsterAPI
import colorama
from colorama import Fore, Back, Style
import json
import socket
import binascii
import datetime

colorama.init()

def print_out(data):
	time = datetime.datetime.now().time()
	timewithoutseconds = time.replace(second=0, microsecond=0)
	print(Style.NORMAL+"[",timewithoutseconds,"]",data+Style.RESET_ALL)

def ip_in_subnetwork(ip_address, subnetwork):
 
    """
    Returns True if the given IP address belongs to the
    subnetwork expressed in CIDR notation, otherwise False.
    Both parameters are strings.
 
    Both IPv4 addresses/subnetworks (e.g. "192.168.1.1"
    and "192.168.1.0/24") and IPv6 addresses/subnetworks (e.g.
    "2a02:a448:ddb0::" and "2a02:a448:ddb0::/44") are accepted.
    """
 
    (ip_integer, version1) = ip_to_integer(ip_address)
    (ip_lower, ip_upper, version2) = subnetwork_to_ip_range(subnetwork)
 
    if version1 != version2:
        raise ValueError("incompatible IP versions")
 
    return (ip_lower <= ip_integer <= ip_upper)
 
 
def ip_to_integer(ip_address):
 
    """
    Converts an IP address expressed as a string to its
    representation as an integer value and returns a tuple
    (ip_integer, version), with version being the IP version
    (either 4 or 6).
 
    Both IPv4 addresses (e.g. "192.168.1.1") and IPv6 addresses
    (e.g. "2a02:a448:ddb0::") are accepted.
    """
 
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
 
    """
    Returns a tuple (ip_lower, ip_upper, version) containing the
    integer values of the lower and upper IP addresses respectively
    in a subnetwork expressed in CIDR notation (as a string), with
    version being the subnetwork IP version (either 4 or 6).
 
    Both IPv4 subnetworks (e.g. "192.168.1.0/24") and IPv6
    subnetworks (e.g. "2a02:a448:ddb0::/44") are accepted.
    """
 
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

# END FUNCTIONS AND BEGIN ACTUAL LOGIC CODE

logo = """\
 _____ _           _ _____         _   
|     | |___ _ _ _| |   __|_ _ ___| |_ 
|   --| | . | | | . |   __| | |  _| '_|
|_____|_|___|___|___|__|  |___|___|_,_|

"""

print(Fore.RED+logo+Fore.RESET)

parser = argparse.ArgumentParser()
parser.add_argument("target", help="target url of website", type=str)
args = parser.parse_args()

print_out (Fore.CYAN + "Fetching initial information from: "+args.target+"...")
	
ip = socket.gethostbyname(args.target)
print_out(Fore.CYAN + "Server IP: "+ip)
print_out(Fore.CYAN + "Testing if "+ip+" is on the Cloudflare subnet...")

with open('data/cf-subnet.txt') as f:
	inCF = False
	for line in f:
		try:
			isInNetwork = ip_in_subnetwork(ip,line)
		except NetworkException as net_exc:
			print ("error parsing stream", net_exc)
		else:
			if isInNetwork:
				inCF = True
				break
			else:
				continue
				
if inCF:
	print_out (Style.BRIGHT+Fore.GREEN+ args.target+" is part of the Cloudflare network!")
else:
	print_out (Fore.RED + args.target+" is not part of the Cloudflare network, quitting...")
	sys.exit(0)
	
print_out (Fore.CYAN + "Testing for misconfigured DNS using dnsdumpster.com...")

res = DNSDumpsterAPI(False).search(args.target)

if res['dns_records']['dns']:	
	print_out (Fore.CYAN + "Looking for DNS...")
	for entry in res['dns_records']['dns']:
		provider = str(entry['provider'])
		if "CloudFlare" not in provider:
			print_out(Style.BRIGHT+Fore.GREEN+"{domain} {ip} {as} {provider} {country}".format(**entry))
	
if res['dns_records']['mx']:	
	print_out (Fore.CYAN + "Looking for MX...")
	for entry in res['dns_records']['mx']:
		provider = str(entry['provider'])
		if "CloudFlare" not in provider:
			print_out(Style.BRIGHT+Fore.GREEN+"{ip} {as} {provider} {country}".format(**entry))
	
if res['dns_records']['host']:
	print_out (Fore.CYAN + "Looking for HOSTS...")
	for entry in res['dns_records']['host']:
		provider = str(entry['provider'])
		if "CloudFlare" not in provider:
			print_out(Style.BRIGHT+Fore.GREEN+"{domain} {ip} {as} {provider} {country}".format(**entry))

if res['dns_records']['txt']:
	print_out (Fore.CYAN + "Dumping TXT record anyway...")
	for entry in res['dns_records']['txt']:
		print_out (entry)
	
print_out (Fore.CYAN + "Scanning crimeflare.com database...")


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
		print_out(Style.BRIGHT+Fore.GREEN+""+foundIp.strip())
else:
	print_out("Did not find anything.")