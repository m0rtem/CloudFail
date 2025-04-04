"""
This is a wrapper for the official DNSDumpster.com API that maintains compatibility
with the old unofficial API's output structure.
"""

import requests
import base64
import json
import sys

class DNSDumpsterAPI(object):
    """DNSDumpsterAPI Main Handler - Now using official API but maintaining old output structure"""

    def __init__(self, api_key=None, verbose=False, session=None):
        self.verbose = verbose
        self.api_key = api_key
        if not session:
            self.session = requests.Session()
        else:
            self.session = session

    def display_message(self, s):
        if self.verbose:
            print('[verbose] %s' % s)

    def _convert_api_response(self, api_data, domain):
        """Convert the official API response to the old format"""
        result = {
            'domain': domain,
            'dns_records': {
                'dns': [],
                'mx': [],
                'txt': api_data.get('txt', []),
                'host': []
            },
            'image_data': None,  # Not available in official API
            'xls_data': None    # Not available in official API
        }

        # Process A records
        for a_record in api_data.get('a', []):
            host = a_record['host']
            for ip_info in a_record['ips']:
                result['dns_records']['dns'].append({
                    'domain': host,
                    'ip': ip_info['ip'],
                    'reverse_dns': ip_info.get('ptr', ''),
                    'as': ip_info.get('asn', ''),
                    'provider': ip_info.get('asn_name', ''),
                    'country': ip_info.get('country', ''),
                    'header': ''  # Not available in official API
                })
                result['dns_records']['host'].append({
                    'domain': host,
                    'ip': ip_info['ip'],
                    'reverse_dns': ip_info.get('ptr', ''),
                    'as': ip_info.get('asn', ''),
                    'provider': ip_info.get('asn_name', ''),
                    'country': ip_info.get('country', ''),
                    'header': ''  # Not available in official API
                })

        # Process MX records
        for mx_record in api_data.get('mx', []):
            host = mx_record['host']
            for ip_info in mx_record['ips']:
                result['dns_records']['mx'].append({
                    'domain': host,
                    'ip': ip_info['ip'],
                    'reverse_dns': ip_info.get('ptr', ''),
                    'as': ip_info.get('asn', ''),
                    'provider': ip_info.get('asn_name', ''),
                    'country': ip_info.get('country', ''),
                    'header': ''  # Not available in official API
                })

        # Process NS records (added to dns section in old format)
        for ns_record in api_data.get('ns', []):
            host = ns_record['host']
            for ip_info in ns_record['ips']:
                result['dns_records']['dns'].append({
                    'domain': host,
                    'ip': ip_info['ip'],
                    'reverse_dns': ip_info.get('ptr', ''),
                    'as': ip_info.get('asn', ''),
                    'provider': ip_info.get('asn_name', ''),
                    'country': ip_info.get('country', ''),
                    'header': ''  # Not available in official API
                })

        return result

    def search(self, domain):
        """Search for domain information using the official API"""
        
        if not self.api_key:
            print("API key is required for the official DNSDumpster API", file=sys.stderr)
            return None

        api_url = f"https://api.dnsdumpster.com/domain/{domain}"
        headers = {
            "X-API-Key": self.api_key,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36"
        }

        try:
            req = self.session.get(api_url, headers=headers)
            
            if req.status_code != 200:
                print(
                    f"Unexpected status code from API: {req.status_code}",
                    file=sys.stderr,
                )
                return None

            api_data = req.json()
            self.display_message(f"Successfully retrieved data from official API for {domain}")
            
            # Convert to old format
            return self._convert_api_response(api_data, domain)

        except Exception as e:
            print(f"Error accessing API: {str(e)}", file=sys.stderr)
            return None
