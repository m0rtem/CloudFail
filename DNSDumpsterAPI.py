"""
This is the (unofficial) Python API for dnsdumpster.com Website.
Using this code, you can retrieve subdomains
Author: https://github.com/PaulSec/
"""
from __future__ import print_function

import re
import sys
import requests

from bs4 import BeautifulSoup


class DNSDumpsterAPI(object):

    """DNSDumpsterAPI Main Handler"""

    def __init__(self, verbose=False):
        self.verbose = verbose

    def display_message(self, string):
        if self.verbose:
            print('[verbose] %s' % string)

    def retrieve_results(self, table):
        res = []
        trs = table.findAll('tr')
        for tr in trs:
            tds = tr.findAll('td')
            pattern_ip = r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
            ip = re.findall(pattern_ip, tds[1].text)[0]
            domain = tds[0].text.replace('\n', ' ')

            additional_info = tds[2].text
            country = tds[2].find('span', attrs={}).text
            autonomous_system = additional_info.split(' ')[0]
            provider = ' '.join(additional_info.split(' ')[1:])
            provider = provider.replace(country, '')
            data = {'domain': domain, 'ip': ip, 'as': autonomous_system, 'provider': provider, 'country': country}
            res.append(data)
        return res

    def retrieve_txt_record(self, table):
        res = []
        for td in table.findAll('td'):
            res.append(td.text)
        return res

    def search(self, domain):
        dnsdumpster_url = 'https://dnsdumpster.com/'
        s = requests.session()

        req = s.get(dnsdumpster_url)
        soup = BeautifulSoup(req.content, 'html.parser')
        csrf_middleware = soup.findAll('input', attrs={'name': 'csrfmiddlewaretoken'})[0]['value']
        self.display_message('Retrieved token: %s' % csrf_middleware)

        cookies = {'csrftoken': csrf_middleware}
        headers = {'Referer': dnsdumpster_url}
        data = {'csrfmiddlewaretoken': csrf_middleware, 'targetip': domain}
        req = s.post(dnsdumpster_url, cookies=cookies, data=data, headers=headers)

        if req.status_code != 200:
            print(
                u"Unexpected status code from {url}: {code}".format(
                    url=dnsdumpster_url, code=req.status_code),
                file=sys.stderr,
            )
            return []

        if 'error getting results' in req.content.decode('utf-8'):
            print("There was an error getting results", file=sys.stderr)
            return []

        soup = BeautifulSoup(req.content, 'html.parser')
        tables = soup.findAll('table')

        res = {'domain': domain, 'dns_records': {}}
        res['dns_records']['dns'] = self.retrieve_results(tables[0])
        res['dns_records']['mx'] = self.retrieve_results(tables[1])
        res['dns_records']['txt'] = self.retrieve_txt_record(tables[2])
        res['dns_records']['host'] = self.retrieve_results(tables[3])
        return res