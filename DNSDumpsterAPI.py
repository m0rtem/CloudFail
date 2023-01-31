"""
This is the (unofficial) Python API for dnsdumpster.com Website.
Using this code, you can retrieve subdomains

"""

from __future__ import print_function
import requests
import re
import sys
import base64
import collections
collections.Callable = collections.abc.Callable

from bs4 import BeautifulSoup


class DNSDumpsterAPI(object):

    """DNSDumpsterAPI Main Handler"""

    def __init__(self, verbose=False, session=None):
        self.verbose = verbose
        if not session:
            self.session = requests.Session()
        else:
            self.session = session

    def display_message(self, s):
        if self.verbose:
            print('[verbose] %s' % s)

    def retrieve_results(self, table):
        res = []
        trs = table.findAll('tr')
        for tr in trs:
            tds = tr.findAll('td')
            pattern_ip = r'([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})'
            try:
                ip = re.findall(pattern_ip, tds[1].text)[0]
                domain = str(tds[0]).split('<br/>')[0].split('>')[1].split('<')[0]
                header = ' '.join(tds[0].text.replace('\n', '').split(' ')[1:])
                reverse_dns = tds[1].find('span', attrs={}).text

                additional_info = tds[2].text
                country = tds[2].find('span', attrs={}).text
                autonomous_system = additional_info.split(' ')[0]
                provider = ' '.join(additional_info.split(' ')[1:])
                provider = provider.replace(country, '')
                data = {'domain': domain,
                        'ip': ip,
                        'reverse_dns': reverse_dns,
                        'as': autonomous_system,
                        'provider': provider,
                        'country': country,
                        'header': header}
                res.append(data)
            except:
                pass
        return res

    def retrieve_txt_record(self, table):
        res = []
        for td in table.findAll('td'):
            res.append(td.text)
        return res


    def search(self, domain):
        dnsdumpster_url = 'https://dnsdumpster.com/'

        req = self.session.get(dnsdumpster_url)
        soup = BeautifulSoup(req.content, 'html.parser')
        csrf_middleware = soup.findAll('input', attrs={'name': 'csrfmiddlewaretoken'})[0]['value']
        self.display_message('Retrieved token: %s' % csrf_middleware)

        cookies = {'csrftoken': csrf_middleware}
        headers = {'Referer': dnsdumpster_url, 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36'}
        data = {'csrfmiddlewaretoken': csrf_middleware, 'targetip': domain, 'user': 'free'}
        req = self.session.post(dnsdumpster_url, cookies=cookies, data=data, headers=headers)

        if req.status_code != 200:
            print(
                "Unexpected status code from {url}: {code}".format(
                    url=dnsdumpster_url, code=req.status_code),
                file=sys.stderr,
            )
            return []

        if 'There was an error getting results' in req.content.decode('utf-8'):
            print("There was an error getting results", file=sys.stderr)
            return []

        soup = BeautifulSoup(req.content, 'html.parser')
        tables = soup.findAll('table')

        res = {}
        res['domain'] = domain
        res['dns_records'] = {}
        res['dns_records']['dns'] = self.retrieve_results(tables[0])
        res['dns_records']['mx'] = self.retrieve_results(tables[1])
        res['dns_records']['txt'] = self.retrieve_txt_record(tables[2])
        res['dns_records']['host'] = self.retrieve_results(tables[3])

        # Network mapping image
        try:
            tmp_url = 'https://dnsdumpster.com/static/map/{}.png'.format(domain)
            image_data = base64.b64encode(self.session.get(tmp_url).content)
        except:
            image_data = None
        finally:
            res['image_data'] = image_data

        # XLS hosts.
        # eg. tsebo.com-201606131255.xlsx
        try:
            pattern = r'/static/xls/' + domain + '-[0-9]{12}\.xlsx'
            xls_url = re.findall(pattern, req.content.decode('utf-8'))[0]
            xls_url = 'https://dnsdumpster.com' + xls_url
            xls_data = base64.b64encode(self.session.get(xls_url).content)
        except Exception as err:
            print(err)
            xls_data = None
        finally:
            res['xls_data'] = xls_data

        return res
