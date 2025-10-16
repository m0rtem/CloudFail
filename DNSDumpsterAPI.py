"""
This is the (unofficial) Python API for dnsdumpster.com Website.
Using this code, you can retrieve subdomains
"""

from __future__ import print_function
import requests
import re
import sys
import base64

from bs4 import BeautifulSoup


class DNSDumpsterAPI(object):
    """DNSDumpsterAPI Main Handler"""

    def __init__(self, verbose=False, session=None):
        self.verbose = verbose
        if not session:
            self.session = requests.Session()
        else:
            self.session = session

        # Add realistic headers to reduce blocking and keep them for all requests
        self.session.headers.update({
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/119.0 Safari/537.36"
            ),
            "Referer": "https://dnsdumpster.com/"
        })

    def display_message(self, s):
        if self.verbose:
            print('[verbose] %s' % s)

    def _empty_result(self, domain):
        """Return an empty structured result when DNSDumpster fails."""
        return {
            'domain': domain,
            'dns_records': {
                'dns': [],
                'mx': [],
                'txt': [],
                'host': []
            },
            'image_data': None,
            'xls_data': None
        }

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
            except Exception:
                pass
        return res

    def retrieve_txt_record(self, table):
        res = []
        for td in table.findAll('td'):
            res.append(td.text)
        return res

    def search(self, domain):
        dnsdumpster_url = 'https://dnsdumpster.com/'

        # Initial GET to obtain the CSRF token and cookies
        try:
            req = self.session.get(dnsdumpster_url, timeout=20)
            req.raise_for_status()
        except requests.RequestException as e:
            print("DNSDumpster GET failed: %s" % e, file=sys.stderr)
            return self._empty_result(domain)

        soup = BeautifulSoup(req.content, 'html.parser')

        # ---- Robust CSRF extraction (tolerant to HTML changes or block pages)
        token_input = soup.find("input", attrs={"name": "csrfmiddlewaretoken"})
        csrf_middleware = None
        if token_input and token_input.get("value"):
            csrf_middleware = token_input["value"]
        else:
            # Fallback: regex search in raw HTML
            m = re.search(
                r"name=['\"]csrfmiddlewaretoken['\"]\s+value=['\"]([^'\"]+)['\"]",
                req.text
            )
            if m:
                csrf_middleware = m.group(1)

        if not csrf_middleware:
            print(
                "DNSDumpster: CSRF token not found (site may be blocking or serving a captcha).",
                file=sys.stderr
            )
            return self._empty_result(domain)

        self.display_message('Retrieved token: %s' % csrf_middleware)

        # Prepare POST
        cookies = {'csrftoken': csrf_middleware}
        headers = {
            'Referer': dnsdumpster_url,
            'User-Agent': self.session.headers.get('User-Agent', 'Mozilla/5.0')
        }
        data = {'csrfmiddlewaretoken': csrf_middleware, 'targetip': domain, 'user': 'free'}

        try:
            req = self.session.post(dnsdumpster_url, cookies=cookies, data=data, headers=headers, timeout=30)
            req.raise_for_status()
        except requests.RequestException as e:
            print("DNSDumpster POST failed: %s" % e, file=sys.stderr)
            return self._empty_result(domain)

        if 'There was an error getting results' in req.content.decode('utf-8', errors='ignore'):
            print("There was an error getting results", file=sys.stderr)
            return self._empty_result(domain)

        soup = BeautifulSoup(req.content, 'html.parser')
        tables = soup.findAll('table')

        if len(tables) < 4:
            print("DNSDumpster: unexpected response format (tables missing).", file=sys.stderr)
            return self._empty_result(domain)

        res = {
            'domain': domain,
            'dns_records': {
                'dns': self.retrieve_results(tables[0]),
                'mx': self.retrieve_results(tables[1]),
                'txt': self.retrieve_txt_record(tables[2]),
                'host': self.retrieve_results(tables[3])
            }
        }

        # Network mapping image
        try:
            tmp_url = f'https://dnsdumpster.com/static/map/{domain}.png'
            image_data = base64.b64encode(self.session.get(tmp_url, timeout=20).content)
        except Exception:
            image_data = None
        finally:
            res['image_data'] = image_data

        # XLS hosts
        try:
            pattern = rf'/static/xls/{re.escape(domain)}-[0-9]{{12}}\.xlsx'
            m = re.findall(pattern, req.content.decode('utf-8', errors='ignore'))
            if m:
                xls_url = 'https://dnsdumpster.com' + m[0]
                xls_data = base64.b64encode(self.session.get(xls_url, timeout=20).content)
            else:
                xls_data = None
        except Exception as err:
            print(err, file=sys.stderr)
            xls_data = None
        finally:
            res['xls_data'] = xls_data

        return res
