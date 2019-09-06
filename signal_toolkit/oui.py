import os

from urllib.request import urlopen


class MacVendorDB:

    def __init__(self, oui_file='oui.txt'):
        self.db = {}

        if not os.path.isfile(oui_file):
            self.download_oui(oui_file)

        with open(oui_file, 'r') as f:
            for line in f:
                if '(hex)' in line:
                    data = line.split('(hex)')
                    mac = data[0].replace('-', '').lower().strip()
                    company = data[1].strip()
                    self.db[mac] = company

    def lookup(self, mac):
        try:
            oui_prefix = mac.lower().replace(':', '')[0:6]
            if oui_prefix in self.db:
                return self.db[oui_prefix]
        except Exception:
            pass

        return ''

    def download_oui(self, to_file='oui.txt'):
        uri = 'http://standards-oui.ieee.org/oui/oui.txt'
        print('Trying to download current version of oui.txt from [%s] to file [%s]' % (uri, to_file))
        oui_data = urlopen(uri, timeout=10).read()
        with open(to_file, 'wb') as oui_file:
            oui_file.write(oui_data)
