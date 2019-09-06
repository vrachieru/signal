import scapy.all as scapy

from signal_toolkit.oui import MacVendorDB
from signal_toolkit.plugin import Plugin


class HowManyPeopleAreAround(Plugin):
    '''
    Aproximate how many people are around by attempting to count 
    the number of cellphones in the area.
    '''

    CELLPONE_MANUFACTURERS = [
        'Apple, Inc.',
        'BlackBerry RTS',
        'GUANGDONG OPPO MOBILE TELECOMMUNICATIONS CORP.,LTD',
        'HTC Corporation',
        'Huawei Symantec Technologies Co.,Ltd.',
        'LG Electronics (Mobile Communications)'
        'LG ELECTRONICS INC',
        'LG Electronics',
        'Microsoft',
        'Motorola Mobility LLC, a Lenovo Company',
        'OnePlus Tech (Shenzhen) Ltd',
        'SAMSUNG ELECTRO-MECHANICS(THAILAND)',
        'Samsung Electronics Co.,Ltd',
        'Xiaomi Communications Co Ltd',
    ]

    def __init__(self, percentage_of_people_with_phones=1):
        self.mac_vendor_db = MacVendorDB()
        self.devices = set()
        self.percentage_of_people_with_phones = percentage_of_people_with_phones

    def process_packet(self, packet):
        if packet.raw_packet.haslayer(scapy.Dot11ProbeReq):
            self.devices.add(packet.src)

    def stop(self):
        print('Detected %d devices.' % len(self.devices))

        people = self.count_people()

        if people == 0:
            print('No one around (not even you!).')
        elif people == 1:
            print('No one around, but you.')
        else:
            print('There are about %d people around.' % people)

    def filter_cellphones(self):
        is_cellphone = lambda device: self.mac_vendor_db.lookup(device) in HowManyPeopleAreAround.CELLPONE_MANUFACTURERS
        return set(filter(is_cellphone, self.devices))

    def count_people(self):
        cellphones = self.filter_cellphones()
        people = int(round(len(cellphones) / self.percentage_of_people_with_phones))

        return people
