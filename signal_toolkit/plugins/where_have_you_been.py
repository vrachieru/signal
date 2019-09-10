import yaml
import scapy.all as scapy
import sys
import time
import os

from signal_toolkit.plugin import Plugin


class WhereHaveYouBeen(Plugin):
    '''
    Determine where a device has been by collecting probe requests 
    for APs to which the device has been connected before.
    '''

    def __init__(self, database='where_have_you_been.yaml', save_interval=60 * 5):
        self.devices = dict()
        self.database = database

        self.last_save = time.time()
        self.save_interval = save_interval # seconds

    def process_packet(self, packet):
        if packet.raw_packet.haslayer(scapy.Dot11ProbeReq):
            if packet.ssid.strip():
                self.devices[packet.src] = list(set(self.devices.get(packet.src, [])) | {packet.ssid})

                now = time.time()
                if now - self.last_save >= self.save_interval:
                    self.last_save = now
                    self.save()

    def start(self):
        self.load()

    def stop(self):
        self.save()

    def load(self):
        if os.path.isfile(self.database):
            with open(self.database, 'r') as f:
                self.devices = yaml.safe_load(f)

    def save(self):
        with open(self.database, 'w') as f:
            yaml.dump(self.devices, f)
