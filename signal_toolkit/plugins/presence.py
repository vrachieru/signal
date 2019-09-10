import yaml
import scapy.all as scapy
import time
import sys
import os

from signal_toolkit.plugin import Plugin


class Presence(Plugin):

    def __init__(self, check_interval=60, dropoff_interval=60 * 15, database='presence.yaml'):
        self.device_first_seen = dict()
        self.device_sightings = dict()

        self.last_check = time.time()
        self.check_interval = check_interval # seconds
        self.dropoff_interval = dropoff_interval # seconds
        self.database = database
        self.callback = callback

    def start(self):
        self.load()

    def stop(self):
        self.save()

    def process_packet(self, packet):
        now = time.time()

        if packet.raw_packet.haslayer(scapy.Dot11ProbeReq):

            if packet.src not in self.device_first_seen:
                self.device_first_seen[packet.src] = {
                    'first_seen': now,
                    'last_seen': now
                }
            else:
                self.device_first_seen[packet.src]['last_seen'] = now

            if now - self.last_check >= self.check_interval:
                self.last_check = now

                devices_to_remove = []
                for device, sightings in self.device_first_seen.items():
                    if now - sightings['last_seen'] >= self.dropoff_interval:
                        if device not in self.device_sightings:
                            self.device_sightings[device] = []

                        self.device_sightings[device] = self.device_sightings[device] + [{'start': sightings['first_seen'], 'end': sightings['last_seen']}]
                        devices_to_remove.append(device)

                if devices_to_remove:
                    self.save()

                for device in devices_to_remove:
                    del self.device_first_seen[device]

                devices_to_remove = []

    def load(self):
        if os.path.isfile(self.database):
            with open(self.database, 'r') as f:
                self.device_sightings = yaml.safe_load(f)

    def save(self):
        with open(self.database, 'w') as f:
            yaml.dump(self.device_sightings, f)
