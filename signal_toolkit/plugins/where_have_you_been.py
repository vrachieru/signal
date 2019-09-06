import pyaml
import scapy.all as scapy
import sys

from signal_toolkit.plugin import Plugin


class WhereHaveYouBeen(Plugin):
    '''
    Determine where a device has been by collecting probe requests 
    for APs to which the device has been connected before.
    '''

    def __init__(self):
        self.devices = dict()

    def process_packet(self, packet):
        if packet.raw_packet.haslayer(scapy.Dot11ProbeReq):
            if packet.ssid.strip():
                self.devices[packet.src] = self.devices.get(packet.src, set()) | {packet.ssid}

    def stop(self):
        pyaml.dump(self.devices, sys.stdout)
