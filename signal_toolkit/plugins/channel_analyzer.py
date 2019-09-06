import pyaml
import scapy.all as scapy
import sys

from statistics import mean
from signal_toolkit.plugin import Plugin


class ChannelAnalyzer(Plugin):

    def __init__(self):
        self.channels = {1:{}, 2:{}, 3:{}, 4:{}, 5:{}, 6:{}, 7:{}, 8:{}, 9:{}, 10:{}, 11:{}, 12:{}, 13:{}}

    def process_packet(self, packet):
        if packet.raw_packet.haslayer(scapy.Dot11Beacon) or packet.raw_packet.haslayer(scapy.Dot11ProbeResp):
            if packet.bssid in self.channels[packet.channel]:
                self.channels[packet.channel][packet.bssid].append(packet.signal_strength)
            else:
                self.channels[packet.channel][packet.bssid] = [packet.signal_strength]

    def stop(self):
        avg_pwr_per_ap = self.calculate_average_power_per_ap()

        channels = {}
        for channel in self.channels:
            channels[channel] = {
                'rating': 1,
                'access_points': len(self.channels[channel]),
                'interference_level': self.calculate_channel_interference(avg_pwr_per_ap, channel)
            }

        pyaml.dump(channels, sys.stdout)

    def calculate_channel_interference(self, avg_pwr_per_ap, channel):
        items = [avg_pwr_per_ap[channel][bssid] for bssid in avg_pwr_per_ap[channel]]
        return -sum(items) if len(items) > 0 else 0

    def calculate_average_power_per_ap(self):
        avg_pwr_per_ap = {1:{}, 2:{}, 3:{}, 4:{}, 5:{}, 6:{}, 7:{}, 8:{}, 9:{}, 10:{}, 11:{}, 12:{}, 13:{}}
        for channel in self.channels:
            for bssid in self.channels[channel]:
                bssid_avg_pwr = mean(self.channels[channel][bssid]) if len(self.channels[channel][bssid]) > 0 else 0
                avg_pwr_per_ap[channel][bssid] = bssid_avg_pwr

        return avg_pwr_per_ap


    # https://www.networkcomputing.com/wireless-infrastructure/reducing-wifi-channel-interference
    # https://en.wikipedia.org/wiki/Adjacent-channel_interference
    def calculate_co_channel_interference(self, channel):
        return len(self.channels[channel])

    def calculate_adjacent_channel_interference(self, channel):
        pass
