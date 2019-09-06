import scapy.all as scapy

from signal_toolkit.interface_manager import InterfaceManager
from signal_toolkit.model import Dot11Packet
from signal_toolkit.plugins import *


class SignalToolkit:

    def __init__(self, iface='mon0', plugins=[PacketLogger()]):
        self.iface_manager = InterfaceManager(iface=iface)
        self.plugins = plugins

    def process_packet(self, packet):
        if packet.haslayer(scapy.Dot11):
            dot11_packet = Dot11Packet(
                raw_packet=packet,
                channel=int(self.iface_manager.current_channel),
                iface=self.iface_manager.iface)

            for plugin in self.plugins:
                plugin.process_packet(dot11_packet)

    def start(self):
        print('Starting monitoring on %s' % self.iface_manager.iface)
        self.iface_manager.start()
        scapy.sniff(iface=self.iface_manager.iface, prn=self.process_packet, store=0)
        for plugin in self.plugins:
            plugin.start()

    def stop(self):
        print('Stopping monitoring on %s' % self.iface_manager.iface)
        self.iface_manager.stop()
        for plugin in self.plugins:
            plugin.stop()
