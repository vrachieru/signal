import scapy.all as scapy

from signal_toolkit.plugin import Plugin

class PacketLogger(Plugin):
    '''
    Log sniffed packets.
    '''

    WEIGHTED_PACKET_LAYER_TYPES = [
        scapy.Dot11Beacon,
        scapy.Dot11ProbeReq,
        scapy.Dot11ProbeResp,
        scapy.Dot11Auth,
        scapy.Dot11Deauth,
        scapy.Dot11AssoReq,
        scapy.Dot11AssoResp,
        scapy.Dot11ReassoReq,
        scapy.Dot11ReassoResp,
        scapy.Dot11Disas,
        scapy.Dot11WEP,
        scapy.Dot11QoS,
        scapy.Dot11Ack,
        scapy.Dot11Elt,
        scapy.Dot11ATIM,
        scapy.Dot11
    ]

    def __init__(self, packet_types=[], layer_types=[]):
        self.packet_types = packet_types
        self.layer_types = layer_types

    def process_packet(self, packet):
        if (not self.packet_types and not self.layer_types) or (packet.type in self.packet_types):
            self.log_packet(packet)
        else:
            for layer_type in self.layer_types:
                if packet.raw_packet.haslayer(layer_type):
                    self.log_packet(packet)

    def get_most_relevant_packet_layer_name(self, packet):
        for layer_type in PacketLogger.WEIGHTED_PACKET_LAYER_TYPES:
            if packet.raw_packet.haslayer(layer_type):
                return packet.raw_packet.getlayer(layer_type).name

        return packet.raw_packet.name

    def log_packet(self, packet):
        print(
            '{:<30}: Dot11 (type={:<10}, from={:<17}, to={:<17}, bssid={:<17}, ssid={:<15}, ds=[from={:<5}, to={:<5}], signal_strength={:<4})'
            .format(
                self.get_most_relevant_packet_layer_name(packet),
                str(packet.type),
                str(packet.src),
                str(packet.dst),
                str(packet.bssid),
                str(packet.ssid),
                str(packet.from_ds),
                str(packet.to_ds),
                str(packet.signal_strength)
            )
        )
