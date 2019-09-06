import scapy.all as scapy


class Dot11Packet:

    def __init__(self, raw_packet, channel=0, iface=None):
        self.iface = iface
        self.channel = channel
        self.signal_strength = 0
        self.bssid = None
        self.ssid = None

        self.raw_packet = raw_packet
        self.size = len(raw_packet) # in bytes
        
        # https://dalewifisec.wordpress.com/2014/05/17/the-to-ds-and-from-ds-fields/
        # DS = Distribution System; wired infrastructure connecting multiple BSSs to form an ESS
        # Needed to determine the meanings of addr1-4
        self.to_ds = raw_packet.FCfield & 0x1 != 0
        self.from_ds = raw_packet.FCfield & 0x2 != 0

        # When both the To DS and From DS are set to 1 the packet is involved with a wireless distribution system (WDS) network.
        if self.to_ds and self.from_ds:
            self.src = raw_packet.addr4
            self.dst = raw_packet.addr3
            self.macs = {raw_packet.addr1, raw_packet.addr2, raw_packet.addr3, raw_packet.addr4}

        # The frame is leaving the wireless environment and is intended for a computer on the distribution system network. 
        elif self.to_ds:
            self.src = raw_packet.addr2
            self.dst = raw_packet.addr3
            self.bssid = raw_packet.addr1
            self.macs = {raw_packet.addr2, raw_packet.addr3}
        
        # The packet is entering the wireless environment coming from the DS.
        elif self.from_ds:
            self.src = raw_packet.addr3
            self.dst = raw_packet.addr1
            self.bssid = raw_packet.addr2
            self.macs = {raw_packet.addr1, raw_packet.addr3}
        
        # The frame is either part of an ad-hoc network or the frame is not intended to leave the wireless environment.
        # Management and Control frames will always have the To DS and From DS fields set to 0 and are never sent to the distribution system network.
        else:
            self.src = raw_packet.addr2
            self.dst = raw_packet.addr1
            self.bssid = raw_packet.addr3
            self.macs = {raw_packet.addr1, raw_packet.addr2}

        if raw_packet.haslayer(scapy.Dot11Elt) \
            and (raw_packet.haslayer(scapy.Dot11Beacon) or raw_packet.haslayer(scapy.Dot11ProbeReq) or raw_packet.haslayer(scapy.Dot11ProbeResp)):

            try:
                self.ssid = raw_packet[scapy.Dot11Elt].info.decode().replace('\x00', '[NULL]')
            except UnicodeDecodeError:
                self.ssid = None

        if raw_packet.haslayer(scapy.RadioTap):
            # It seems the rssi information is located in different places depending on the type of headers supported by the adapter.
            dBm = ord(raw_packet.notdecoded[-4:-3])
            if not dBm:
                dBm = ord(raw_packet.notdecoded[-2:-1])

            self.signal_strength = -(256-dBm)

    @property
    def type(self):
        if self.raw_packet.type == 0:
            return 'management'
        elif self.raw_packet.type == 1:
            return 'control'
        elif self.raw_packet.type == 2:
            return 'data'
        return 'unknown'

    def __str__(self):
        return 'Dot11 (type={}, from={}, to={}, bssid={}, ssid={}, ds=[from={}, to={}], signal_strength={})' \
            .format(
                self.type, 
                self.src, 
                self.dst, 
                self.bssid, 
                self.ssid, 
                self.from_ds,
                self.to_ds,
                self.signal_strength
            )

    def __repr__(self):
        return self.__str__()
