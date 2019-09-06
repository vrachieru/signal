import scapy.all as scapy

from signal_toolkit.main import SignalToolkit
from signal_toolkit.plugins import *


if __name__ == '__main__':
    signal = SignalToolkit(iface='mon0', plugins=[
        PacketLogger(),
        # HowManyPeopleAreAround(),
        # WhereHaveYouBeen(),
        # ChannelAnalyzer()
    ])

    signal.start()
    signal.stop()
