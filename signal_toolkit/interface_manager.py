import re
import time
import threading
import subprocess


class InterfaceManager:

    def __init__(self, iface):
        self.iface = iface

        self.stop_event = threading.Event()
        self.supported_channels = []
        self.current_channel = 1
        self.last_channel_switch_time = 0

        self.configure_channels()

    def get_supported_channels(self, iface):
        iwlist_output = subprocess.check_output('iwlist {} freq'.format(iface), shell=True).decode()
        lines = [line.strip() for line in iwlist_output.split('\n')]
        channel_regex = re.compile(r'Channel\W+(\d+)')
        channels = []
        for line in lines:
            m = re.search(channel_regex, line)
            if m:
                c = m.groups()[0]
                channels.append(c)

        return list(sorted(list(set([int(chan) for chan in channels]))))

    def configure_channels(self):
        self.supported_channels = self.get_supported_channels(self.iface)
        if not self.supported_channels:
            raise Exception('Interface either not found, or incompatible: {}'.format(self.iface))

        self.current_channel = self.supported_channels[0]
        print('Monitoring all available channels on %s: %s' % (self.iface, self.supported_channels))

        self.switch_to_channel(self.current_channel, force=True)

    def channel_switcher_thread(self, firethread=True):
        if firethread:
            t = threading.Thread(target=self.channel_switcher_thread, args=(False,))
            t.daemon = True
            t.start()
            return t

        if len(self.supported_channels) > 1:
            while not self.stop_event.is_set():
                time.sleep(2) # time per channel
                self.switch_channel_round_robin()
                self.last_channel_switch_time = time.time()

    def switch_channel_round_robin(self):
        chans = self.supported_channels
        next_channel = chans[(chans.index(self.current_channel)+1) % len(chans)]
        self.switch_to_channel(next_channel)

    def switch_to_channel(self, channel_num, force=False):
        print('Switching to channel %s' % channel_num)
        if channel_num == self.current_channel and not force:
            return
        subprocess.call('iw dev {} set channel {}'.format(self.iface, channel_num), shell=True)
        self.current_channel = channel_num

    def start(self):
        self.channel_switcher_thread()

    def stop(self):
        self.stop_event.set()
