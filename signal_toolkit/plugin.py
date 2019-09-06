from abc import ABC, abstractmethod


class Plugin(ABC):

    def start(self):
        pass

    def stop(self):
        pass

    @abstractmethod
    def process_packet(self, packet):
        pass
